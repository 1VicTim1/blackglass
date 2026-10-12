use anyhow::{Result, anyhow};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyState {
    Missing,
    Present(String),
    Multiple(usize),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MailDnsResult {
    MailExchangers(Vec<String>),
    AddressFallback(Vec<String>),
    NoMailRoute,
    Policy(PolicyState),
}

pub fn select_policy(records: &[String], prefix: &str) -> PolicyState {
    let prefix = prefix.to_ascii_lowercase();
    let matches: Vec<_> = records
        .iter()
        .filter(|record| record.to_ascii_lowercase().starts_with(&prefix))
        .collect();
    match matches.as_slice() {
        [] => PolicyState::Missing,
        [record] => PolicyState::Present((*record).clone()),
        many => PolicyState::Multiple(many.len()),
    }
}

pub fn lookup_mx(domain: &str) -> Result<MailDnsResult> {
    let records = query_dns(domain, "MX")?;
    if records.iter().any(|record| record.data.trim() == "0 .") {
        return Ok(MailDnsResult::NoMailRoute);
    }
    let mut values: Vec<_> = records
        .into_iter()
        .filter(|record| record.record_type == 15)
        .map(|record| {
            let mut fields = record.data.split_whitespace();
            let priority = fields.next().unwrap_or("?");
            let host = fields.next().unwrap_or("?");
            format!("priority={priority} host={host}")
        })
        .collect();
    values.sort();
    if values.is_empty() {
        fallback_addresses(domain)
    } else {
        Ok(MailDnsResult::MailExchangers(values))
    }
}

pub fn lookup_policy(domain: &str, prefix: &str) -> Result<MailDnsResult> {
    let records: Vec<_> = query_dns(domain, "TXT")?
        .into_iter()
        .filter(|record| record.record_type == 16)
        .map(|record| decode_txt(&record.data))
        .collect();
    Ok(MailDnsResult::Policy(select_policy(&records, prefix)))
}

#[derive(Debug, Deserialize)]
struct DnsResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "Answer", default)]
    answers: Vec<DnsAnswer>,
}

#[derive(Debug, Deserialize)]
struct DnsAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

fn query_dns(name: &str, record_type: &str) -> Result<Vec<DnsAnswer>> {
    let response = Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent(concat!("nulltrace/", env!("CARGO_PKG_VERSION")))
        .build()?
        .get("https://cloudflare-dns.com/dns-query")
        .header("accept", "application/dns-json")
        .query(&[("name", name), ("type", record_type)])
        .send()?
        .error_for_status()?
        .json::<DnsResponse>()?;
    if matches!(response.status, 0 | 3) {
        Ok(response.answers)
    } else {
        Err(anyhow!(
            "DNS-over-HTTPS returned status {} for {name} {record_type}",
            response.status
        ))
    }
}

fn fallback_addresses(domain: &str) -> Result<MailDnsResult> {
    let mut values = Vec::new();
    for record_type in ["A", "AAAA"] {
        values.extend(
            query_dns(domain, record_type)?
                .into_iter()
                .filter(|record| matches!(record.record_type, 1 | 28))
                .map(|record| record.data),
        );
    }
    values.sort();
    values.dedup();
    if values.is_empty() {
        Ok(MailDnsResult::NoMailRoute)
    } else {
        Ok(MailDnsResult::AddressFallback(values))
    }
}

fn decode_txt(value: &str) -> String {
    value
        .trim_matches('"')
        .replace("\" \"", "")
        .replace("\\\"", "\"")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailAddress {
    original: String,
    local: String,
    domain: String,
}

impl EmailAddress {
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > 254
            || input
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control())
        {
            return Err(anyhow!("invalid email address length or whitespace"));
        }
        let mut parts = input.rsplitn(2, '@');
        let raw_domain = parts.next().unwrap_or_default();
        let local = parts
            .next()
            .ok_or_else(|| anyhow!("email address has no @"))?;
        if local.is_empty()
            || local.len() > 64
            || local.starts_with('.')
            || local.ends_with('.')
            || local.contains("..")
            || raw_domain.is_empty()
            || raw_domain.contains('@')
        {
            return Err(anyhow!("invalid email local part or domain"));
        }
        if !local.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '/'
                        | '='
                        | '?'
                        | '^'
                        | '_'
                        | '`'
                        | '{'
                        | '|'
                        | '}'
                        | '~'
                        | '.'
                )
        }) {
            return Err(anyhow!("unsupported or invalid email local part"));
        }
        let domain = idna::domain_to_ascii(raw_domain)
            .map_err(|_| anyhow!("invalid internationalized email domain"))?
            .to_ascii_lowercase();
        if domain.len() > 253
            || !domain.contains('.')
            || domain.starts_with('.')
            || domain.ends_with('.')
            || domain.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            })
        {
            return Err(anyhow!("invalid email domain"));
        }
        Ok(Self {
            original: input.into(),
            local: local.into(),
            domain,
        })
    }

    pub fn normalized(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }

    pub fn original(&self) -> &str {
        &self.original
    }

    pub fn local(&self) -> &str {
        &self.local
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
}

use crate::{Confidence, Finding, Origin, Severity};
use anyhow::{Result, anyhow};
use reqwest::{
    StatusCode,
    blocking::Client,
    header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION, RANGE, SERVER},
    redirect::Policy,
};
use std::time::Duration;
use url::Url;

#[derive(Clone, Debug)]
pub struct HttpHop {
    pub url: Url,
    pub status: StatusCode,
    pub location: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<String>,
    pub server: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HttpReport {
    pub hops: Vec<HttpHop>,
    pub findings: Vec<Finding>,
}

pub fn redirect_findings(from: &Url, to: &Url) -> Vec<Finding> {
    let mut findings = Vec::new();
    if from.scheme() == "https" && to.scheme() == "http" {
        findings.push(
            Finding::new(
                "HTTP-DOWNGRADE",
                "transport",
                Origin::Online,
                Severity::High,
                Confidence::High,
                "Redirect downgrades HTTPS to unencrypted HTTP",
                35,
            )
            .with_evidence(format!("{from} -> {to}")),
        );
    }
    let from_site = from.host_str().map(site_key);
    let to_site = to.host_str().map(site_key);
    if from_site.is_some() && to_site.is_some() && from_site != to_site {
        findings.push(
            Finding::new(
                "HTTP-CROSS-HOST",
                "redirect",
                Origin::Online,
                Severity::Medium,
                Confidence::High,
                "Redirect leaves the original registrable domain",
                18,
            )
            .with_evidence(format!("{from} -> {to}")),
        );
    }
    findings
}

pub fn trace_http(start: &Url) -> Result<HttpReport> {
    let client = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(6))
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("nulltrace/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut current = start.clone();
    let mut hops = Vec::new();
    let mut findings = Vec::new();
    for _ in 0..=10 {
        let response = client
            .get(current.clone())
            .header(RANGE, "bytes=0-0")
            .send()?;
        let headers = response.headers();
        let text = |name| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        };
        let location = text(LOCATION);
        hops.push(HttpHop {
            url: current.clone(),
            status: response.status(),
            location: location.clone(),
            content_type: text(CONTENT_TYPE),
            content_length: text(CONTENT_LENGTH),
            server: text(SERVER),
        });
        if !response.status().is_redirection() {
            return Ok(HttpReport { hops, findings });
        }
        let location = location.ok_or_else(|| anyhow!("redirect has no Location header"))?;
        let next = current.join(&location)?;
        if !matches!(next.scheme(), "http" | "https") {
            return Err(anyhow!(
                "redirect uses unsupported scheme {}",
                next.scheme()
            ));
        }
        findings.extend(redirect_findings(&current, &next));
        current = next;
    }
    findings.push(Finding::new(
        "HTTP-REDIRECT-LIMIT",
        "redirect",
        Origin::Online,
        Severity::Medium,
        Confidence::High,
        "Redirect chain exceeded 10 hops",
        20,
    ));
    Ok(HttpReport { hops, findings })
}

fn site_key(host: &str) -> String {
    let labels: Vec<_> = host.trim_end_matches('.').split('.').collect();
    let suffix_len = if labels.len() >= 3
        && matches!(
            (labels[labels.len() - 2], labels[labels.len() - 1]),
            (
                "co" | "com" | "org" | "net" | "gov" | "ac",
                "uk" | "au" | "jp" | "nz" | "za"
            )
        ) {
        3
    } else {
        2
    };
    labels[labels.len().saturating_sub(suffix_len)..].join(".")
}

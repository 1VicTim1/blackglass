use crate::{Confidence, Finding, Origin, Severity};
use anyhow::{Context, Result, anyhow};
use mailparse::{
    DispositionType, MailAddr, MailHeaderMap, ParsedMail, addrparse_header, parse_mail,
};
use regex::Regex;
use scraper::{Html, Selector};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs::File, io::Read, path::Path};
use url::Url;

const MAX_EML_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PARTS: usize = 128;

#[derive(Clone, Debug, Default)]
pub struct EmlSection {
    pub observations: Vec<(String, String)>,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Default)]
pub struct EmlReport {
    pub headers: EmlSection,
    pub authentication: EmlSection,
    pub bodies: EmlSection,
    pub links: EmlSection,
    pub attachments: EmlSection,
    pub sender_domain: Option<String>,
    pub urls: Vec<Url>,
}

pub fn inspect_urls_independently<T, F>(
    urls: &[Url],
    limit: usize,
    mut inspect: F,
) -> Vec<(Url, std::result::Result<T, String>)>
where
    F: FnMut(&Url) -> Result<T>,
{
    urls.iter()
        .take(limit)
        .map(|url| {
            let result = inspect(url).map_err(|error| error.to_string());
            (url.clone(), result)
        })
        .collect()
}

pub fn looks_like_eml(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("eml"))
    {
        return true;
    }
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut prefix = vec![0; 8192];
    let Ok(length) = file.read(&mut prefix) else {
        return false;
    };
    prefix.truncate(length);
    let text = String::from_utf8_lossy(&prefix).to_ascii_lowercase();
    (text.starts_with("from:") || text.contains("\nfrom:"))
        && text.contains("\nsubject:")
        && (text.contains("\nmime-version:") || text.contains("\nmessage-id:"))
}

pub fn inspect(path: &Path) -> Result<EmlReport> {
    let metadata = path.metadata()?;
    if metadata.len() > MAX_EML_BYTES {
        return Err(anyhow!("EML exceeds the 32 MiB offline parsing limit"));
    }
    let mut bytes = Vec::with_capacity(metadata.len().min(MAX_EML_BYTES) as usize);
    File::open(path)?
        .take(MAX_EML_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_EML_BYTES {
        return Err(anyhow!("EML exceeds the 32 MiB offline parsing limit"));
    }
    reject_excessive_multipart_nesting(&bytes)?;
    let message = parse_mail(&bytes).context("invalid RFC 5322/MIME message")?;
    let mut report = EmlReport::default();
    inspect_headers(&message, &mut report);
    inspect_authentication(&message, &mut report);
    let mut part_count = 0;
    inspect_parts(&message, &mut report, &mut part_count)?;
    report.urls.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    report.urls.dedup_by(|a, b| a.as_str() == b.as_str());
    report
        .links
        .observations
        .push(("Message URL count".into(), report.urls.len().to_string()));
    Ok(report)
}

fn inspect_headers(message: &ParsedMail<'_>, report: &mut EmlReport) {
    let fields = [
        ("From", "Message From"),
        ("To", "Message To"),
        ("Cc", "Message Cc"),
        ("Reply-To", "Message Reply-To"),
        ("Return-Path", "Message Return-Path"),
        ("Subject", "Message Subject"),
        ("Date", "Message Date"),
        ("Message-ID", "Message-ID"),
    ];
    for (header, label) in fields {
        if let Some(value) = message.headers.get_first_value(header) {
            report.headers.observations.push((label.into(), value));
        }
    }
    let received = message.headers.get_all_values("Received");
    report
        .headers
        .observations
        .push(("Received hops".into(), received.len().to_string()));
    for (index, hop) in received.iter().take(20).enumerate() {
        report
            .headers
            .observations
            .push((format!("Received hop {}", index + 1), hop.clone()));
    }
    let from_domains = header_domains(message, "From");
    if from_domains.len() != 1 {
        report.headers.findings.push(
            Finding::new(
                "EML-FROM-AMBIGUOUS",
                "message-identity",
                Origin::Offline,
                Severity::High,
                Confidence::High,
                "Message does not contain exactly one parseable From mailbox",
                28,
            )
            .with_evidence(format!("parseable From mailbox domains={from_domains:?}")),
        );
    }
    report.sender_domain = (from_domains.len() == 1).then(|| from_domains[0].clone());
    for name in ["Reply-To", "Return-Path"] {
        let other_domains = header_domains(message, name);
        let Some(other_domain) = (other_domains.len() == 1).then(|| other_domains[0].clone())
        else {
            continue;
        };
        if report
            .sender_domain
            .as_deref()
            .is_some_and(|from_domain| !same_organizational_domain(from_domain, &other_domain))
        {
            report.headers.findings.push(
                Finding::new(
                    "EML-REPLY-MISMATCH",
                    "message-identity",
                    Origin::Offline,
                    Severity::High,
                    Confidence::High,
                    &format!("{name} domain differs from the visible From domain"),
                    30,
                )
                .with_evidence(format!(
                    "From domain={}; {name} domain={other_domain}",
                    report.sender_domain.as_deref().unwrap_or("unknown")
                )),
            );
        }
    }
}

fn inspect_authentication(message: &ParsedMail<'_>, report: &mut EmlReport) {
    let values = message.headers.get_all_values("Authentication-Results");
    report.authentication.observations.push((
        "Authentication-Results headers".into(),
        values.len().to_string(),
    ));
    report.authentication.observations.push((
        "Authentication evidence".into(),
        "header values are untrusted until the receiving boundary is established".into(),
    ));
    for value in &values {
        for mechanism in ["spf", "dkim", "dmarc"] {
            if let Some(result) = auth_result(value, mechanism) {
                report.authentication.observations.push((
                    format!("{} result", mechanism.to_ascii_uppercase()),
                    result.clone(),
                ));
                if matches!(
                    result.as_str(),
                    "fail" | "softfail" | "temperror" | "permerror"
                ) {
                    report.authentication.findings.push(
                        Finding::new(
                            "EML-AUTH-FAIL",
                            "message-authentication",
                            Origin::Offline,
                            Severity::High,
                            Confidence::Medium,
                            &format!("Message header reports {mechanism}={result}"),
                            24,
                        )
                        .with_evidence("Authentication-Results is sender-supplied evidence unless a trusted receiving boundary is established"),
                    );
                }
            }
        }
    }
    for header in ["DKIM-Signature", "ARC-Seal", "ARC-Message-Signature"] {
        report.authentication.observations.push((
            format!("{header} count"),
            message.headers.get_all_values(header).len().to_string(),
        ));
    }
}

fn inspect_parts(
    part: &ParsedMail<'_>,
    report: &mut EmlReport,
    part_count: &mut usize,
) -> Result<()> {
    *part_count += 1;
    if *part_count > MAX_PARTS {
        return Err(anyhow!("MIME message exceeds the 128-part parsing limit"));
    }
    let disposition = part.get_content_disposition();
    let filename = disposition.params.get("filename").cloned().or_else(|| {
        part.ctype
            .params
            .get("name")
            .map(std::string::ToString::to_string)
    });
    let is_attachment =
        disposition.disposition == DispositionType::Attachment || filename.is_some();
    if is_attachment {
        let body = part.get_body_raw()?;
        let name = filename.unwrap_or_else(|| "unnamed attachment".into());
        report.attachments.observations.push((
            "Attachment".into(),
            format!(
                "{name}; type={}; decoded={} bytes",
                part.ctype.mimetype,
                body.len()
            ),
        ));
        inspect_attachment_name(&name, &part.ctype.mimetype, &body, &mut report.attachments);
    } else if part.subparts.is_empty() && part.ctype.mimetype.starts_with("text/") {
        let body = part.get_body()?;
        report.bodies.observations.push((
            "Message body".into(),
            format!("{}; {} chars", part.ctype.mimetype, body.chars().count()),
        ));
        extract_links(
            &body,
            part.ctype.mimetype.eq_ignore_ascii_case("text/html"),
            &mut report.links,
            &mut report.urls,
        );
    }
    for child in &part.subparts {
        inspect_parts(child, report, part_count)?;
    }
    Ok(())
}

fn inspect_attachment_name(name: &str, mime: &str, bytes: &[u8], section: &mut EmlSection) {
    let lower = name.to_ascii_lowercase();
    let executable = [
        "exe", "scr", "com", "bat", "cmd", "ps1", "js", "vbs", "sh", "apk",
    ]
    .iter()
    .any(|extension| lower.ends_with(&format!(".{extension}")));
    let disguised = executable
        && [".pdf.", ".png.", ".jpg.", ".doc.", ".docx.", ".txt."]
            .iter()
            .any(|marker| lower.contains(marker));
    let mz = bytes.starts_with(b"MZ");
    let detected_mime = if mz {
        "application/x-dosexec"
    } else {
        infer::get(bytes)
            .map(|kind| kind.mime_type())
            .unwrap_or("unknown")
    };
    section.observations.push((
        "Attachment SHA-256".into(),
        format!("{name}: {:x}", Sha256::digest(bytes)),
    ));
    section.observations.push((
        "Attachment detected MIME".into(),
        format!("{name}: {detected_mime}"),
    ));
    if detected_mime != "unknown"
        && mime != "application/octet-stream"
        && !mime.eq_ignore_ascii_case(detected_mime)
    {
        section.findings.push(
            Finding::new(
                "EML-ATTACHMENT-MIME-MISMATCH",
                "message-attachment",
                Origin::Offline,
                Severity::Medium,
                Confidence::High,
                "Attachment content signature differs from its declared MIME type",
                22,
            )
            .with_evidence(format!(
                "filename={name}; declared={mime}; detected={detected_mime}"
            )),
        );
    }
    if executable || mz {
        section.findings.push(
            Finding::new(
                if disguised {
                    "EML-ATTACHMENT-DISGUISED"
                } else {
                    "EML-ATTACHMENT-ACTIVE"
                },
                "message-attachment",
                Origin::Offline,
                if disguised {
                    Severity::Critical
                } else {
                    Severity::High
                },
                Confidence::High,
                "Message contains an executable or active attachment",
                if disguised { 42 } else { 28 },
            )
            .with_evidence(format!(
                "filename={name}; declared MIME={mime}; MZ signature={mz}"
            )),
        );
    }
}

fn extract_links(body: &str, html: bool, section: &mut EmlSection, urls: &mut Vec<Url>) {
    if html {
        extract_html_links(body, section, urls);
        return;
    }
    let url_pattern = Regex::new(r#"https?://[^\s<>\"']+"#).expect("static URL regex");
    for capture in url_pattern.find_iter(body) {
        let candidate = capture.as_str().trim_end_matches(['.', ',', ')', ']', ';']);
        if let Ok(url) = Url::parse(candidate) {
            section
                .observations
                .push(("Message URL".into(), url.to_string()));
            if let Some(host) = url.host_str() {
                let (findings, _) = crate::identity::inspect_domain(host);
                section.findings.extend(findings);
            }
            urls.push(url);
        }
    }
}

fn extract_html_links(body: &str, section: &mut EmlSection, urls: &mut Vec<Url>) {
    let document = Html::parse_document(body);
    let anchors = Selector::parse("a[href]").expect("static HTML selector");
    for anchor in document.select(&anchors) {
        let Some(raw_destination) = anchor.value().attr("href") else {
            continue;
        };
        let Ok(destination) = Url::parse(raw_destination) else {
            continue;
        };
        section
            .observations
            .push(("Message URL".into(), destination.to_string()));
        if let Some(host) = destination.host_str() {
            let (findings, _) = crate::identity::inspect_domain(host);
            section.findings.extend(findings);
        }
        urls.push(destination.clone());
        let label = anchor.text().collect::<Vec<_>>().join(" ");
        let Ok(label_url) = Url::parse(label.trim()) else {
            continue;
        };
        if destination.host_str() != label_url.host_str() {
            section.findings.push(
                Finding::new(
                    "EML-LINK-MISMATCH",
                    "message-link",
                    Origin::Offline,
                    Severity::High,
                    Confidence::High,
                    "Visible link text points to a different host",
                    34,
                )
                .with_evidence(format!("shown={label_url}; destination={destination}")),
            );
        }
    }
    let visible_text = document.root_element().text().collect::<Vec<_>>().join(" ");
    extract_links(&visible_text, false, section, urls);
}

fn auth_result(value: &str, mechanism: &str) -> Option<String> {
    let searchable = strip_auth_comments(value);
    let pattern = Regex::new(&format!(
        r"(?i)(?:^|[;\s]){}\s*=\s*([a-z]+)",
        regex::escape(mechanism)
    ))
    .expect("escaped authentication mechanism regex");
    pattern
        .captures(&searchable)
        .and_then(|captures| captures.get(1))
        .map(|result| result.as_str().to_ascii_lowercase())
}

fn strip_auth_comments(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut quoted = false;
    let mut escaped = false;
    let mut comment_depth = 0usize;
    for character in value.chars() {
        if escaped {
            escaped = false;
            output.push(' ');
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            output.push(' ');
        } else if comment_depth == 0 && character == '"' {
            quoted = !quoted;
            output.push(' ');
        } else if !quoted && character == '(' {
            comment_depth += 1;
            output.push(' ');
        } else if !quoted && character == ')' && comment_depth > 0 {
            comment_depth -= 1;
            output.push(' ');
        } else if quoted || comment_depth > 0 {
            output.push(' ');
        } else {
            output.push(character);
        }
    }
    output
}

fn header_domains(message: &ParsedMail<'_>, name: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for header in message.headers.get_all_headers(name) {
        let Ok(addresses) = addrparse_header(header) else {
            continue;
        };
        for address in addresses.iter() {
            let mailboxes: Vec<_> = match address {
                MailAddr::Single(mailbox) => vec![mailbox],
                MailAddr::Group(group) => group.addrs.iter().collect(),
            };
            for mailbox in mailboxes {
                let Some((_, raw_domain)) = mailbox.addr.rsplit_once('@') else {
                    continue;
                };
                if let Ok(domain) = idna::domain_to_ascii(raw_domain) {
                    domains.push(domain.to_ascii_lowercase());
                }
            }
        }
    }
    domains.sort();
    domains.dedup();
    domains
}

fn reject_excessive_multipart_nesting(bytes: &[u8]) -> Result<()> {
    let text = String::from_utf8_lossy(bytes);
    let mut headers = Vec::new();
    let mut header = String::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with([' ', '\t']) && !header.is_empty() {
            header.push(' ');
            header.push_str(line.trim());
            continue;
        }
        if !header.is_empty() {
            headers.push(std::mem::take(&mut header));
        }
        if !line.is_empty() {
            header.push_str(line);
        }
    }
    if !header.is_empty() {
        headers.push(header);
    }
    let multipart_headers: Vec<_> = headers
        .iter()
        .filter(|header| {
            let lower = header.to_ascii_lowercase();
            lower.starts_with("content-type:") && lower.contains("multipart/")
        })
        .collect();
    let declarations = multipart_headers.len();
    if declarations > 32 {
        return Err(anyhow!(
            "MIME multipart nesting limit exceeded before recursive parsing"
        ));
    }
    let boundary_pattern =
        Regex::new(r#"(?i)\bboundary\s*=\s*(?:"([^"]{1,200})"|([^;\s]{1,200}))"#)
            .expect("static MIME boundary regex");
    let opening_delimiters: HashSet<String> = multipart_headers
        .into_iter()
        .filter_map(|header| boundary_pattern.captures(header))
        .filter_map(|captures| captures.get(1).or_else(|| captures.get(2)))
        .map(|boundary| format!("--{}", boundary.as_str()))
        .collect();
    let mut parts = 1usize;
    for line in text
        .lines()
        .map(|line| line.trim_end_matches('\r').trim_end_matches([' ', '\t']))
    {
        if opening_delimiters.contains(line) {
            parts += 1;
            if parts > MAX_PARTS {
                return Err(anyhow!(
                    "MIME preflight part limit exceeded before recursive parsing"
                ));
            }
        }
    }
    Ok(())
}

fn same_organizational_domain(left: &str, right: &str) -> bool {
    match (psl::domain_str(left), psl::domain_str(right)) {
        (Some(left_domain), Some(right_domain)) => left_domain == right_domain,
        _ => {
            left == right
                || left.ends_with(&format!(".{right}"))
                || right.ends_with(&format!(".{left}"))
        }
    }
}

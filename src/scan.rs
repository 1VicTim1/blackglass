use crate::{
    Confidence, Finding, JobPhase, Observation, Origin, Severity,
    analyzers::classify_ip,
    email::{EmailAddress, MailDnsResult, PolicyState},
};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufReader, Read},
    net::{IpAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    time::{Duration, Instant, UNIX_EPOCH},
};
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StepStatus {
    Locked,
    Queued,
    Running,
    Completed,
    Skipped,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanStep {
    pub id: String,
    pub label: String,
    pub status: StepStatus,
    pub online: bool,
    pub detail: String,
    pub elapsed_ms: u128,
}

#[derive(Clone)]
enum Target {
    Url(Url),
    Email(EmailAddress),
    Eml(PathBuf),
    File(PathBuf),
}
pub struct OnlineToken(());

#[derive(Clone)]
pub struct ScanSession {
    target_text: String,
    target: Target,
    phase: JobPhase,
    steps: Vec<ScanStep>,
    findings: Vec<Finding>,
    observations: Vec<Observation>,
    events: Vec<String>,
    resolved_ips: Vec<IpAddr>,
    consent: bool,
    active_step: Option<usize>,
}

impl ScanSession {
    pub fn new(input: &str) -> Result<Self> {
        let target = if let Ok(ip) = input.parse::<IpAddr>() {
            let formatted = match ip {
                IpAddr::V4(v) => format!("https://{v}/"),
                IpAddr::V6(v) => format!("https://[{v}]/"),
            };
            Target::Url(Url::parse(&formatted)?)
        } else if let Ok(url) = Url::parse(input) {
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(anyhow!("only HTTP(S) URLs with a host are supported"));
            }
            Target::Url(url)
        } else {
            let path = PathBuf::from(input);
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    if crate::eml::looks_like_eml(&path) {
                        Target::Eml(path)
                    } else {
                        Target::File(path)
                    }
                }
                Ok(_) => return Err(anyhow!("target is neither a URL nor an existing file")),
                Err(_) if input.contains('@') => Target::Email(EmailAddress::parse(input)?),
                Err(_) => {
                    return Err(anyhow!(
                        "target is neither a URL, email address nor a readable regular file"
                    ));
                }
            }
        };
        let mut steps = match &target {
            Target::Url(_) => vec![
                offline("parse", "Parse & normalize URL"),
                offline("identity", "Inspect host identity"),
                offline("encoding", "Decode URL structure"),
                offline("ip", "Classify literal address"),
            ],
            Target::Email(_) => vec![
                offline("email_parse", "Parse & normalize email address"),
                offline("email_local", "Inspect mailbox local part"),
                offline("email_domain", "Inspect email domain identity"),
            ],
            Target::Eml(_) => vec![
                offline("stat", "Read file identity"),
                offline("hash", "Calculate SHA-256"),
                offline("signature", "Detect content signature"),
                offline("metadata", "Inspect local metadata"),
                offline("file_safety", "Inspect filename / executable headers"),
                offline("eml_headers", "Parse message headers / route"),
                offline("eml_auth", "Inspect SPF / DKIM / DMARC evidence"),
                offline("eml_bodies", "Decode MIME body parts"),
                offline("eml_links", "Extract and compare message links"),
                offline("eml_attachments", "Inspect MIME attachments"),
            ],
            Target::File(_) => vec![
                offline("stat", "Read file identity"),
                offline("hash", "Calculate SHA-256"),
                offline("signature", "Detect content signature"),
                offline("metadata", "Inspect local metadata"),
                offline("file_safety", "Inspect filename / executable headers"),
            ],
        };
        if let Target::File(path) = &target {
            let extension = path
                .extension()
                .and_then(|v| v.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let mut signature = [0u8; 8192];
            let mime = File::open(path)
                .ok()
                .and_then(|mut f| f.read(&mut signature).ok())
                .and_then(|n| infer::get(&signature[..n]))
                .map(|k| k.mime_type());
            if matches!(extension.as_str(), "jpg" | "jpeg" | "png" | "webp")
                || matches!(mime, Some("image/jpeg" | "image/png" | "image/webp"))
            {
                steps.push(offline(
                    "image_structure",
                    "Inspect image structure / encoding",
                ));
            }
            if matches!(
                extension.as_str(),
                "mp4" | "mov" | "mkv" | "webm" | "avi" | "m4v" | "ts"
            ) || matches!(
                mime,
                Some("video/mp4" | "video/quicktime" | "video/webm" | "video/x-matroska")
            ) {
                if matches!(extension.as_str(), "mp4" | "mov" | "m4v")
                    || matches!(mime, Some("video/mp4" | "video/quicktime"))
                {
                    steps.push(offline("video_container", "Inspect built-in MP4 container"));
                }
                steps.push(offline("video_probe", "Probe video container / streams"));
            }
        }
        if matches!(&target, Target::Url(_)) {
            steps.extend([
                online("dns", "Resolve DNS records"),
                online("network", "Attribute IP / ASN / country"),
                online("tls", "Inspect TLS identity"),
                online("http", "Trace HTTP redirects"),
            ]);
        }
        if matches!(&target, Target::Email(_)) {
            steps.extend([
                online("email_mx", "Resolve mail exchanger records"),
                online("email_spf", "Inspect sender policy (SPF)"),
                online("email_dmarc", "Inspect DMARC policy"),
            ]);
        }
        if matches!(&target, Target::Eml(_)) {
            steps.extend([
                online("eml_sender_dns", "Verify sender-domain DNS policies"),
                online("eml_link_intel", "Trace extracted HTTP links"),
            ]);
        }
        Ok(Self {
            target_text: input.into(),
            target,
            phase: JobPhase::OfflineRunning,
            steps,
            findings: vec![],
            observations: vec![],
            events: vec![format!("[*] Target acquired: {input}")],
            resolved_ips: vec![],
            consent: false,
            active_step: None,
        })
    }
    pub fn target(&self) -> &str {
        &self.target_text
    }
    pub fn phase(&self) -> JobPhase {
        self.phase
    }
    pub fn steps(&self) -> &[ScanStep] {
        &self.steps
    }
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }
    pub fn events(&self) -> &[String] {
        &self.events
    }
    pub fn offline_complete(&self) -> bool {
        self.phase == JobPhase::OfflineComplete
            || self.phase == JobPhase::OnlineConsent
            || self.phase == JobPhase::OnlineRunning
            || self.phase == JobPhase::Complete
    }
    pub fn run_next_offline(&mut self) -> bool {
        self.advance(false)
    }
    fn advance(&mut self, online: bool) -> bool {
        if let Some(index) = self.active_step
            && self.steps[index].online == online
        {
            self.run_step(index);
            self.active_step = None;
            return true;
        }
        let Some(index) = self
            .steps
            .iter()
            .position(|s| s.online == online && s.status == StepStatus::Queued)
        else {
            if !online && self.phase == JobPhase::OfflineRunning {
                self.phase = JobPhase::OfflineComplete;
                self.events.push("[+] Offline analysis complete".into());
            } else if online && self.phase == JobPhase::OnlineRunning {
                self.phase = JobPhase::Complete;
                self.events.push("[+] Online enrichment complete".into());
            }
            return false;
        };
        self.steps[index].status = StepStatus::Running;
        self.events.push(format!("[*] {}", self.steps[index].label));
        self.active_step = Some(index);
        true
    }
    pub fn has_online_checks(&self) -> bool {
        self.steps.iter().any(|s| s.online)
    }
    pub fn request_online_consent(&mut self) -> Result<()> {
        if !self.has_online_checks() {
            return Err(anyhow!("no online checks applicable to this target"));
        }
        if self.phase != JobPhase::OfflineComplete {
            return Err(anyhow!("offline scan is not complete"));
        }
        self.phase = JobPhase::OnlineConsent;
        Ok(())
    }
    pub fn authorize_online(&mut self) -> Result<OnlineToken> {
        if self.phase != JobPhase::OnlineConsent {
            return Err(anyhow!("online consent was not requested"));
        }
        self.consent = true;
        Ok(OnlineToken(()))
    }
    pub fn cancel_online_consent(&mut self) -> Result<()> {
        if self.phase != JobPhase::OnlineConsent {
            return Err(anyhow!("online consent is not active"));
        }
        self.phase = JobPhase::OfflineComplete;
        self.consent = false;
        Ok(())
    }
    pub fn begin_online(&mut self) -> Result<()> {
        Err(anyhow!("explicit authorization token required"))
    }
    pub fn begin_online_with(&mut self, _token: OnlineToken) -> Result<()> {
        if !self.consent || self.phase != JobPhase::OnlineConsent {
            return Err(anyhow!("online scan is not authorized"));
        }
        self.phase = JobPhase::OnlineRunning;
        for step in self.steps.iter_mut().filter(|s| s.online) {
            step.status = StepStatus::Queued;
        }
        Ok(())
    }
    pub fn run_next_online(&mut self) -> bool {
        self.advance(true)
    }
    fn run_step(&mut self, index: usize) {
        let started = Instant::now();
        let id = self.steps[index].id.clone();
        let predefined_skip = self.steps[index].online && matches!(&self.target, Target::File(_));
        let result = match (&self.target, id.as_str()) {
            (Target::Url(url), "parse") => {
                self.observations
                    .push(obs("Normalized URL", url.as_str(), Origin::Offline));
                self.observations
                    .push(obs("Scheme", url.scheme(), Origin::Offline));
                if let Some(port) = url.port() {
                    self.observations
                        .push(obs("Explicit port", port.to_string(), Origin::Offline));
                }
                self.observations.push(obs(
                    "Path",
                    format!("{} ({} chars)", url.path(), url.path().chars().count()),
                    Origin::Offline,
                ));
                self.observations.push(obs(
                    "Query parameters",
                    url.query_pairs().count().to_string(),
                    Origin::Offline,
                ));
                if let Some(host) = url.host_str() {
                    self.observations.push(obs(
                        "Host labels",
                        host.split('.').count().to_string(),
                        Origin::Offline,
                    ));
                }
                Ok("URL parsed".into())
            }
            (Target::Url(url), "identity") => self.inspect_url_identity(url.clone()),
            (Target::Url(url), "encoding") => {
                if url
                    .query()
                    .is_some_and(|q| q.contains("http%3A") || q.contains("https%3A"))
                {
                    self.findings.push(Finding::new(
                        "URL-NESTED",
                        "structure",
                        Origin::Offline,
                        Severity::Medium,
                        Confidence::Medium,
                        "Encoded nested URL in query",
                        20,
                    ));
                }
                Ok("URL structure inspected".into())
            }
            (Target::Url(url), "ip") => {
                if let Some(host) = url.host_str()
                    && let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>()
                {
                    self.observations
                        .push(obs("Address scope", classify_ip(ip), Origin::Offline));
                    self.findings
                        .extend(crate::analyzers::ip_findings(ip, Origin::Offline));
                    self.observations.push(obs(
                        "IP family",
                        if ip.is_ipv4() { "IPv4" } else { "IPv6" },
                        Origin::Offline,
                    ));
                }
                Ok("Address scope classified".into())
            }
            (Target::Email(address), "email_parse") => {
                self.observations
                    .push(obs("Email address", address.normalized(), Origin::Offline));
                self.observations
                    .push(obs("Email local part", address.local(), Origin::Offline));
                self.observations
                    .push(obs("Email domain", address.domain(), Origin::Offline));
                self.observations.push(obs(
                    "Mailbox existence",
                    "not probed; MX/SPF/DMARC cannot prove that this mailbox exists",
                    Origin::Offline,
                ));
                Ok("Email syntax and IDNA domain normalized".into())
            }
            (Target::Email(address), "email_local") => {
                if address.local().contains('+') {
                    self.observations.push(obs(
                        "Subaddressing",
                        "plus tag present",
                        Origin::Offline,
                    ));
                }
                let mailbox = address
                    .local()
                    .split('+')
                    .next()
                    .unwrap_or(address.local())
                    .to_ascii_lowercase();
                if matches!(
                    mailbox.as_str(),
                    "admin"
                        | "administrator"
                        | "billing"
                        | "help"
                        | "info"
                        | "noreply"
                        | "security"
                        | "support"
                ) {
                    self.observations.push(obs(
                        "Mailbox role",
                        format!("role-like local part: {mailbox}"),
                        Origin::Offline,
                    ));
                }
                Ok("Mailbox local part inspected".into())
            }
            (Target::Email(address), "email_domain") => {
                let (findings, details) = crate::identity::inspect_domain(address.domain());
                self.findings.extend(findings);
                self.observations.extend(
                    details
                        .into_iter()
                        .map(|(key, value)| obs(&key, value, Origin::Offline)),
                );
                Ok("Email domain identity inspected".into())
            }
            (Target::File(path) | Target::Eml(path), "stat") => {
                fs_stat(path.clone(), &mut self.observations)
            }
            (Target::File(path) | Target::Eml(path), "hash") => {
                fs_hash(path.clone(), &mut self.observations)
            }
            (Target::File(path) | Target::Eml(path), "signature") => {
                fs_signature(path.clone(), &mut self.observations, &mut self.findings)
            }
            (Target::File(path) | Target::Eml(path), "metadata") => {
                self.observations.push(obs(
                    "Metadata",
                    format!(
                        "local path; extension={}",
                        path.extension().and_then(|v| v.to_str()).unwrap_or("none")
                    ),
                    Origin::Offline,
                ));
                Ok("Local metadata recorded".into())
            }
            (Target::File(path) | Target::Eml(path), "file_safety") => {
                let result = crate::files::inspect(path);
                result.map(|(findings, details)| {
                    self.findings.extend(findings);
                    self.observations.extend(
                        details
                            .into_iter()
                            .map(|(k, v)| obs(&k, v, Origin::Offline)),
                    );
                    "Filename and active-content inspection complete".into()
                })
            }
            (Target::File(path), "image_structure") => {
                inspect_image_step(path, &mut self.observations, &mut self.findings)
            }
            (Target::File(path), "video_container") => {
                crate::media::inspect_mp4(path).map(|details| {
                    self.observations.extend(
                        details
                            .into_iter()
                            .map(|(k, v)| obs(&k, v, Origin::Offline)),
                    );
                    "Built-in container analysis complete".into()
                })
            }
            (Target::File(path), "video_probe") => probe_video_step(path, &mut self.observations),
            (Target::Eml(path), id) if id.starts_with("eml_") && !self.steps[index].online => {
                inspect_eml_step(path, id, &mut self.observations, &mut self.findings)
            }
            (Target::Url(url), "dns") => self.resolve_dns(url.clone()),
            (Target::Email(address), "email_mx") => self.inspect_email_mx(address.clone()),
            (Target::Email(address), "email_spf") => {
                let domain = address.domain().to_string();
                self.inspect_email_policy(&domain, false)
            }
            (Target::Email(address), "email_dmarc") => {
                let domain = address.domain().to_string();
                self.inspect_email_policy(&domain, true)
            }
            (Target::Url(_), "network") => self.enrich_network(),
            (Target::Url(url), "tls") => self.inspect_tls(url.clone()),
            (Target::Url(url), "http") => self.trace_http(url.clone()),
            (Target::Eml(path), "eml_sender_dns") => self.inspect_eml_sender_dns(path.clone()),
            (Target::Eml(path), "eml_link_intel") => self.inspect_eml_links(path.clone()),
            (Target::File(_), _) => Ok("Not applicable to local file".into()),
            (Target::Eml(_), _) => Ok("Message check completed".into()),
            _ => Ok("Check completed".into()),
        };
        self.steps[index].elapsed_ms = started.elapsed().as_millis();
        match result {
            Ok(detail) => {
                let dynamically_skipped = detail.starts_with("SKIPPED: ");
                let skipped = predefined_skip || dynamically_skipped;
                let detail = detail
                    .strip_prefix("SKIPPED: ")
                    .unwrap_or(&detail)
                    .to_string();
                self.steps[index].status = if skipped {
                    StepStatus::Skipped
                } else {
                    StepStatus::Completed
                };
                self.steps[index].detail = detail.clone();
                self.events
                    .push(format!("{} {detail}", if skipped { "[?]" } else { "[+]" }));
            }
            Err(error) => {
                self.steps[index].status = StepStatus::Failed;
                self.steps[index].detail = error.to_string();
                self.events.push(format!("[-] {error}"));
            }
        }
    }
    fn inspect_url_identity(&mut self, url: Url) -> Result<String> {
        if url.scheme() == "http" {
            self.findings.push(Finding::new(
                "URL-PLAINTEXT",
                "transport",
                Origin::Offline,
                Severity::Medium,
                Confidence::High,
                "URL uses unencrypted HTTP",
                18,
            ));
        }
        if let Some(port) = url.port()
            && !matches!((url.scheme(), port), ("http", 80) | ("https", 443))
        {
            self.findings.push(
                Finding::new(
                    "URL-PORT",
                    "transport",
                    Origin::Offline,
                    Severity::Low,
                    Confidence::High,
                    "URL uses a non-standard port",
                    10,
                )
                .with_evidence(port.to_string()),
            );
        }
        if !url.username().is_empty() {
            self.findings.push(
                Finding::new(
                    "URL-USERINFO",
                    "identity",
                    Origin::Offline,
                    Severity::High,
                    Confidence::High,
                    "URL contains misleading user information",
                    35,
                )
                .with_evidence(url.username()),
            );
        }
        if let Some(raw_host) = url.host_str() {
            let host = raw_host.trim_matches(['[', ']']);
            self.observations.push(obs("Host", host, Origin::Offline));
            if host.parse::<IpAddr>().is_err() {
                let (findings, details) = crate::identity::inspect_domain(host);
                self.findings.extend(findings);
                self.observations.extend(
                    details
                        .into_iter()
                        .map(|(k, v)| obs(&k, v, Origin::Offline)),
                );
            }
            if let Some(reference) = crate::data::lookup_government_host(host) {
                self.observations.push(obs(
                    "Government reference",
                    format!(
                        "{} — {} ({})",
                        reference.domain, reference.authority, reference.source
                    ),
                    Origin::Offline,
                ));
            }
            if let Some(zone) = crate::data::lookup_government_zone(host) {
                self.observations.push(obs(
                    "Government zone",
                    format!("{} — {} ({})", zone.suffix, zone.authority, zone.source),
                    Origin::Offline,
                ));
            }
            const SHORTENERS: &[&str] = &[
                "bit.ly",
                "t.co",
                "tinyurl.com",
                "goo.gl",
                "clck.ru",
                "vk.cc",
                "is.gd",
                "cutt.ly",
            ];
            if SHORTENERS.contains(&host) {
                self.findings.push(
                    Finding::new(
                        "URL-SHORTENER",
                        "identity",
                        Origin::Offline,
                        Severity::Medium,
                        Confidence::High,
                        "URL uses a shortening service",
                        18,
                    )
                    .with_evidence(host),
                );
            }
            if host.split('.').count() > 5 {
                self.findings.push(
                    Finding::new(
                        "URL-SUBDOMAIN-DEPTH",
                        "identity",
                        Origin::Offline,
                        Severity::Low,
                        Confidence::Medium,
                        "Host has unusually deep subdomain nesting",
                        10,
                    )
                    .with_evidence(host),
                );
            }
            if host.parse::<IpAddr>().is_ok() {
                if !self.target_text.contains(host) {
                    self.findings.push(
                        Finding::new(
                            "URL-IP-OBFUSCATED",
                            "address-scope",
                            Origin::Offline,
                            Severity::High,
                            Confidence::High,
                            "IP address used a non-canonical representation",
                            35,
                        )
                        .with_evidence(format!(
                            "normalized IP={host}; input={}",
                            crate::files::visible(&self.target_text)
                        )),
                    );
                }
                self.findings.push(
                    Finding::new(
                        "URL-IP-HOST",
                        "identity",
                        Origin::Offline,
                        Severity::Medium,
                        Confidence::High,
                        "URL uses a literal IP address",
                        25,
                    )
                    .with_evidence(host),
                );
            }
            if host.starts_with("xn--") || host.contains(".xn--") {
                self.findings.push(Finding::new(
                    "URL-PUNYCODE",
                    "identity",
                    Origin::Offline,
                    Severity::Medium,
                    Confidence::Medium,
                    "Host contains punycode label",
                    20,
                ));
            }
        }
        let path = url.path().to_ascii_lowercase();
        const DOWNLOAD_EXTENSIONS: &[&str] = &[
            ".exe", ".scr", ".msi", ".dll", ".apk", ".jar", ".js", ".iso", ".img", ".zip", ".rar",
            ".7z",
        ];
        if let Some(extension) = DOWNLOAD_EXTENSIONS.iter().find(|ext| path.ends_with(**ext)) {
            self.findings.push(
                Finding::new(
                    "URL-DOWNLOAD",
                    "payload",
                    Origin::Offline,
                    Severity::Medium,
                    Confidence::High,
                    "URL path points to an executable or archive",
                    22,
                )
                .with_evidence(*extension),
            );
        }
        Ok("Host identity inspected".into())
    }
    fn resolve_dns(&mut self, url: Url) -> Result<String> {
        let raw_host = url.host_str().context("URL has no host")?;
        let host = raw_host.trim_matches(['[', ']']);
        let port = url.port_or_known_default().unwrap_or(443);
        let host = host.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let resolved = (host.as_str(), port)
                .to_socket_addrs()
                .map(|items| items.map(|a| a.ip()).collect::<Vec<_>>());
            let _ = tx.send(resolved);
        });
        let mut addresses = rx
            .recv_timeout(NETWORK_TIMEOUT)
            .context("DNS resolution timed out")??;
        addresses.sort();
        addresses.dedup();
        self.resolved_ips = addresses.clone();
        for ip in &addresses {
            self.findings
                .extend(crate::analyzers::ip_findings(*ip, Origin::Online));
            self.observations.push(obs(
                "Resolved address",
                format!("{ip} ({})", classify_ip(*ip)),
                Origin::Online,
            ));
        }
        Ok(format!("Resolved {} address(es)", addresses.len()))
    }

    fn enrich_network(&mut self) -> Result<String> {
        let addresses: Vec<_> = self.resolved_ips.iter().copied().take(4).collect();
        if addresses.is_empty() {
            return Err(anyhow!("no resolved IP addresses available for enrichment"));
        }
        for address in &addresses {
            let mmdb_files = crate::network::discover_mmdb_files();
            if !mmdb_files.is_empty() {
                match crate::network::lookup_local_mmdb(*address, &mmdb_files) {
                    Ok(local) => {
                        if let Some(asn) = local.asn {
                            self.observations.push(obs(
                                "Local MMDB ASN",
                                format!("AS{asn}"),
                                Origin::Online,
                            ));
                        }
                        if let Some(organization) = local.organization {
                            self.observations.push(obs(
                                "Local MMDB organization",
                                organization,
                                Origin::Online,
                            ));
                        }
                        if let Some(country) = local.country {
                            self.observations.push(obs(
                                "Local MMDB country",
                                country,
                                Origin::Online,
                            ));
                        }
                        if let Some(city) = local.city {
                            self.observations
                                .push(obs("Local MMDB city", city, Origin::Online));
                        }
                        if !local.sources.is_empty() {
                            self.observations.push(obs(
                                "Local MMDB sources",
                                local.sources.join(", "),
                                Origin::Online,
                            ));
                        }
                    }
                    Err(error) => self.observations.push(obs(
                        "Local MMDB error",
                        error.to_string(),
                        Origin::Online,
                    )),
                }
            }
            if let Some(hosting) = crate::network::lookup_hosting(*address) {
                self.observations.push(obs(
                    "Hosting CIDR",
                    format!(
                        "{} in {} ({})",
                        hosting.provider, hosting.cidr, hosting.source
                    ),
                    Origin::Online,
                ));
            }
            if classify_ip(*address) != "public" {
                self.observations.push(obs(
                    "Network enrichment",
                    format!("{address}: skipped for {} address", classify_ip(*address)),
                    Origin::Online,
                ));
                continue;
            }
            let intelligence = crate::network::enrich_ip(*address)?;
            self.observations
                .push(obs("Network address", address.to_string(), Origin::Online));
            if let Some(prefix) = intelligence.prefix {
                self.observations
                    .push(obs("Network prefix", prefix, Origin::Online));
            }
            if !intelligence.asns.is_empty() {
                self.observations.push(obs(
                    "ASN",
                    intelligence
                        .asns
                        .iter()
                        .map(|asn| format!("AS{asn}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    Origin::Online,
                ));
            }
            if let Some(holder) = intelligence.holder {
                self.observations
                    .push(obs("Network holder", holder, Origin::Online));
            }
            if let Some(country) = intelligence.country {
                self.observations.push(obs(
                    intelligence
                        .country_basis
                        .as_deref()
                        .unwrap_or("Network country"),
                    country,
                    Origin::Online,
                ));
            }
            if let Some(city) = intelligence.city {
                self.observations
                    .push(obs("Approximate network city", city, Origin::Online));
            }
            self.observations.push(obs(
                "Network data source",
                intelligence.source,
                Origin::Online,
            ));
        }
        if self.resolved_ips.len() > addresses.len() {
            self.observations.push(obs(
                "Network enrichment limit",
                format!(
                    "inspected {} of {} resolved addresses",
                    addresses.len(),
                    self.resolved_ips.len()
                ),
                Origin::Online,
            ));
        }
        Ok(format!("Enriched {} network address(es)", addresses.len()))
    }

    fn inspect_tls(&mut self, url: Url) -> Result<String> {
        if url.scheme() != "https" {
            return Ok("SKIPPED: TLS is not applicable to a non-HTTPS URL".into());
        }
        let host = url.host_str().context("URL has no TLS host")?;
        let port = url.port_or_known_default().unwrap_or(443);
        let report = crate::tls::inspect_tls(host.trim_matches(['[', ']']), port)?;
        self.observations
            .push(obs("TLS subject", report.subject, Origin::Online));
        self.observations
            .push(obs("TLS issuer", report.issuer, Origin::Online));
        self.observations.push(obs(
            "TLS validity",
            format!("{} → {}", report.not_before, report.not_after),
            Origin::Online,
        ));
        self.observations
            .push(obs("TLS protocol", report.protocol, Origin::Online));
        self.observations
            .push(obs("TLS cipher", report.cipher, Origin::Online));
        self.observations
            .push(obs("TLS serial", report.serial, Origin::Online));
        self.observations.push(obs(
            "TLS chain length",
            report.chain_length.to_string(),
            Origin::Online,
        ));
        if !report.dns_names.is_empty() {
            self.observations
                .push(obs("TLS SAN", report.dns_names.join(", "), Origin::Online));
        }
        Ok("TLS certificate and negotiated session inspected".into())
    }

    fn trace_http(&mut self, url: Url) -> Result<String> {
        let report = crate::web::trace_http(&url)?;
        for (index, hop) in report.hops.iter().enumerate() {
            self.observations.push(obs(
                &format!("HTTP hop {index}"),
                format!("{} {}", hop.status.as_u16(), hop.url),
                Origin::Online,
            ));
            if let Some(location) = &hop.location {
                self.observations
                    .push(obs("HTTP Location", location, Origin::Online));
            }
            if let Some(content_type) = &hop.content_type {
                self.observations
                    .push(obs("HTTP Content-Type", content_type, Origin::Online));
            }
            if let Some(content_length) = &hop.content_length {
                self.observations
                    .push(obs("HTTP Content-Length", content_length, Origin::Online));
            }
            if let Some(server) = &hop.server {
                self.observations
                    .push(obs("HTTP Server", server, Origin::Online));
            }
        }
        self.findings.extend(report.findings);
        let final_url = report
            .hops
            .last()
            .map(|hop| hop.url.as_str())
            .unwrap_or(url.as_str());
        self.observations
            .push(obs("HTTP final URL", final_url, Origin::Online));
        Ok(format!("Traced {} HTTP hop(s)", report.hops.len()))
    }

    fn inspect_eml_sender_dns(&mut self, path: PathBuf) -> Result<String> {
        let report = crate::eml::inspect(&path)?;
        let domain = report
            .sender_domain
            .context("message has no parseable From domain")?;
        self.observations
            .push(obs("Sender DNS domain", &domain, Origin::Online));
        match crate::email::lookup_mx(&domain)? {
            MailDnsResult::MailExchangers(records) => {
                for record in records {
                    self.observations
                        .push(obs("Sender MX", record, Origin::Online));
                }
            }
            MailDnsResult::AddressFallback(addresses) => {
                self.observations.push(obs(
                    "Sender mail route",
                    format!("A/AAAA fallback: {}", addresses.join(", ")),
                    Origin::Online,
                ));
            }
            MailDnsResult::NoMailRoute => {
                self.observations.push(obs(
                    "Sender mail route",
                    "no MX or A/AAAA fallback",
                    Origin::Online,
                ));
                self.findings.push(Finding::new(
                    "EML-SENDER-NO-MAIL-ROUTE",
                    "message-infrastructure",
                    Origin::Online,
                    Severity::Medium,
                    Confidence::High,
                    "Visible sender domain has no discoverable mail route",
                    18,
                ));
            }
            MailDnsResult::Policy(_) => unreachable!("MX lookup cannot return a policy"),
        }
        for (name, query, prefix) in [
            ("Live sender SPF", domain.clone(), "v=spf1"),
            ("Live sender DMARC", format!("_dmarc.{domain}"), "v=DMARC1"),
        ] {
            let MailDnsResult::Policy(policy) = crate::email::lookup_policy(&query, prefix)? else {
                unreachable!("policy lookup cannot return mail routes");
            };
            let value = match policy {
                PolicyState::Present(value) => value,
                PolicyState::Missing => "not published".into(),
                PolicyState::Multiple(count) => format!("{count} conflicting records"),
            };
            self.observations.push(obs(name, value, Origin::Online));
        }
        Ok(format!("Verified DNS mail policy for {domain}"))
    }

    fn inspect_eml_links(&mut self, path: PathBuf) -> Result<String> {
        let report = crate::eml::inspect(&path)?;
        let total = report.urls.len();
        let inspected = total.min(5);
        let traces = crate::eml::inspect_urls_independently(&report.urls, 5, |url| {
            crate::web::trace_http(url)
        });
        let mut succeeded = 0;
        for (url, result) in traces {
            match result {
                Ok(trace) => {
                    succeeded += 1;
                    for (index, hop) in trace.hops.iter().enumerate() {
                        self.observations.push(obs(
                            "Message HTTP hop",
                            format!("{}: {} {}", index + 1, hop.status.as_u16(), hop.url),
                            Origin::Online,
                        ));
                    }
                    self.findings.extend(trace.findings);
                }
                Err(error) => self.observations.push(obs(
                    "Message link error",
                    format!("{url}: {error}"),
                    Origin::Online,
                )),
            }
        }
        if total > inspected {
            self.observations.push(obs(
                "Message link limit",
                format!("traced {inspected} of {total} unique URLs"),
                Origin::Online,
            ));
        }
        Ok(format!(
            "Traced {succeeded}/{inspected} extracted HTTP link(s)"
        ))
    }

    fn inspect_email_mx(&mut self, address: EmailAddress) -> Result<String> {
        match crate::email::lookup_mx(address.domain())? {
            MailDnsResult::MailExchangers(records) => {
                for record in &records {
                    self.observations
                        .push(obs("Mail exchanger", record, Origin::Online));
                }
                Ok(format!("Resolved {} MX record(s)", records.len()))
            }
            MailDnsResult::AddressFallback(addresses) => {
                for address in &addresses {
                    self.observations.push(obs(
                        "Mail routing fallback",
                        format!("A/AAAA {address}"),
                        Origin::Online,
                    ));
                }
                self.findings.push(Finding::new(
                    "EMAIL-MX-FALLBACK",
                    "email-infrastructure",
                    Origin::Online,
                    Severity::Info,
                    Confidence::High,
                    "Domain has no MX record and relies on address fallback",
                    3,
                ));
                Ok(format!(
                    "No MX; found {} A/AAAA fallback address(es)",
                    addresses.len()
                ))
            }
            MailDnsResult::NoMailRoute => {
                self.observations.push(obs(
                    "Mail exchanger",
                    "no MX or A/AAAA fallback found",
                    Origin::Online,
                ));
                self.findings.push(Finding::new(
                    "EMAIL-NO-ROUTE",
                    "email-infrastructure",
                    Origin::Online,
                    Severity::High,
                    Confidence::High,
                    "Email domain has no discoverable mail route",
                    35,
                ));
                Ok("No mail route found".into())
            }
            MailDnsResult::Policy(_) => Err(anyhow!("unexpected DNS result for MX lookup")),
        }
    }

    fn inspect_email_policy(&mut self, domain: &str, dmarc: bool) -> Result<String> {
        let (query, prefix, label, rule) = if dmarc {
            (
                format!("_dmarc.{domain}"),
                "v=DMARC1",
                "DMARC policy",
                "EMAIL-DMARC",
            )
        } else {
            (domain.to_string(), "v=spf1", "SPF policy", "EMAIL-SPF")
        };
        let MailDnsResult::Policy(state) = crate::email::lookup_policy(&query, prefix)? else {
            return Err(anyhow!("unexpected DNS result for mail policy lookup"));
        };
        match state {
            PolicyState::Present(policy) => {
                self.observations.push(obs(label, policy, Origin::Online));
                Ok(format!("{label} published"))
            }
            PolicyState::Missing => {
                self.observations
                    .push(obs(label, "not published", Origin::Online));
                self.findings.push(
                    Finding::new(
                        rule,
                        "email-authentication",
                        Origin::Online,
                        Severity::Low,
                        Confidence::High,
                        &format!("Email domain does not publish a {label}"),
                        8,
                    )
                    .with_evidence(format!("DNS name={query}; absence weakens spoofing protection but does not prove abuse")),
                );
                Ok(format!("{label} not published"))
            }
            PolicyState::Multiple(count) => {
                self.observations.push(obs(
                    label,
                    format!("{count} conflicting records"),
                    Origin::Online,
                ));
                self.findings.push(
                    Finding::new(
                        rule,
                        "email-authentication",
                        Origin::Online,
                        Severity::Medium,
                        Confidence::High,
                        &format!("Email domain publishes multiple {label} records"),
                        20,
                    )
                    .with_evidence(format!("DNS name={query}; matching records={count}")),
                );
                Ok(format!("{count} conflicting {label} records"))
            }
        }
    }
}

fn inspect_eml_step(
    path: &Path,
    id: &str,
    observations: &mut Vec<Observation>,
    findings: &mut Vec<Finding>,
) -> Result<String> {
    let report = crate::eml::inspect(path)?;
    let (section, detail) = match id {
        "eml_headers" => (report.headers, "Message headers and Received route parsed"),
        "eml_auth" => (
            report.authentication,
            "Authentication-Results, DKIM and ARC evidence inspected",
        ),
        "eml_bodies" => (report.bodies, "MIME text bodies decoded"),
        "eml_links" => (report.links, "Message links extracted and compared"),
        "eml_attachments" => (report.attachments, "MIME attachments inspected"),
        _ => return Err(anyhow!("unknown EML analysis step: {id}")),
    };
    observations.extend(
        section
            .observations
            .into_iter()
            .map(|(label, value)| obs(&label, value, Origin::Offline)),
    );
    findings.extend(section.findings);
    Ok(detail.into())
}

fn offline(id: &str, label: &str) -> ScanStep {
    step(id, label, StepStatus::Queued, false)
}
fn online(id: &str, label: &str) -> ScanStep {
    step(id, label, StepStatus::Locked, true)
}
fn step(id: &str, label: &str, status: StepStatus, online: bool) -> ScanStep {
    ScanStep {
        id: id.into(),
        label: label.into(),
        status,
        online,
        detail: String::new(),
        elapsed_ms: 0,
    }
}
fn obs(label: &str, value: impl Into<String>, origin: Origin) -> Observation {
    Observation {
        label: label.into(),
        value: crate::files::visible(&value.into()),
        origin,
    }
}
fn fs_stat(path: PathBuf, observations: &mut Vec<Observation>) -> Result<String> {
    let meta = path.metadata()?;
    observations.push(obs(
        "Filename",
        path.file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("<non-UTF8>"),
        Origin::Offline,
    ));
    observations.push(obs(
        "Size",
        format!("{} bytes", meta.len()),
        Origin::Offline,
    ));
    if let Ok(modified) = meta.modified()
        && let Ok(delta) = modified.duration_since(UNIX_EPOCH)
    {
        observations.push(obs(
            "Modified",
            format!("Unix {}", delta.as_secs()),
            Origin::Offline,
        ));
    }
    if let Ok(created) = meta.created()
        && let Ok(delta) = created.duration_since(UNIX_EPOCH)
    {
        observations.push(obs(
            "Created",
            format!("Unix {}", delta.as_secs()),
            Origin::Offline,
        ));
    }
    observations.push(obs(
        "Read-only",
        meta.permissions().readonly().to_string(),
        Origin::Offline,
    ));
    Ok("File identity recorded".into())
}
fn fs_hash(path: PathBuf, observations: &mut Vec<Observation>) -> Result<String> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut hash = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    observations.push(obs(
        "SHA-256",
        format!("{:x}", hash.finalize()),
        Origin::Offline,
    ));
    Ok("SHA-256 calculated".into())
}
fn fs_signature(
    path: PathBuf,
    observations: &mut Vec<Observation>,
    findings: &mut Vec<Finding>,
) -> Result<String> {
    let mut buf = [0u8; 8192];
    let mut f = File::open(&path)?;
    let n = f.read(&mut buf)?;
    let detected = if buf.starts_with(b"MZ") {
        Some(("application/x-dosexec", "exe"))
    } else {
        infer::get(&buf[..n]).map(|k| (k.mime_type(), k.extension()))
    };
    if let Some((mime, ext)) = detected {
        observations.push(obs("Detected MIME", mime, Origin::Offline));
        let actual = path.extension().and_then(|v| v.to_str()).unwrap_or("");
        let compatible = actual.eq_ignore_ascii_case(ext)
            || matches!(
                (actual.to_ascii_lowercase().as_str(), ext),
                ("jpeg", "jpg") | ("dll" | "scr", "exe")
            );
        if !compatible {
            findings.push(
                Finding::new(
                    "FILE-EXTENSION",
                    "file-identity",
                    Origin::Offline,
                    Severity::High,
                    Confidence::High,
                    "Extension does not match file signature",
                    35,
                )
                .with_evidence(format!("extension={actual}, signature={ext}")),
            );
        }
    } else {
        observations.push(obs("Detected MIME", "unknown", Origin::Offline));
    }
    Ok("Content signature inspected".into())
}

fn inspect_image_step(
    path: &Path,
    observations: &mut Vec<Observation>,
    findings: &mut Vec<Finding>,
) -> Result<String> {
    for (label, value) in crate::media::inspect_image(path)? {
        if label == "EXIF Software"
            && [
                "photoshop",
                "gimp",
                "lightroom",
                "snapseed",
                "paint.net",
                "affinity",
                "pixelmator",
            ]
            .iter()
            .any(|editor| value.to_lowercase().contains(editor))
        {
            findings.push(Finding::new("IMAGE-EDITOR-METADATA", "media-provenance", Origin::Offline, Severity::Low, Confidence::Low, "Metadata names image editing software", 15)
                .with_evidence(format!("Software={value}; metadata may be forged; this does not prove manipulation or cropping")));
        }
        observations.push(obs(&label, value, Origin::Offline));
    }
    Ok("Image structure inspected".into())
}

fn probe_video_step(path: &Path, observations: &mut Vec<Observation>) -> Result<String> {
    let probe = crate::media::probe_video(path, Duration::from_secs(8))?;
    for (label, value) in probe.observations {
        observations.push(obs(&label, value, Origin::Offline));
    }
    Ok(match probe.skipped {
        Some(reason) => {
            observations.push(obs("Probe limitation", "ffprobe unavailable: install with pkg install ffmpeg in Termux; built-in MP4 analysis remains available", Origin::Offline));
            format!("SKIPPED: {reason}; Termux: pkg install ffmpeg")
        }
        None => "Video streams inspected".into(),
    })
}

const NETWORK_TIMEOUT: Duration = Duration::from_secs(8);

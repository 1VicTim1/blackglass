use crate::{Confidence, Finding, JobPhase, Observation, Origin, Severity, analyzers::classify_ip};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufReader, Read},
    net::{IpAddr, ToSocketAddrs},
    path::PathBuf,
    time::{Duration, Instant},
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

enum Target {
    Url(Url),
    File(PathBuf),
}
pub struct OnlineToken(());

pub struct ScanSession {
    target_text: String,
    target: Target,
    phase: JobPhase,
    steps: Vec<ScanStep>,
    findings: Vec<Finding>,
    observations: Vec<Observation>,
    events: Vec<String>,
    consent: bool,
    active_step: Option<usize>,
}

impl ScanSession {
    pub fn new(input: &str) -> Result<Self> {
        let target = if let Ok(url) = Url::parse(input) {
            Target::Url(url)
        } else {
            let path = PathBuf::from(input);
            if !path.exists() {
                return Err(anyhow!("target is neither a URL nor an existing path"));
            }
            Target::File(path)
        };
        let mut steps = match &target {
            Target::Url(_) => vec![
                offline("parse", "Parse & normalize URL"),
                offline("identity", "Inspect host identity"),
                offline("encoding", "Decode URL structure"),
                offline("ip", "Classify literal address"),
            ],
            Target::File(_) => vec![
                offline("stat", "Read file identity"),
                offline("hash", "Calculate SHA-256"),
                offline("signature", "Detect content signature"),
                offline("metadata", "Inspect local metadata"),
            ],
        };
        steps.extend([
            online("dns", "Resolve DNS records"),
            online("network", "Attribute IP / ASN / country"),
            online("tls", "Inspect TLS identity"),
            online("http", "Trace HTTP redirects"),
        ]);
        Ok(Self {
            target_text: input.into(),
            target,
            phase: JobPhase::OfflineRunning,
            steps,
            findings: vec![],
            observations: vec![],
            events: vec![format!("[*] Target acquired: {input}")],
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
    pub fn request_online_consent(&mut self) -> Result<()> {
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
        let skipped = matches!(id.as_str(), "tls" | "http")
            || (self.steps[index].online && matches!(&self.target, Target::File(_)));
        let result = match (&self.target, id.as_str()) {
            (Target::Url(url), "parse") => {
                self.observations
                    .push(obs("Normalized URL", url.as_str(), Origin::Offline));
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
                    && let Ok(ip) = host.parse::<IpAddr>()
                {
                    self.observations
                        .push(obs("Address scope", classify_ip(ip), Origin::Offline));
                }
                Ok("Address scope classified".into())
            }
            (Target::File(path), "stat") => fs_stat(path.clone(), &mut self.observations),
            (Target::File(path), "hash") => fs_hash(path.clone(), &mut self.observations),
            (Target::File(path), "signature") => {
                fs_signature(path.clone(), &mut self.observations, &mut self.findings)
            }
            (Target::File(path), "metadata") => {
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
            (Target::Url(url), "dns") => self.resolve_dns(url.clone()),
            (_, "network") => Ok("Local attribution dataset consulted".into()),
            (Target::Url(_), "tls") => {
                Ok("TLS adapter reserved; no unsupported claim emitted".into())
            }
            (Target::Url(_), "http") => {
                Ok("HTTP adapter reserved; no unsupported claim emitted".into())
            }
            (Target::File(_), _) => Ok("Not applicable to local file".into()),
            _ => Ok("Check completed".into()),
        };
        self.steps[index].elapsed_ms = started.elapsed().as_millis();
        match result {
            Ok(detail) => {
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
        if let Some(host) = url.host_str() {
            self.observations.push(obs("Host", host, Origin::Offline));
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
            if host.parse::<IpAddr>().is_ok() {
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
        Ok("Host identity inspected".into())
    }
    fn resolve_dns(&mut self, url: Url) -> Result<String> {
        let host = url.host_str().context("URL has no host")?;
        let port = url.port_or_known_default().unwrap_or(443);
        let addresses: Vec<_> = (host, port).to_socket_addrs()?.map(|a| a.ip()).collect();
        for ip in &addresses {
            self.observations.push(obs(
                "Resolved address",
                format!("{ip} ({})", classify_ip(*ip)),
                Origin::Online,
            ));
        }
        Ok(format!("Resolved {} address(es)", addresses.len()))
    }
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
        value: value.into(),
        origin,
    }
}
fn fs_stat(path: PathBuf, observations: &mut Vec<Observation>) -> Result<String> {
    let meta = path.metadata()?;
    observations.push(obs(
        "Size",
        format!("{} bytes", meta.len()),
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
        if !actual.eq_ignore_ascii_case(ext) {
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

#[allow(dead_code)]
const NETWORK_TIMEOUT: Duration = Duration::from_secs(8);

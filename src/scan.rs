use crate::{Confidence, Finding, JobPhase, Observation, Origin, Severity, analyzers::classify_ip};
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
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|_| anyhow!("target is neither a URL nor a readable regular file"))?;
            if !metadata.file_type().is_file() {
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
        let predefined_skip = matches!(id.as_str(), "network" | "tls" | "http")
            || (self.steps[index].online && matches!(&self.target, Target::File(_)));
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
            (Target::File(path), "file_safety") => {
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
            (Target::Url(url), "dns") => self.resolve_dns(url.clone()),
            (_, "network") => Ok("No sourced ASN / country prefix dataset available".into()),
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

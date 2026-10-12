use nulltrace::{
    Origin,
    scan::{ScanSession, StepStatus},
};
use std::{fs, net::IpAddr};

#[test]
fn url_plan_is_real_and_offline_scan_finishes_before_online() {
    let mut session =
        ScanSession::new("https://user@127.0.0.1:8443/login?next=https%3A%2F%2Fevil.test").unwrap();
    assert!(
        session
            .steps()
            .iter()
            .filter(|s| !s.online)
            .all(|s| s.status == StepStatus::Queued)
    );
    assert!(
        session
            .steps()
            .iter()
            .filter(|s| s.online)
            .all(|s| s.status == StepStatus::Locked)
    );
    while session.run_next_offline() {}
    assert!(session.offline_complete());
    assert!(
        session
            .findings()
            .iter()
            .all(|f| f.origin == Origin::Offline)
    );
    assert!(
        session
            .findings()
            .iter()
            .any(|f| f.rule_id == "URL-USERINFO")
    );
    assert!(
        session
            .findings()
            .iter()
            .any(|f| f.rule_id == "URL-IP-HOST")
    );
    assert!(
        session
            .steps()
            .iter()
            .filter(|s| s.online)
            .all(|s| s.status == StepStatus::Locked)
    );
}

#[test]
fn file_scan_hashes_content_and_detects_extension_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.jpg");
    fs::write(&path, b"MZfake executable").unwrap();
    let mut session = ScanSession::new(path.to_str().unwrap()).unwrap();
    while session.run_next_offline() {}
    assert!(
        session
            .observations()
            .iter()
            .any(|o| o.label == "SHA-256" && o.value.len() == 64)
    );
    assert!(
        session
            .findings()
            .iter()
            .any(|f| f.rule_id == "FILE-EXTENSION")
    );
}

#[test]
fn non_regular_paths_are_rejected_before_scanning() {
    let dir = tempfile::tempdir().unwrap();
    assert!(ScanSession::new(dir.path().to_str().unwrap()).is_err());
}

#[test]
fn ip_classification_distinguishes_scope() {
    assert_eq!(
        nulltrace::analyzers::classify_ip("127.0.0.1".parse::<IpAddr>().unwrap()),
        "loopback"
    );
    assert_eq!(
        nulltrace::analyzers::classify_ip("8.8.8.8".parse::<IpAddr>().unwrap()),
        "public"
    );
}

#[test]
fn bare_ipv4_and_ipv6_targets_are_accepted_and_classified() {
    for target in ["8.8.8.8", "2001:4860:4860::8888"] {
        let mut session = ScanSession::new(target).unwrap();
        while session.run_next_offline() {}
        assert!(
            session
                .observations()
                .iter()
                .any(|o| o.label == "Address scope")
        );
    }
}

#[test]
fn online_requires_authorization_token() {
    let mut session = ScanSession::new("https://example.com").unwrap();
    while session.run_next_offline() {}
    assert!(session.begin_online().is_err());
    session.request_online_consent().unwrap();
    let token = session.authorize_online().unwrap();
    session.begin_online_with(token).unwrap();
    assert!(
        session
            .steps()
            .iter()
            .filter(|s| s.online)
            .all(|s| s.status != StepStatus::Locked)
    );
}

#[test]
fn cancelling_consent_returns_to_completed_offline_report() {
    let mut session = ScanSession::new("https://example.com").unwrap();
    while session.run_next_offline() {}
    session.request_online_consent().unwrap();
    session.cancel_online_consent().unwrap();
    assert_eq!(session.phase(), nulltrace::JobPhase::OfflineComplete);
    session.request_online_consent().unwrap();
}

#[test]
fn known_government_domain_is_reported_as_attribution_not_risk() {
    let mut session = ScanSession::new("https://government.ru/news/").unwrap();
    while session.run_next_offline() {}
    assert!(
        session
            .observations()
            .iter()
            .any(|o| o.label == "Government reference")
    );
    assert!(!session.findings().iter().any(|f| f.rule_id == "GOV-DOMAIN"));
}

#[test]
fn a_check_is_visible_as_running_before_it_completes() {
    let mut session = ScanSession::new("https://example.com").unwrap();
    assert!(session.run_next_offline());
    assert_eq!(session.steps()[0].status, StepStatus::Running);
    assert!(session.run_next_offline());
    assert_eq!(session.steps()[0].status, StepStatus::Completed);
}

#[test]
fn unavailable_online_adapters_are_skipped_not_reported_successful() {
    let mut session = ScanSession::new("https://example.com").unwrap();
    while session.run_next_offline() {}
    session.request_online_consent().unwrap();
    let token = session.authorize_online().unwrap();
    session.begin_online_with(token).unwrap();
    while session.run_next_online() {}
    let tls = session
        .steps()
        .iter()
        .find(|step| step.id == "tls")
        .unwrap();
    let http = session
        .steps()
        .iter()
        .find(|step| step.id == "http")
        .unwrap();
    let network = session
        .steps()
        .iter()
        .find(|step| step.id == "network")
        .unwrap();
    assert_eq!(network.status, StepStatus::Skipped);
    assert_eq!(tls.status, StepStatus::Skipped);
    assert_eq!(http.status, StepStatus::Skipped);
}

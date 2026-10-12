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

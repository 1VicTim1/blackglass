use nulltrace::{
    JobPhase,
    email::{PolicyState, select_policy},
    scan::{ScanSession, StepStatus},
};

fn finish_offline(input: &str) -> ScanSession {
    let mut session = ScanSession::new(input).unwrap();
    while session.run_next_offline() {}
    session
}

#[test]
fn plain_email_address_has_an_offline_report_and_locked_dns_checks() {
    let session = finish_offline("122aaa121@gmail.com");

    for (label, value) in [
        ("Email address", "122aaa121@gmail.com"),
        ("Email local part", "122aaa121"),
        ("Email domain", "gmail.com"),
    ] {
        assert!(
            session
                .observations()
                .iter()
                .any(|item| item.label == label && item.value == value),
            "missing {label}={value}"
        );
    }
    assert_eq!(session.phase(), JobPhase::OfflineComplete);
    for id in ["email_mx", "email_spf", "email_dmarc"] {
        let step = session.steps().iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.status, StepStatus::Locked);
        assert!(step.online);
    }
}

#[test]
fn malformed_email_addresses_are_rejected_as_targets() {
    for address in [
        "a..b@example.com",
        ".user@example.com",
        "user@example",
        "user name@example.com",
        "user@@example.com",
    ] {
        assert!(ScanSession::new(address).is_err(), "accepted {address}");
    }
}

#[test]
fn an_existing_file_with_at_sign_is_still_a_file_target() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("message@sample.bin");
    std::fs::write(&path, b"sample").unwrap();
    let session = finish_offline(path.to_str().unwrap());
    assert!(session.steps().iter().any(|step| step.id == "hash"));
    assert!(!session.steps().iter().any(|step| step.id == "email_mx"));
}

#[test]
fn email_domain_uses_the_same_brand_impersonation_checks_as_urls() {
    let session = finish_offline("support@rnicrosoft.ru");
    assert!(
        session
            .findings()
            .iter()
            .any(|finding| finding.rule_id == "DOMAIN-BRAND-VISUAL")
    );
}

#[test]
fn email_network_checks_still_require_explicit_consent() {
    let mut session = finish_offline("122aaa121@gmail.com");
    assert!(session.begin_online().is_err());
    session.request_online_consent().unwrap();
    assert_eq!(session.phase(), JobPhase::OnlineConsent);
}

#[test]
fn spf_and_dmarc_policy_records_are_selected_without_fabricating_results() {
    let records = vec![
        "google-site-verification=abc".to_string(),
        "v=spf1 include:_spf.example.test -all".to_string(),
    ];
    assert_eq!(
        select_policy(&records, "v=spf1"),
        PolicyState::Present("v=spf1 include:_spf.example.test -all".into())
    );
    assert_eq!(select_policy(&records, "v=DMARC1"), PolicyState::Missing);

    let duplicate = vec!["v=spf1 -all".into(), "V=SPF1 ~all".into()];
    assert_eq!(
        select_policy(&duplicate, "v=spf1"),
        PolicyState::Multiple(2)
    );
}

#[test]
#[ignore = "requires network access to Cloudflare DNS-over-HTTPS"]
fn gmail_mail_dns_checks_execute_after_consent() {
    let mut session = finish_offline("122aaa121@gmail.com");
    session.request_online_consent().unwrap();
    let token = session.authorize_online().unwrap();
    session.begin_online_with(token).unwrap();
    while session.run_next_online() {}

    assert!(
        session
            .steps()
            .iter()
            .filter(|step| step.online)
            .all(|step| step.status == StepStatus::Completed),
        "mail DNS steps were not executed: {:?}",
        session
            .steps()
            .iter()
            .filter(|step| step.online)
            .map(|step| (&step.id, step.status, &step.detail))
            .collect::<Vec<_>>()
    );
    for label in ["Mail exchanger", "SPF policy", "DMARC policy"] {
        assert!(
            session
                .observations()
                .iter()
                .any(|item| item.label == label),
            "missing {label}; observations={:?}",
            session
                .observations()
                .iter()
                .map(|item| (&item.label, &item.value))
                .collect::<Vec<_>>()
        );
    }
}

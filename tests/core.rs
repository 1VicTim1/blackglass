use nulltrace::{
    CheckState, Confidence, Finding, JobPhase, Origin, Severity, progress::snapshot,
    risk::summarize,
};

fn finding(group: &str, severity: Severity, confidence: Confidence, weight: u8) -> Finding {
    Finding::new(
        "TEST",
        group,
        Origin::Offline,
        severity,
        confidence,
        "evidence",
        weight,
    )
}

#[test]
fn correlated_risk_is_capped() {
    let findings = vec![
        finding("domain", Severity::High, Confidence::High, 40),
        finding("domain", Severity::High, Confidence::High, 40),
    ];
    assert_eq!(summarize(&findings).score, 50);
}

#[test]
fn confidence_scales_risk() {
    let findings = vec![finding("identity", Severity::Medium, Confidence::Low, 40)];
    assert_eq!(summarize(&findings).score, 16);
}

#[test]
fn progress_handles_no_checks_and_terminal_states() {
    assert_eq!(snapshot(&[]).percent, 100);
    let checks = vec![
        CheckState::Completed,
        CheckState::Running,
        CheckState::Skipped("n/a".into()),
    ];
    let progress = snapshot(&checks);
    assert_eq!(
        (progress.settled, progress.total, progress.percent),
        (2, 3, 66)
    );
}

#[test]
fn phases_require_consent_before_online_execution() {
    assert!(JobPhase::OfflineComplete.can_transition_to(JobPhase::OnlineConsent));
    assert!(!JobPhase::OfflineComplete.can_transition_to(JobPhase::OnlineRunning));
    assert!(JobPhase::OnlineConsent.can_transition_to(JobPhase::OnlineRunning));
}

use nulltrace::{
    scan::ScanSession,
    tui::{TerminalCapabilities, marker_for, render_snapshot, render_snapshot_scrolled},
};

#[test]
fn marker_grammar_and_spinner_are_stable() {
    assert_eq!(marker_for("running", 0, false), "[|]");
    assert_eq!(marker_for("running", 1, false), "[/]");
    assert_eq!(marker_for("running", 2, false), "[-]");
    assert_eq!(marker_for("running", 3, false), "[\\]");
    assert_eq!(marker_for("running", 8, true), "[~]");
    assert_eq!(marker_for("completed", 0, false), "[+]");
}

#[test]
fn desktop_snapshot_contains_three_styles_and_locked_online_tree() {
    let session = ScanSession::new("https://example.com").unwrap();
    let snapshot = render_snapshot(&session, 120, 38, 1, TerminalCapabilities::enhanced());
    assert!(snapshot.contains("NULLTRACE"));
    assert!(snapshot.contains("FORENSIC OPERATIONS CONSOLE"));
    assert!(snapshot.contains("OFFLINE ANALYSIS"));
    assert!(snapshot.contains("ONLINE INTELLIGENCE [LOCKED]"));
    assert!(snapshot.contains("[*]"));
}

#[test]
fn termux_width_uses_compact_layout() {
    let session = ScanSession::new("https://example.com").unwrap();
    let snapshot = render_snapshot(&session, 70, 24, 0, TerminalCapabilities::basic());
    assert!(snapshot.contains("TASKS"));
    assert!(!snapshot.contains("FORENSIC OPERATIONS CONSOLE  //  EVIDENCE MATRIX"));
}

#[test]
fn desktop_evidence_renders_real_observations() {
    let mut session = ScanSession::new("https://government.ru/").unwrap();
    while session.run_next_offline() {}
    let snapshot = render_snapshot(&session, 120, 38, 0, TerminalCapabilities::enhanced());
    assert!(snapshot.contains("Government reference"));
    assert!(snapshot.contains("government.ru"));
}

#[test]
fn completed_tree_nodes_show_real_result_details() {
    let mut session = ScanSession::new("https://example.com/").unwrap();
    while session.run_next_offline() {}
    let snapshot = render_snapshot(&session, 80, 32, 0, TerminalCapabilities::basic());
    assert!(snapshot.contains("URL parsed"));
    assert!(snapshot.contains("Host identity inspected"));
}

#[test]
fn evidence_panel_can_scroll_through_dense_real_data() {
    let mut session = ScanSession::new("https://a.b.c.d.e.example.com:8443/a/b?x=1&y=2").unwrap();
    while session.run_next_offline() {}
    let top = render_snapshot_scrolled(&session, 80, 24, 0, TerminalCapabilities::basic(), 0);
    let lower = render_snapshot_scrolled(&session, 80, 24, 0, TerminalCapabilities::basic(), 6);
    assert_ne!(top, lower);
    assert!(lower.contains("Host labels") || lower.contains("Explicit port"));
}

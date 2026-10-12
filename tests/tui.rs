use nulltrace::{
    scan::ScanSession,
    tui::{TerminalCapabilities, marker_for, render_snapshot},
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

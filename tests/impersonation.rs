use nulltrace::{analyzers::classify_ip, risk, scan::ScanSession};
fn scan(url: &str) -> ScanSession {
    let mut s = ScanSession::new(url).unwrap();
    while s.run_next_offline() {}
    s
}
#[test]
fn brand_spoofs_have_evidence_and_nonzero_risk() {
    for url in [
        "https://rnicrosoft.ru",
        "https://micros0ft.com",
        "https://microsoft-login.example",
        "https://microsoft.com.evil.test",
        "https://gοοgle.com",
        "https://paypa1.com",
        "https://microsfot.com",
        "https://microsoftsecure.com",
    ] {
        let s = scan(url);
        assert!(
            s.findings()
                .iter()
                .any(|f| f.rule_id.starts_with("DOMAIN-BRAND") && !f.evidence.is_empty()),
            "missed {url}"
        );
        assert!(
            risk::summarize(s.findings()).score >= 25,
            "weak score {url}"
        );
    }
}
#[test]
fn official_hosts_and_unrelated_words_do_not_trigger_brand_rules() {
    for url in [
        "https://microsoft.com",
        "https://login.microsoft.com",
        "https://google.co.uk",
        "https://apple.com",
        "https://pineapple.example",
        "https://example.com",
        "https://notmicrosoft.com",
    ] {
        let s = scan(url);
        assert!(
            !s.findings()
                .iter()
                .any(|f| f.rule_id.starts_with("DOMAIN-BRAND")),
            "false positive {url}"
        );
    }
}
#[test]
fn special_ip_ranges_are_not_public() {
    for (ip, scope) in [
        ("100.64.0.1", "shared-CGNAT"),
        ("192.0.2.1", "documentation"),
        ("198.18.0.1", "benchmark"),
        ("240.1.1.1", "reserved"),
        ("255.255.255.255", "broadcast"),
        ("2001:db8::1", "documentation"),
        ("::ffff:127.0.0.1", "loopback"),
    ] {
        assert_eq!(classify_ip(ip.parse().unwrap()), scope, "{ip}");
    }
    let s = scan("https://[::ffff:127.0.0.1]/");
    assert!(s.findings().iter().any(|f| f.rule_id == "IP-NONPUBLIC"));
}
#[test]
fn local_files_do_not_have_network_plan_or_consent() {
    let f = tempfile::NamedTempFile::new().unwrap();
    let mut s = scan(f.path().to_str().unwrap());
    assert!(!s.steps().iter().any(|step| step.online));
    assert!(s.request_online_consent().is_err());
}
#[test]
fn deceptive_names_and_executables_are_inspected_without_execution() {
    for name in ["photo\u{202e}gnp.exe", "invoice.pdf.exe"] {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(name);
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&183u16.to_le_bytes());
        std::fs::write(&p, elf).unwrap();
        let s = scan(p.to_str().unwrap());
        assert!(s.findings().iter().any(|f| f.rule_id == "FILE-EXECUTABLE"));
        assert!(s.findings().iter().any(|f| f.rule_id
            == if name.contains('\u{202e}') {
                "FILE-BIDI"
            } else {
                "FILE-DOUBLE-EXTENSION"
            }));
        assert!(
            s.observations()
                .iter()
                .any(|o| o.label == "Executable architecture" && o.value == "AArch64")
        );
        assert!(
            !s.observations()
                .iter()
                .any(|o| o.value.contains('\u{202e}'))
        );
    }
}

#[test]
fn ip_obfuscation_and_confusable_extensions_are_reported() {
    for url in ["https://2130706433", "https://0x7f000001"] {
        let s = scan(url);
        assert!(
            s.findings()
                .iter()
                .any(|f| f.rule_id == "URL-IP-OBFUSCATED")
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("invoice.exе");
    std::fs::write(&p, b"MZmock").unwrap();
    let s = scan(p.to_str().unwrap());
    assert!(
        s.findings()
            .iter()
            .any(|f| f.rule_id == "FILE-EXTENSION-CONFUSABLE")
    );
}
#[test]
fn forged_pe_header_offsets_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("app.exe");
    let mut b = [0u8; 64];
    b[..2].copy_from_slice(b"MZ");
    b[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&p, b).unwrap();
    let s = scan(p.to_str().unwrap());
    assert!(
        s.observations()
            .iter()
            .any(|o| o.label == "Executable format" && o.value.starts_with("DOS"))
    );
    assert!(
        !s.observations()
            .iter()
            .any(|o| o.label == "Executable architecture")
    );
}

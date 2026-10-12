use nulltrace::tls::inspect_tls;

#[test]
#[ignore = "requires live TLS access"]
fn example_com_certificate_exposes_identity_and_validity() {
    let report = inspect_tls("example.com", 443).unwrap();
    assert!(!report.subject.is_empty());
    assert!(!report.issuer.is_empty());
    assert!(
        report
            .dns_names
            .iter()
            .any(|name| name == "example.com" || name == "*.example.com")
    );
    assert!(!report.not_before.is_empty());
    assert!(!report.not_after.is_empty());
    assert!(report.protocol.starts_with("TLS"));
}

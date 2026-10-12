use nulltrace::{
    JobPhase,
    scan::{ScanSession, StepStatus},
};
use std::io::Write;
use url::Url;

fn eml_file(contents: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().suffix(".eml").tempfile().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file
}

fn suspicious_message() -> tempfile::NamedTempFile {
    eml_file(concat!(
        "From: Microsoft Security <security@microsoft.com>\r\n",
        "Reply-To: recovery@rnicrosoft.example\r\n",
        "Return-Path: <bounce@mailer.invalid>\r\n",
        "To: victim@example.com\r\n",
        "Subject: Urgent account verification\r\n",
        "Date: Mon, 12 Oct 2026 09:00:00 +0500\r\n",
        "Message-ID: <campaign-42@mailer.invalid>\r\n",
        "Received: from relay.invalid (relay.invalid [203.0.113.7]) by mx.example\r\n",
        "Authentication-Results: mx.example; spf=fail smtp.mailfrom=mailer.invalid; dkim=fail header.d=microsoft.com; dmarc=fail header.from=microsoft.com\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=nt\r\n",
        "\r\n",
        "--nt\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "\r\n",
        "<p>Open <a href=https://rnicrosoft.example/login?a=1&amp;b=2><span>https://microsoft.com/login</span></a></p>\r\n",
        "--nt\r\n",
        "Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\n",
        "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "TVqQAAMAAAAEAAAA\r\n",
        "--nt--\r\n",
    ))
}

#[test]
fn eml_gets_a_dedicated_offline_analysis_tree() {
    let file = suspicious_message();
    let session = ScanSession::new(file.path().to_str().unwrap()).unwrap();
    for id in [
        "eml_headers",
        "eml_auth",
        "eml_bodies",
        "eml_links",
        "eml_attachments",
    ] {
        assert!(
            session.steps().iter().any(|step| step.id == id),
            "missing {id}"
        );
    }
}

#[test]
fn eml_exposes_headers_authentication_links_and_attachments() {
    let file = suspicious_message();
    let mut session = ScanSession::new(file.path().to_str().unwrap()).unwrap();
    while session.run_next_offline() {}

    for (label, fragment) in [
        ("Message From", "security@microsoft.com"),
        ("Message Reply-To", "rnicrosoft.example"),
        ("SPF result", "fail"),
        ("DKIM result", "fail"),
        ("DMARC result", "fail"),
        ("Authentication evidence", "untrusted"),
        ("Message URL", "https://rnicrosoft.example/login"),
        ("Attachment", "invoice.pdf.exe"),
        ("Attachment SHA-256", ""),
        ("Attachment detected MIME", "application/x-dosexec"),
    ] {
        assert!(
            session
                .observations()
                .iter()
                .any(|item| item.label == label && item.value.contains(fragment)),
            "missing {label} containing {fragment}"
        );
    }
    for rule in ["EML-REPLY-MISMATCH", "EML-AUTH-FAIL", "EML-LINK-MISMATCH"] {
        assert!(
            session
                .findings()
                .iter()
                .any(|finding| finding.rule_id == rule)
        );
    }
}

#[test]
fn eml_network_actions_remain_locked_until_explicit_consent() {
    let file = suspicious_message();
    let mut session = ScanSession::new(file.path().to_str().unwrap()).unwrap();
    while session.run_next_offline() {}
    assert_eq!(session.phase(), JobPhase::OfflineComplete);
    for id in ["eml_sender_dns", "eml_link_intel"] {
        let step = session.steps().iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.status, StepStatus::Locked);
    }
}

#[test]
fn extensionless_rfc_message_is_detected_from_its_headers() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(
        b"From: sender@example.com\r\nSubject: test\r\nMessage-ID: <1@example.com>\r\n\r\nbody",
    )
    .unwrap();
    let session = ScanSession::new(file.path().to_str().unwrap()).unwrap();
    assert!(session.steps().iter().any(|step| step.id == "eml_headers"));
}

#[test]
fn sender_domain_comes_from_a_parsed_mailbox_not_comments() {
    let file = eml_file(concat!(
        "From: \"Ops @ team\" <security@microsoft.com> (forwarded by comment@evil.test)\r\n",
        "Subject: test\r\n",
        "Message-ID: <1@example.com>\r\n\r\nbody",
    ));
    let report = nulltrace::eml::inspect(file.path()).unwrap();
    assert_eq!(report.sender_domain.as_deref(), Some("microsoft.com"));
}

#[test]
fn excessive_multipart_structure_is_rejected_before_recursive_parsing() {
    let mut message = String::from("From: sender@example.com\r\nSubject: nested\r\n");
    for index in 0..33 {
        message.push_str(&format!(
            "Content-Type:\r\n multipart/mixed; boundary=layer{index}\r\n\r\n--layer{index}\r\n"
        ));
    }
    message.push_str("Content-Type: text/plain\r\n\r\nbody\r\n");
    for index in (0..33).rev() {
        message.push_str(&format!("--layer{index}--\r\n"));
    }
    let file = eml_file(&message);
    let error = nulltrace::eml::inspect(file.path()).unwrap_err();
    assert!(error.to_string().contains("multipart nesting limit"));
}

#[test]
fn excessive_flat_mime_parts_are_rejected() {
    let mut message = String::from(concat!(
        "From: sender@example.com\r\nSubject: wide\r\n",
        "Content-Type: multipart/mixed; boundary=wide\r\n\r\n",
    ));
    for _ in 0..129 {
        message.push_str("--wide \t\r\nContent-Type: text/plain\r\n\r\npart\r\n");
    }
    message.push_str("--wide--\r\n");
    let file = eml_file(&message);
    let error = nulltrace::eml::inspect(file.path()).unwrap_err();
    assert!(error.to_string().contains("preflight part limit"));
}

#[test]
fn link_batch_continues_after_an_individual_trace_failure() {
    let urls = [
        Url::parse("https://broken.example/").unwrap(),
        Url::parse("https://working.example/").unwrap(),
    ];
    let results = nulltrace::eml::inspect_urls_independently(&urls, 5, |url| {
        if url.host_str() == Some("broken.example") {
            anyhow::bail!("connection refused")
        }
        Ok("inspected")
    });
    assert!(results[0].1.is_err());
    assert_eq!(results[1].1.as_ref().unwrap(), &"inspected");
}

#[test]
fn sibling_subdomains_share_the_same_registrable_sender_domain() {
    let file = eml_file(concat!(
        "From: alerts@news.example.co.uk\r\n",
        "Reply-To: replies@bounce.example.co.uk\r\n",
        "Subject: test\r\nMessage-ID: <1@example.co.uk>\r\n\r\nbody",
    ));
    let mut session = ScanSession::new(file.path().to_str().unwrap()).unwrap();
    while session.run_next_offline() {}
    assert!(
        !session
            .findings()
            .iter()
            .any(|finding| finding.rule_id == "EML-REPLY-MISMATCH")
    );
}

#[test]
fn authentication_parser_ignores_quoted_comments_and_accepts_spacing() {
    let file = eml_file(concat!(
        "From: sender@example.com\r\n",
        "Subject: test\r\n",
        "Authentication-Results: mx.example; reason=\"dkim=fail\"; spf = fail smtp.mailfrom=example.com; dkim=pass header.d=example.com\r\n",
        "Message-ID: <1@example.com>\r\n\r\nbody",
    ));
    let report = nulltrace::eml::inspect(file.path()).unwrap();
    assert!(
        report
            .authentication
            .observations
            .iter()
            .any(|(label, value)| { label == "SPF result" && value == "fail" })
    );
    assert!(
        report
            .authentication
            .observations
            .iter()
            .any(|(label, value)| { label == "DKIM result" && value == "pass" })
    );
}

#[test]
#[ignore = "requires live DNS-over-HTTPS and HTTP access"]
fn eml_online_enrichment_executes_after_consent() {
    let file = eml_file(concat!(
        "From: sender@example.com\r\n",
        "Subject: live adapter test\r\n",
        "Message-ID: <1@example.com>\r\n",
        "Content-Type: text/plain\r\n\r\n",
        "https://example.com/\r\n",
    ));
    let mut session = ScanSession::new(file.path().to_str().unwrap()).unwrap();
    while session.run_next_offline() {}
    session.request_online_consent().unwrap();
    let token = session.authorize_online().unwrap();
    session.begin_online_with(token).unwrap();
    while session.run_next_online() {}
    for id in ["eml_sender_dns", "eml_link_intel"] {
        let step = session.steps().iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.status, StepStatus::Completed, "{id}: {}", step.detail);
    }
}

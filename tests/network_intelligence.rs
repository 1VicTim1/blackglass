use nulltrace::{
    network::{
        lookup_hosting, lookup_hosting_catalog, lookup_local_mmdb, parse_geo_location,
        parse_ripe_network_info, parse_rir_country,
    },
    risk,
    scan::{ScanSession, StepStatus},
    web::redirect_findings,
};
use std::net::IpAddr;
use url::Url;

#[test]
fn embedded_hosting_cidrs_attribute_cloudflare_without_calling_it_malicious() {
    let hit = lookup_hosting("104.16.12.34".parse::<IpAddr>().unwrap()).unwrap();
    assert_eq!(hit.provider, "Cloudflare");
    assert_eq!(hit.cidr, "104.16.0.0/13");
    assert!(hit.source.starts_with("https://"));
}

#[test]
fn rir_geo_country_is_parsed_as_registration_data() {
    let json = br#"{"status":"ok","data":{"located_resources":[{"resource":"8.8.8.8/32","location":"US"}]}}"#;
    assert_eq!(parse_rir_country(json).unwrap().as_deref(), Some("US"));

    let unknown = br#"{"status":"ok","data":{"located_resources":[{"location":"?"}]}}"#;
    assert_eq!(parse_rir_country(unknown).unwrap(), None);
}

#[test]
fn unknown_geo_values_are_not_presented_as_a_country_or_city() {
    let unknown = br#"{"data":{"located_resources":[{"locations":[{"country":"?","city":""}]}]}}"#;
    assert_eq!(parse_geo_location(unknown).unwrap(), (None, None));
    let known =
        br#"{"data":{"located_resources":[{"locations":[{"country":"US","city":"Ashburn"}]}]}}"#;
    assert_eq!(
        parse_geo_location(known).unwrap(),
        (Some("US".into()), Some("Ashburn".into()))
    );
}

#[test]
fn absent_user_mmdb_files_are_reported_as_unavailable_instead_of_fabricated() {
    let report = lookup_local_mmdb("8.8.8.8".parse().unwrap(), &[]).unwrap();
    assert!(report.asn.is_none());
    assert!(report.country.is_none());
    assert!(report.sources.is_empty());
}

#[test]
fn user_cidr_catalog_uses_the_same_parser_as_the_embedded_snapshot() {
    let catalog = "provider,cidr,source\nLab cloud,203.0.113.0/24,local:test\n";
    let hit = lookup_hosting_catalog(catalog, "203.0.113.8".parse().unwrap()).unwrap();
    assert_eq!(hit.provider, "Lab cloud");
    assert_eq!(hit.cidr, "203.0.113.0/24");
    assert_eq!(hit.source, "local:test");
}

#[test]
fn ripe_network_json_exposes_prefix_asn_holder_and_registration_country() {
    let json = br#"{"status":"ok","data":{"asns":[15169],"prefix":"8.8.8.0/24","holder":"GOOGLE - Google LLC","resource":"8.8.8.8"}}"#;
    let info = parse_ripe_network_info(json, "8.8.8.8".parse().unwrap()).unwrap();
    assert_eq!(info.prefix.as_deref(), Some("8.8.8.0/24"));
    assert_eq!(info.asns, vec![15169]);
    assert_eq!(info.holder.as_deref(), Some("GOOGLE - Google LLC"));
}

#[test]
fn redirect_rules_flag_https_downgrade_and_foreign_hostname() {
    let from = Url::parse("https://accounts.microsoft.com/login").unwrap();
    let to = Url::parse("http://collect.example.test/session").unwrap();
    let findings = redirect_findings(&from, &to);
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "HTTP-DOWNGRADE")
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "HTTP-CROSS-HOST")
    );
    assert!(risk::summarize(&findings).score > 0);
}

#[test]
fn orb_ru_is_in_the_embedded_government_catalog() {
    let mut session = ScanSession::new("https://orb.ru").unwrap();
    while session.run_next_offline() {}
    assert!(session.observations().iter().any(|observation| {
        observation.label == "Government reference" && observation.value.contains("orb.ru")
    }));
}

#[test]
#[ignore = "requires live DNS, HTTPS, TLS and RIPE Stat"]
fn url_online_adapters_execute_real_checks() {
    let mut session = ScanSession::new("https://example.com").unwrap();
    while session.run_next_offline() {}
    session.request_online_consent().unwrap();
    let token = session.authorize_online().unwrap();
    session.begin_online_with(token).unwrap();
    while session.run_next_online() {}

    for id in ["dns", "network", "tls", "http"] {
        let step = session.steps().iter().find(|step| step.id == id).unwrap();
        assert_eq!(
            step.status,
            StepStatus::Completed,
            "{id} failed or skipped: {}",
            step.detail
        );
    }
    for label in ["Network prefix", "TLS issuer", "HTTP final URL"] {
        assert!(
            session
                .observations()
                .iter()
                .any(|observation| observation.label == label),
            "missing {label}"
        );
    }
}

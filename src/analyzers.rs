use crate::{Confidence, Finding, Origin, Severity};
use std::net::IpAddr;
pub fn classify_ip(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, d] = v.octets();
            if v.is_unspecified() {
                "unspecified"
            } else if v.is_loopback() {
                "loopback"
            } else if v.is_private() {
                "private"
            } else if v.is_link_local() {
                "link-local"
            } else if v.is_broadcast() {
                "broadcast"
            } else if v.is_multicast() {
                "multicast"
            } else if a == 100 && (64..=127).contains(&b) {
                "shared-CGNAT"
            } else if (a, b, c) == (192, 0, 2)
                || (a, b, c) == (198, 51, 100)
                || (a, b, c) == (203, 0, 113)
            {
                "documentation"
            } else if a == 198 && (b == 18 || b == 19) {
                "benchmark"
            } else if a == 0
                || a >= 240
                || ((a, b, c) == (192, 0, 0) && !matches!(d, 9 | 10))
                || (a, b, c) == (192, 88, 99)
            {
                "reserved"
            } else {
                "public"
            }
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return classify_ip(IpAddr::V4(v4));
            }
            let seg = v.segments();
            if v.is_loopback() {
                "loopback"
            } else if v.is_unique_local() {
                "private"
            } else if v.is_unicast_link_local() {
                "link-local"
            } else if v.is_multicast() {
                "multicast"
            } else if v.is_unspecified() {
                "unspecified"
            } else if seg[0] == 0x2001 && seg[1] == 0x0db8
                || (seg[0] == 0x3fff && seg[1] & 0xf000 == 0)
            {
                "documentation"
            } else if seg[0] == 0x2001 && seg[1] == 2 && seg[2] == 0 {
                "benchmark"
            } else if seg[0] == 0x2001 && (seg[1] & 0xfff0 == 0x10 || seg[1] & 0xfff0 == 0x20) {
                "reserved-ORCHID"
            } else if seg[0] & 0xe000 != 0x2000 && !(seg[0] == 0x64 && seg[1] == 0xff9b) {
                "reserved"
            } else {
                "public"
            }
        }
    }
}
pub fn ip_findings(ip: IpAddr, origin: Origin) -> Vec<Finding> {
    let scope = classify_ip(ip);
    if scope == "public" {
        return vec![];
    }
    vec![Finding::new("IP-NONPUBLIC", "address-scope", origin, Severity::Medium, Confidence::High,
        "Address is not an ordinary public Internet destination", 25)
        .with_evidence(format!("{ip}: {scope}; may be intentional for a local service; does not establish maliciousness"))]
}

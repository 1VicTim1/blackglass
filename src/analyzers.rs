use std::net::IpAddr;

pub fn classify_ip(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v) if v.is_loopback() => "loopback",
        IpAddr::V4(v) if v.is_private() => "private",
        IpAddr::V4(v) if v.is_link_local() => "link-local",
        IpAddr::V4(v) if v.is_multicast() => "multicast",
        IpAddr::V4(v) if v.is_unspecified() => "unspecified",
        IpAddr::V6(v) if v.is_loopback() => "loopback",
        IpAddr::V6(v) if v.is_unique_local() => "private",
        IpAddr::V6(v) if v.is_unicast_link_local() => "link-local",
        IpAddr::V6(v) if v.is_multicast() => "multicast",
        IpAddr::V6(v) if v.is_unspecified() => "unspecified",
        _ => "public",
    }
}

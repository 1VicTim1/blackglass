use anyhow::{Result, anyhow};
use ipnet::IpNet;
use reqwest::blocking::Client;
use serde::{Deserialize, Deserializer};
use std::{
    env,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkMatch {
    pub provider: String,
    pub cidr: String,
    pub source: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpIntelligence {
    pub address: IpAddr,
    pub prefix: Option<String>,
    pub asns: Vec<u32>,
    pub holder: Option<String>,
    pub country: Option<String>,
    pub country_basis: Option<String>,
    pub city: Option<String>,
    pub source: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalMmdbReport {
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub sources: Vec<String>,
}

pub fn discover_mmdb_files() -> Vec<PathBuf> {
    let mut directories = Vec::new();
    if let Ok(directory) = env::var("NULLTRACE_DATA_DIR") {
        directories.push(PathBuf::from(directory));
    }
    if let Ok(executable) = env::current_exe()
        && let Some(parent) = executable.parent()
    {
        directories.push(parent.join("data"));
    }
    directories.push(PathBuf::from("data"));
    const NAMES: &[&str] = &[
        "GeoLite2-ASN.mmdb",
        "GeoLite2-City.mmdb",
        "GeoIP2-ASN.mmdb",
        "GeoIP2-City.mmdb",
        "DBIP-ASN-LITE.mmdb",
        "DBIP-CITY-LITE.mmdb",
    ];
    let mut paths = Vec::new();
    for directory in directories {
        for name in NAMES {
            let path = directory.join(name);
            if path.is_file() && !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    paths
}

pub fn lookup_local_mmdb(address: IpAddr, paths: &[PathBuf]) -> Result<LocalMmdbReport> {
    let mut report = LocalMmdbReport::default();
    for path in paths {
        let reader = maxminddb::Reader::open_readfile(path)?;
        let database_type = reader.metadata.database_type.to_ascii_lowercase();
        if database_type.contains("asn") {
            if let Some(record) = reader.lookup::<maxminddb::geoip2::Asn<'_>>(address)? {
                report.asn = record.autonomous_system_number.or(report.asn);
                report.organization = record
                    .autonomous_system_organization
                    .map(str::to_string)
                    .or(report.organization);
            }
        } else if (database_type.contains("city") || database_type.contains("country"))
            && let Some(record) = reader.lookup::<maxminddb::geoip2::City<'_>>(address)?
        {
            report.country = record
                .country
                .and_then(|country| country.iso_code)
                .map(str::to_string)
                .or(report.country);
            report.city = record
                .city
                .and_then(|city| city.names)
                .and_then(|names| names.get("en").copied())
                .map(str::to_string)
                .or(report.city);
        }
        report.sources.push(display_path(path));
    }
    Ok(report)
}

fn display_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("MMDB database")
        .to_string()
}

pub fn lookup_hosting(address: IpAddr) -> Option<NetworkMatch> {
    crate::data::external_data("hosting_prefixes.csv")
        .and_then(|catalog| lookup_hosting_catalog(&catalog, address))
        .or_else(|| lookup_hosting_catalog(include_str!("../data/hosting_prefixes.csv"), address))
}

pub fn lookup_hosting_catalog(catalog: &str, address: IpAddr) -> Option<NetworkMatch> {
    catalog
        .lines()
        .filter(|line| !line.starts_with('#'))
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.splitn(3, ',');
            let provider = fields.next()?;
            let cidr = fields.next()?;
            let source = fields.next()?;
            let network = IpNet::from_str(cidr).ok()?;
            network.contains(&address).then(|| NetworkMatch {
                provider: provider.into(),
                cidr: cidr.into(),
                source: source.into(),
            })
        })
        .next()
}

#[derive(Deserialize)]
struct RipeEnvelope {
    status: String,
    data: RipeNetworkData,
}

#[derive(Deserialize)]
struct RipeNetworkData {
    #[serde(default, deserialize_with = "deserialize_asns")]
    asns: Vec<u32>,
    prefix: Option<String>,
    holder: Option<String>,
}

fn deserialize_asns<'de, D>(deserializer: D) -> Result<Vec<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Asn {
        Number(u32),
        Text(String),
    }
    let values = Vec::<Asn>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| match value {
            Asn::Number(number) => Ok(number),
            Asn::Text(text) => text.parse().map_err(serde::de::Error::custom),
        })
        .collect()
}

pub fn parse_ripe_network_info(bytes: &[u8], address: IpAddr) -> Result<IpIntelligence> {
    let response: RipeEnvelope = serde_json::from_slice(bytes)?;
    if response.status != "ok" {
        return Err(anyhow!("RIPE Stat returned status {}", response.status));
    }
    Ok(IpIntelligence {
        address,
        prefix: response.data.prefix,
        asns: response.data.asns,
        holder: response.data.holder,
        country: None,
        country_basis: None,
        city: None,
        source: "https://stat.ripe.net/docs/data_api#network-info".into(),
    })
}

pub fn parse_geo_location(bytes: &[u8]) -> Result<(Option<String>, Option<String>)> {
    let geo: serde_json::Value = serde_json::from_slice(bytes)?;
    let location = geo
        .pointer("/data/located_resources/0/locations/0")
        .and_then(serde_json::Value::as_object);
    let meaningful = |field: &str| {
        location
            .and_then(|entry| entry.get(field))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty() && *value != "?")
            .map(str::to_string)
    };
    Ok((meaningful("country"), meaningful("city")))
}

pub fn parse_rir_country(bytes: &[u8]) -> Result<Option<String>> {
    let response: serde_json::Value = serde_json::from_slice(bytes)?;
    if response.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        return Err(anyhow!("RIPE Stat RIR Geo returned a non-ok status"));
    }
    Ok(response
        .pointer("/data/located_resources/0/location")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "?")
        .map(str::to_string))
}

pub fn enrich_ip(address: IpAddr) -> Result<IpIntelligence> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("nulltrace/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let network = client
        .get("https://stat.ripe.net/data/network-info/data.json")
        .query(&[("resource", address.to_string())])
        .send()?
        .error_for_status()?
        .bytes()?;
    let mut result = parse_ripe_network_info(&network, address)?;

    let geo = client
        .get("https://stat.ripe.net/data/maxmind-geo-lite/data.json")
        .query(&[("resource", address.to_string())])
        .send()?
        .error_for_status()
        .and_then(|response| response.bytes());
    if let Ok(geo) = geo {
        if let Ok((country, city)) = parse_geo_location(&geo) {
            result.country = country;
            result.city = city;
            if result.country.is_some() {
                result.country_basis = Some("MaxMind GeoLite approximate location".into());
            }
            result.source = "RIPE Stat network-info + MaxMind GeoLite mirror".into();
        } else {
            result.source = "RIPE Stat network-info; GeoLite response could not be parsed".into();
        }
    } else {
        result.source = "RIPE Stat network-info; GeoLite lookup unavailable".into();
    }
    if result.country.is_none() {
        let rir_geo = client
            .get("https://stat.ripe.net/data/rir-geo/data.json")
            .query(&[("resource", address.to_string())])
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(|response| response.bytes());
        if let Ok(rir_geo) = rir_geo
            && let Ok(Some(country)) = parse_rir_country(&rir_geo)
        {
            result.country = Some(country);
            result.country_basis = Some("RIR registration country (not physical GeoIP)".into());
            result.source.push_str(" + RIPE Stat RIR Geo");
        }
    }
    Ok(result)
}

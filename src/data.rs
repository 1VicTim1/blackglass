use std::{env, fs, path::PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernmentDomain {
    pub domain: String,
    pub authority: String,
    pub source: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernmentZone {
    pub suffix: String,
    pub authority: String,
    pub source: String,
}

pub fn lookup_government_host(host: &str) -> Option<GovernmentDomain> {
    let text = external_data("gov_domains.csv")
        .unwrap_or_else(|| include_str!("../data/gov_domains.csv").to_string());
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split(',');
            let domain = fields.next()?;
            let subdomains = fields.next()? == "true";
            let authority = fields.next()?;
            let source = fields.next()?;
            let host = host.to_ascii_lowercase();
            let matches = host == domain || (subdomains && host.ends_with(&format!(".{domain}")));
            matches.then(|| GovernmentDomain {
                domain: domain.into(),
                authority: authority.into(),
                source: source.into(),
            })
        })
        .next()
}

pub fn lookup_government_zone(host: &str) -> Option<GovernmentZone> {
    let text = external_data("gov_zones.csv")
        .unwrap_or_else(|| include_str!("../data/gov_zones.csv").to_string());
    let host = host.to_ascii_lowercase();
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split(',');
            let suffix = fields.next()?;
            let authority = fields.next()?;
            let source = fields.next()?;
            let matched = host == suffix || host.ends_with(&format!(".{suffix}"));
            matched.then(|| GovernmentZone {
                suffix: suffix.into(),
                authority: authority.into(),
                source: source.into(),
            })
        })
        .next()
}

pub(crate) fn external_data(name: &str) -> Option<String> {
    let executable = env::current_exe().ok()?;
    let candidates = [
        executable.parent()?.join("data").join(name),
        PathBuf::from("data").join(name),
    ];
    candidates
        .into_iter()
        .find_map(|path| fs::read_to_string(path).ok())
}

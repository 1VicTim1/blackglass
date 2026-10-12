//! Conservative offline brand impersonation signals; a match is not a verdict.
use crate::{Confidence, Finding, Origin, Severity};

pub fn inspect_domain(host: &str) -> (Vec<Finding>, Vec<(String, String)>) {
    let host = host.trim_end_matches('.').to_lowercase();
    let (unicode, _) = idna::domain_to_unicode(&host);
    let labels: Vec<_> = unicode.split('.').collect();
    let mut findings = Vec::new();
    let mut observations = vec![("Unicode host".into(), unicode.clone())];
    for line in include_str!("../data/brands.csv").lines().skip(1) {
        let mut fields = line.split(',');
        let (Some(brand), Some(domains), Some(source)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if domains
            .split('|')
            .any(|d| host == d || host.ends_with(&format!(".{d}")))
        {
            observations.push((
                "Brand reference".into(),
                format!(
                    "{brand}: domain suffix matches catalog ({source}); ownership not verified"
                ),
            ));
            continue;
        }
        let mut signal = None;
        for label in &labels {
            if brand.len() < 4 {
                continue;
            }
            let skeleton = visual_skeleton(label);
            if skeleton == brand && *label != brand {
                signal = Some((
                    "DOMAIN-BRAND-VISUAL",
                    Confidence::High,
                    50,
                    format!("visual skeleton '{skeleton}' from '{label}'"),
                ));
                break;
            }
            if *label == brand || label.split('-').any(|part| part == brand) {
                signal = Some((
                    "DOMAIN-BRAND-PLACEMENT",
                    Confidence::Medium,
                    45,
                    format!("brand token '{brand}' in foreign hostname"),
                ));
                break;
            }
            if brand.len() >= 5
                && label.strip_prefix(brand).is_some_and(|suffix| {
                    matches!(
                        suffix,
                        "login"
                            | "secure"
                            | "support"
                            | "account"
                            | "verify"
                            | "update"
                            | "signin"
                            | "security"
                    )
                })
            {
                signal = Some((
                    "DOMAIN-BRAND-PLACEMENT",
                    Confidence::Medium,
                    45,
                    format!(
                        "brand '{brand}' combined with a login/security token on a foreign host"
                    ),
                ));
                break;
            }
            if brand.len() >= 5 && label.is_ascii() && edit_distance(label, brand) == 1 {
                signal = Some((
                    "DOMAIN-BRAND-TYPO",
                    Confidence::Medium,
                    45,
                    format!("'{label}' differs from '{brand}' by one edit"),
                ));
                break;
            }
        }
        if let Some((rule, confidence, weight, reason)) = signal {
            findings.push(Finding::new(rule, "brand-identity", Origin::Offline, Severity::High, confidence, "Possible impersonation of a known brand", weight)
                .with_evidence(format!("{reason}; host={host}; expected catalog domains={domains}; source={source}; heuristic, not proof")));
        }
    }
    let latin = unicode.chars().any(|c| c.is_ascii_alphabetic());
    let cyrillic = unicode
        .chars()
        .any(|c| ('\u{0400}'..='\u{052f}').contains(&c));
    let greek = unicode
        .chars()
        .any(|c| ('\u{0370}'..='\u{03ff}').contains(&c));
    if latin && (cyrillic || greek) {
        findings.push(
            Finding::new(
                "DOMAIN-MIXED-SCRIPT",
                "brand-identity",
                Origin::Offline,
                Severity::Medium,
                Confidence::Medium,
                "Hostname mixes Latin and visually similar scripts",
                20,
            )
            .with_evidence(unicode),
        );
    }
    (findings, observations)
}

fn visual_skeleton(label: &str) -> String {
    label
        .chars()
        .map(|c| match c {
            '0' | 'ο' | 'о' => 'o',
            '1' | 'і' | 'ӏ' => 'l',
            'а' | 'α' => 'a',
            'е' | 'ε' => 'e',
            'с' => 'c',
            'р' | 'ρ' => 'p',
            'х' | 'χ' => 'x',
            'у' => 'y',
            'ѕ' => 's',
            'м' | 'μ' => 'm',
            'т' => 't',
            _ => c,
        })
        .collect::<String>()
        .replace("rn", "m")
        .replace("vv", "w")
}

// Optimal string alignment distance includes adjacent transpositions.
fn edit_distance(a: &str, b: &str) -> usize {
    if a.len().abs_diff(b.len()) > 1 || a.len() > 64 {
        return 2;
    }
    let a: Vec<_> = a.chars().collect();
    let b: Vec<_> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, value) in d[0].iter_mut().enumerate() {
        *value = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + usize::from(a[i - 1] != b[j - 1]));
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

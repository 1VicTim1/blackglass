use crate::Finding;
use std::collections::HashMap;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RiskSummary {
    pub score: u8,
    pub contributions: Vec<(String, u8)>,
}

pub fn summarize(findings: &[Finding]) -> RiskSummary {
    let mut groups: HashMap<&str, u8> = HashMap::new();
    for finding in findings {
        let contribution = (f32::from(finding.weight) * finding.confidence.scale()).round() as u8;
        let current = groups.entry(&finding.group).or_default();
        *current = current.saturating_add(contribution).min(50);
    }
    let mut contributions: Vec<_> = groups
        .into_iter()
        .map(|(g, v)| (g.to_string(), v))
        .collect();
    contributions.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let score = contributions
        .iter()
        .map(|(_, v)| u16::from(*v))
        .sum::<u16>()
        .min(100) as u8;
    RiskSummary {
        score,
        contributions,
    }
}

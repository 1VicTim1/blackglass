use crate::CheckState;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProgressSnapshot {
    pub settled: usize,
    pub total: usize,
    pub percent: u16,
}

pub fn snapshot(checks: &[CheckState]) -> ProgressSnapshot {
    let total = checks.len();
    let settled = checks.iter().filter(|c| c.is_terminal()).count();
    let percent = (settled * 100)
        .checked_div(total)
        .map_or(100, |value| value as u16);
    ProgressSnapshot {
        settled,
        total,
        percent,
    }
}

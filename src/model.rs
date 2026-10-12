use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Origin {
    Offline,
    Online,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub(crate) fn scale(self) -> f32 {
        match self {
            Self::Low => 0.4,
            Self::Medium => 0.7,
            Self::High => 1.0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub group: String,
    pub origin: Origin,
    pub severity: Severity,
    pub confidence: Confidence,
    pub summary: String,
    pub evidence: Vec<String>,
    pub weight: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub label: String,
    pub value: String,
    pub origin: Origin,
}

impl Finding {
    pub fn new(
        rule_id: &str,
        group: &str,
        origin: Origin,
        severity: Severity,
        confidence: Confidence,
        summary: &str,
        weight: u8,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            group: group.into(),
            origin,
            severity,
            confidence,
            summary: summary.into(),
            evidence: Vec::new(),
            weight,
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CheckState {
    Queued,
    Running,
    Completed,
    Skipped(String),
    Failed(String),
    Cancelled,
}

impl CheckState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Skipped(_) | Self::Failed(_) | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum JobPhase {
    Queued,
    OfflineRunning,
    OfflineComplete,
    OnlineConsent,
    OnlineRunning,
    Complete,
    Cancelled,
    Failed,
}

impl JobPhase {
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Queued, Self::OfflineRunning)
                | (
                    Self::OfflineRunning,
                    Self::OfflineComplete | Self::Cancelled | Self::Failed
                )
                | (Self::OfflineComplete, Self::OnlineConsent | Self::Complete)
                | (
                    Self::OnlineConsent,
                    Self::OnlineRunning | Self::OfflineComplete
                )
                | (
                    Self::OnlineRunning,
                    Self::Complete | Self::Cancelled | Self::Failed
                )
        )
    }
}

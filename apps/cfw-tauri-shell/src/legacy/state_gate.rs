use std::fmt;
use std::sync::{Arc, Mutex};

use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum LegacyRetirementStatus {
    #[default]
    AwaitingConfirmation,
    Cleaning,
    Cleared,
    PostCutoverCleanupRequired {
        message: String,
    },
    RecoveryStartRequired {
        target: cfw_engine_api::EngineMode,
        message: String,
    },
    ManualCleanupRequired {
        action: LegacyCleanupAction,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LegacyCleanupAction {
    Retry,
    ReviewDns,
}

#[derive(Debug)]
pub(super) enum LegacyCleanupError {
    Retry(String),
    ReviewDns(String),
}

impl LegacyCleanupError {
    pub(super) fn action(&self) -> LegacyCleanupAction {
        match self {
            Self::Retry(_) => LegacyCleanupAction::Retry,
            Self::ReviewDns(_) => LegacyCleanupAction::ReviewDns,
        }
    }
}

impl fmt::Display for LegacyCleanupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retry(message) | Self::ReviewDns(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for LegacyCleanupError {}

impl From<String> for LegacyCleanupError {
    fn from(message: String) -> Self {
        Self::Retry(message)
    }
}

impl From<&str> for LegacyCleanupError {
    fn from(message: &str) -> Self {
        Self::Retry(message.into())
    }
}

#[derive(Debug, Default)]
struct LegacyRetirementGateState {
    status: LegacyRetirementStatus,
    active_attempt: Option<u64>,
    next_attempt: u64,
}

#[derive(Clone, Debug, Default)]
pub struct LegacyRetirementGate {
    state: Arc<Mutex<LegacyRetirementGateState>>,
}

#[derive(Debug)]
pub(super) struct LegacyRetirementAttempt {
    gate: LegacyRetirementGate,
    token: u64,
    finished: bool,
}

impl LegacyRetirementGate {
    pub(crate) fn status(&self) -> Result<LegacyRetirementStatus, String> {
        self.state
            .lock()
            .map(|state| state.status.clone())
            .map_err(|error| format!("legacy retirement gate lock failed: {error}"))
    }

    pub(crate) fn require_cleared(&self) -> Result<(), String> {
        match self.status()? {
            LegacyRetirementStatus::Cleared
            | LegacyRetirementStatus::PostCutoverCleanupRequired { .. } => Ok(()),
            LegacyRetirementStatus::AwaitingConfirmation => Err(
                "legacy network remains active until the user explicitly confirms the one-way cutover; new network modes remain blocked"
                    .into(),
            ),
            LegacyRetirementStatus::Cleaning => Err(
                "the explicitly confirmed legacy network cutover is still running; new network modes remain blocked"
                    .into(),
            ),
            LegacyRetirementStatus::RecoveryStartRequired { message, .. } => Err(format!(
                "an interrupted one-way cutover requires replacement recovery: {message}"
            )),
            LegacyRetirementStatus::ManualCleanupRequired { message, .. } => Err(format!(
                "legacy network cleanup requires manual intervention: {message}"
            )),
        }
    }

    pub(super) fn apply_launch_preflight(
        &self,
        status: LegacyRetirementStatus,
    ) -> Result<(), String> {
        if matches!(status, LegacyRetirementStatus::Cleaning) {
            return Err("launch preflight cannot synthesize an active cleanup state".into());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|error| format!("legacy retirement gate lock failed: {error}"))?;
        if state.active_attempt.is_some() {
            return Err("launch preflight cannot replace an active cleanup attempt".into());
        }
        state.status = status;
        Ok(())
    }

    pub(super) fn begin_attempt(&self) -> Result<Option<LegacyRetirementAttempt>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| format!("legacy retirement gate lock failed: {error}"))?;
        if matches!(state.status, LegacyRetirementStatus::Cleared) {
            return Ok(None);
        }
        if state.active_attempt.is_some() {
            return Err("legacy network cleanup is already running".into());
        }
        let token = state
            .next_attempt
            .checked_add(1)
            .ok_or_else(|| "legacy retirement attempt counter overflowed".to_owned())?;
        state.next_attempt = token;
        state.active_attempt = Some(token);
        state.status = LegacyRetirementStatus::Cleaning;
        Ok(Some(LegacyRetirementAttempt {
            gate: self.clone(),
            token,
            finished: false,
        }))
    }

    fn finish_attempt(&self, token: u64, status: LegacyRetirementStatus) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| format!("legacy retirement gate lock failed: {error}"))?;
        if state.active_attempt != Some(token) {
            return Err("legacy retirement attempt is no longer authoritative".into());
        }
        state.status = status;
        state.active_attempt = None;
        Ok(())
    }
}

impl LegacyRetirementAttempt {
    pub(super) fn mark_cleared(&mut self) -> Result<(), String> {
        self.gate
            .finish_attempt(self.token, LegacyRetirementStatus::Cleared)?;
        self.finished = true;
        Ok(())
    }

    pub(super) fn mark_failed(
        &mut self,
        action: LegacyCleanupAction,
        message: impl Into<String>,
    ) -> Result<(), String> {
        self.gate.finish_attempt(
            self.token,
            LegacyRetirementStatus::ManualCleanupRequired {
                action,
                message: message.into(),
            },
        )?;
        self.finished = true;
        Ok(())
    }

    pub(super) fn mark_post_cutover_cleanup_required(
        &mut self,
        message: impl Into<String>,
    ) -> Result<(), String> {
        self.gate.finish_attempt(
            self.token,
            LegacyRetirementStatus::PostCutoverCleanupRequired {
                message: message.into(),
            },
        )?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for LegacyRetirementAttempt {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.gate.finish_attempt(
            self.token,
            LegacyRetirementStatus::ManualCleanupRequired {
                action: LegacyCleanupAction::Retry,
                message: "legacy network cleanup was interrupted before completion".into(),
            },
        );
    }
}

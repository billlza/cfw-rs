//! Native observations, coordinator states, snapshots and the events that publish them.

use serde::{Deserialize, Serialize};

use crate::{EngineMode, RuntimeIdentity};

/// Complete native observation used to reconcile coordinator ownership after
/// the host process restarts. Each running variant identifies the native
/// endpoint that supplied the attestation; the embedded owner must agree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NativeEngineStatus {
    /// The authenticated native authority and independent OS observations agree
    /// that every app-owned runtime has stopped and its ownership is released.
    /// Missing services, failed queries and a single owner's local Off snapshot
    /// must be returned as errors, never converted into this global observation.
    #[default]
    Off,
    LocalProxy {
        runtime: RuntimeIdentity,
    },
    SystemProxy {
        runtime: RuntimeIdentity,
    },
    Tunnel {
        runtime: RuntimeIdentity,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EngineState {
    Off,
    LocalProxyStarting {
        generation: u64,
    },
    ProxyStarting {
        generation: u64,
    },
    ProxyActive {
        runtime: RuntimeIdentity,
    },
    LocalProxyActive {
        runtime: RuntimeIdentity,
    },
    LocalProxyStopping {
        generation: u64,
    },
    ProxyStopping {
        generation: u64,
    },
    TunnelInstalling {
        generation: u64,
    },
    AwaitingApproval {
        generation: u64,
    },
    TunnelStarting {
        generation: u64,
    },
    TunnelActive {
        runtime: RuntimeIdentity,
    },
    TunnelSystemProxyActive {
        runtime: RuntimeIdentity,
    },
    TunnelStopping {
        generation: u64,
    },
    Failed {
        generation: u64,
        target: EngineMode,
        error: String,
        /// The runtime attested before this failure is still leased and the
        /// coordinator keeps observing it: the state returns to active on the
        /// next exact attestation, without any start or stop.
        #[serde(default)]
        recheck_pending: bool,
    },
}

impl EngineState {
    pub fn active_mode(&self) -> EngineMode {
        match self {
            Self::LocalProxyActive { .. } => EngineMode::LocalProxy,
            Self::ProxyActive { .. } => EngineMode::SystemProxy,
            Self::TunnelActive { .. } => EngineMode::Tunnel,
            Self::TunnelSystemProxyActive { .. } => EngineMode::TunnelSystemProxy,
            _ => EngineMode::Off,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineSnapshot {
    pub desired_mode: EngineMode,
    pub state: EngineState,
    pub generation: u64,
    pub config_digest: Option<String>,
}

impl Default for EngineSnapshot {
    fn default() -> Self {
        Self {
            desired_mode: EngineMode::Off,
            state: EngineState::Off,
            generation: 0,
            config_digest: None,
        }
    }
}

/// Typed application event surface for engine state and fail-closed boundary
/// failures. Consumers must still validate a reported active snapshot against
/// its runtime identity, generation, digest, and readiness fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EngineEvent {
    SnapshotChanged { snapshot: EngineSnapshot },
    BoundaryFailure { code: String, message: String },
}

impl EngineEvent {
    pub fn boundary_failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::BoundaryFailure {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests;

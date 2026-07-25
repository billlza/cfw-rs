use cfw_engine_api::{
    BackendError, CutoverPreflightRequestError, EngineCommandContext, EngineMode, EngineOwner,
    NativeEngineStatus, RuntimeIdentity,
};
use cfw_singbox_config::ConfigError;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineOperation {
    QueryStatus,
    StartSystemProxy,
    StopSystemProxy,
    InstallTunnel,
    CancelTunnelInstall,
    StartTunnel,
    StopTunnel,
}

impl std::fmt::Display for EngineOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::QueryStatus => "query_status",
            Self::StartSystemProxy => "start_system_proxy",
            Self::StopSystemProxy => "stop_system_proxy",
            Self::InstallTunnel => "install_tunnel",
            Self::CancelTunnelInstall => "cancel_tunnel_install",
            Self::StartTunnel => "start_tunnel",
            Self::StopTunnel => "stop_tunnel",
        };
        formatter.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecoveredRuntimeMismatch {
    #[error("{mode:?} reported owner {actual:?}, expected {expected:?}")]
    Owner {
        mode: EngineMode,
        expected: EngineOwner,
        actual: EngineOwner,
    },
    #[error("runtime installation identifier differs from authoritative lineage")]
    Installation,
    #[error("runtime installation identifier is not a canonical UUID")]
    InvalidInstallation,
    #[error("runtime configuration epoch differs from authoritative lineage")]
    Epoch,
    #[error("runtime configuration epoch must be nonzero")]
    InvalidEpoch,
    #[error("runtime generation {actual} differs from authoritative generation {expected}")]
    Generation { expected: u64, actual: u64 },
    #[error("runtime generation must be nonzero")]
    InvalidGeneration,
    #[error("runtime configuration identity digest is not canonical SHA-256")]
    Digest,
    #[error("runtime did not attest readiness")]
    NotReady,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum EngineCoordinatorError {
    #[error("engine coordinator is no longer running")]
    CoordinatorClosed,
    #[error("engine coordinator command queue is full")]
    CommandQueueFull,
    #[error("configuration projection failed: {0}")]
    InvalidConfiguration(#[from] ConfigError),
    #[error("cutover preparation requires the replacement engine to be exactly Off")]
    CutoverRequiresOff,
    #[error(
        "cutover preparation requires the effective final route to select a supported remote outbound"
    )]
    CutoverRequiresRemoteOutbound,
    #[error("cutover preparation request is invalid: {0}")]
    InvalidCutoverPreparation(CutoverPreflightRequestError),
    #[error("native operation {operation} failed: {source}")]
    Backend {
        operation: EngineOperation,
        source: BackendError,
    },
    #[error(
        "native runtime identity mismatch: expected {expected_owner:?} context {expected_context:?} digest {expected_digest}, received {actual:?}"
    )]
    RuntimeIdentityMismatch {
        expected_owner: EngineOwner,
        expected_context: EngineCommandContext,
        expected_digest: String,
        actual: Box<RuntimeIdentity>,
    },
    #[error(
        "active {expected_mode:?} runtime is no longer reported by the native backend; observed {actual:?}"
    )]
    ActiveRuntimeStatusMismatch {
        expected_mode: EngineMode,
        actual: Box<NativeEngineStatus>,
    },
    #[error(
        "global Off barrier is unproven: the native backend still reports an owner ({observed:?}) after the current owner attested stopped, so no fresh generation is allocated and the other mode is not started"
    )]
    GlobalOffUnproven { observed: Box<NativeEngineStatus> },
    #[error("native startup reconciliation rejected the observed runtime: {mismatch}")]
    RecoveredRuntimeMismatch {
        mismatch: RecoveredRuntimeMismatch,
        actual: Box<RuntimeIdentity>,
    },
    #[error(
        "native start {start_operation} failed: {start_error}; cleanup {cleanup_operation} also failed: {cleanup_error}"
    )]
    StartAndCleanupFailed {
        start_operation: EngineOperation,
        start_error: BackendError,
        cleanup_operation: EngineOperation,
        cleanup_error: BackendError,
    },
    #[error("{validation_error}; cleanup {cleanup_operation} also failed: {cleanup_error}")]
    ValidationAndCleanupFailed {
        validation_error: Box<EngineCoordinatorError>,
        cleanup_operation: EngineOperation,
        cleanup_error: BackendError,
    },
    #[error("engine generation counter is exhausted")]
    GenerationExhausted,
    #[error("engine lineage journal failed: {0}")]
    Journal(String),
    #[error("engine lineage journal returned generation {actual}, expected {expected}")]
    JournalGenerationMismatch { expected: u64, actual: u64 },
    #[error("engine lineage is invalid: {0}")]
    InvalidLineage(String),
}

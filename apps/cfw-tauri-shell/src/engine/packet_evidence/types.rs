//! Errors, phases, receipts and stage callbacks of a packet evidence
//! transaction.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PacketEvidenceCaptureFailure {
    #[error("fixed packet capture command failed")]
    CommandFailed,
    #[error("packet capture archive failed strict validation")]
    EvidenceRejected,
    #[error("packet capture archive could not be persisted")]
    ArchiveFailed,
    #[error("packet capture was cancelled by its authenticated collector")]
    Cancelled,
    #[error("packet capture control channel failed strict validation")]
    ControlChannelFailed,
}

#[derive(Debug, Error)]
pub enum PacketEvidenceTransactionError {
    #[cfg(feature = "physical-release-evidence")]
    #[error("release Packet evidence is blocked by network maintenance: {0}")]
    Maintenance(String),
    #[cfg(feature = "physical-release-evidence")]
    #[error("legacy network start admission failed: {0}")]
    LegacyRetirement(String),
    #[cfg(feature = "physical-release-evidence")]
    #[error("Tunnel mode is unavailable: {0}")]
    TunnelUnavailable(String),
    #[error("the coordinator has no actor-owned accepted baseline")]
    BaselineUnavailable,
    #[error("the accepted baseline is not the exact ready IPv6-enabled Tunnel snapshot")]
    BaselineMismatch,
    #[error("release Packet evidence projection failed: {0}")]
    Projection(#[from] ConfigError),
    #[error("release Packet evidence test apply failed: {0}")]
    TestApply(EngineCoordinatorError),
    #[error("release Packet evidence test snapshot is not exact: {0}")]
    TestSnapshot(String),
    #[error("release Packet evidence capture failed: {0}")]
    Capture(#[from] PacketEvidenceCaptureFailure),
    #[error("release Packet evidence capture stage exceeded its fixed timeout")]
    CaptureTimeout,
    #[error("release Packet evidence capture stage panicked")]
    CapturePanicked,
    #[error("release Packet evidence baseline restore failed: {0}")]
    Restore(EngineCoordinatorError),
    #[error("release Packet evidence restored snapshot/spec is not exact: {0}")]
    RestoreMismatch(String),
    #[error("release Packet evidence restore failed and coordinator quarantine failed: {0}")]
    Quarantine(EngineCoordinatorError),
    #[error("release Packet evidence receipt could not be published: {0}")]
    Observation(String),
    #[cfg(feature = "physical-release-evidence")]
    #[error("release Packet evidence completion channel closed unexpectedly")]
    CompletionClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEvidencePhase {
    Off,
    TunnelActive,
}

impl PacketEvidencePhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::TunnelActive => "tunnel_active",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceSnapshotReceipt {
    desired_mode: EngineMode,
    generation: u64,
    config_digest: Option<String>,
    phase: PacketEvidencePhase,
    owner: Option<EngineOwner>,
    ready: bool,
    ipv6_enabled: bool,
}

impl PacketEvidenceSnapshotReceipt {
    pub(crate) fn from_exact(
        snapshot: &EngineSnapshot,
        ipv6_enabled: bool,
    ) -> Result<Self, String> {
        if snapshot.generation == 0 {
            return Err("Packet evidence snapshot generation is not positive".to_owned());
        }
        match &snapshot.state {
            EngineState::Off
                if snapshot.desired_mode == EngineMode::Off && snapshot.config_digest.is_none() =>
            {
                Ok(Self {
                    desired_mode: EngineMode::Off,
                    generation: snapshot.generation,
                    config_digest: None,
                    phase: PacketEvidencePhase::Off,
                    owner: None,
                    ready: false,
                    ipv6_enabled,
                })
            }
            EngineState::TunnelActive { runtime }
                if snapshot.desired_mode == EngineMode::Tunnel
                    && snapshot.config_digest.as_deref()
                        == Some(runtime.config_digest.as_str())
                    && canonical_digest(&runtime.config_digest)
                    && runtime.owner == EngineOwner::PacketTunnelSystemExtension
                    && runtime.context.generation == snapshot.generation
                    && runtime.ready =>
            {
                Ok(Self {
                    desired_mode: EngineMode::Tunnel,
                    generation: snapshot.generation,
                    config_digest: snapshot.config_digest.clone(),
                    phase: PacketEvidencePhase::TunnelActive,
                    owner: Some(runtime.owner),
                    ready: true,
                    ipv6_enabled,
                })
            }
            _ => Err("Packet evidence snapshot identity is not exact".to_owned()),
        }
    }

    pub const fn desired_mode(&self) -> EngineMode {
        self.desired_mode
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn config_digest(&self) -> Option<&str> {
        self.config_digest.as_deref()
    }

    pub const fn phase(&self) -> PacketEvidencePhase {
        self.phase
    }

    pub const fn owner(&self) -> Option<EngineOwner> {
        self.owner
    }

    pub const fn ready(&self) -> bool {
        self.ready
    }

    pub const fn ipv6_enabled(&self) -> bool {
        self.ipv6_enabled
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceBaselineReady {
    pub case: ReleasePacketEvidenceCase,
    pub baseline: PacketEvidenceSnapshotReceipt,
    pub baseline_observation_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceTestReady {
    pub case: ReleasePacketEvidenceCase,
    pub baseline: PacketEvidenceSnapshotReceipt,
    pub baseline_observation_sequence: u64,
    pub test: PacketEvidenceSnapshotReceipt,
    pub test_observation_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceCaptureFinalizing {
    pub case: ReleasePacketEvidenceCase,
    pub baseline: PacketEvidenceSnapshotReceipt,
    pub baseline_observation_sequence: u64,
    pub test: Option<PacketEvidenceSnapshotReceipt>,
    pub test_observation_sequence: Option<u64>,
    pub restore: PacketEvidenceSnapshotReceipt,
    pub restore_observation_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEvidenceAbortReason {
    TestApplyFailed,
    TestSnapshotInvalid,
    RestoreUnproven,
    RestoreMismatch,
    RestoreQuarantineFailed,
    ObservationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceCaptureAborted {
    pub case: ReleasePacketEvidenceCase,
    pub baseline: PacketEvidenceSnapshotReceipt,
    pub baseline_observation_sequence: u64,
    pub reason: PacketEvidenceAbortReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketEvidenceCaptureTerminal {
    Restored(PacketEvidenceCaptureFinalizing),
    Aborted(PacketEvidenceCaptureAborted),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceTransactionOutcome {
    pub baseline: PacketEvidenceSnapshotReceipt,
    pub baseline_observation_sequence: u64,
    pub test: PacketEvidenceSnapshotReceipt,
    pub test_observation_sequence: u64,
    pub restore: PacketEvidenceSnapshotReceipt,
    pub restore_observation_sequence: u64,
    pub candidate_observation_sequence: u64,
}

pub(crate) type StageFuture =
    Pin<Box<dyn Future<Output = Result<(), PacketEvidenceCaptureFailure>> + Send + 'static>>;
pub(crate) type StageOperation<Input> = Box<dyn FnOnce(Input) -> StageFuture + Send + 'static>;

pub struct PacketEvidenceStages {
    pub(crate) begin_capture: StageOperation<PacketEvidenceBaselineReady>,
    pub(crate) exercise_test: StageOperation<PacketEvidenceTestReady>,
    pub(crate) finish_capture: StageOperation<PacketEvidenceCaptureTerminal>,
}

impl PacketEvidenceStages {
    pub fn new<Begin, BeginFuture, Exercise, ExerciseFuture, Finish, FinishFuture>(
        begin_capture: Begin,
        exercise_test: Exercise,
        finish_capture: Finish,
    ) -> Self
    where
        Begin: FnOnce(PacketEvidenceBaselineReady) -> BeginFuture + Send + 'static,
        BeginFuture: Future<Output = Result<(), PacketEvidenceCaptureFailure>> + Send + 'static,
        Exercise: FnOnce(PacketEvidenceTestReady) -> ExerciseFuture + Send + 'static,
        ExerciseFuture: Future<Output = Result<(), PacketEvidenceCaptureFailure>> + Send + 'static,
        Finish: FnOnce(PacketEvidenceCaptureTerminal) -> FinishFuture + Send + 'static,
        FinishFuture: Future<Output = Result<(), PacketEvidenceCaptureFailure>> + Send + 'static,
    {
        Self {
            begin_capture: Box::new(move |ready| Box::pin(begin_capture(ready))),
            exercise_test: Box::new(move |ready| Box::pin(exercise_test(ready))),
            finish_capture: Box::new(move |ready| Box::pin(finish_capture(ready))),
        }
    }
}

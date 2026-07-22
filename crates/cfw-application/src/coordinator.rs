use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use cfw_engine_api::{
    CutoverPreflightRequest, EngineBackend, EngineGenerationStore, EngineMode,
    EngineSessionIdentity, EngineSnapshot, EngineState,
};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use tokio::sync::{mpsc, oneshot, watch};

use crate::{
    EngineCoordinatorError,
    coordinator_actor::{
        Command, CoordinatorRuntime, SetModeCommand, StartupReconciliation, run_coordinator,
    },
    runtime::validate_lineage,
};

pub(crate) const COMMAND_QUEUE_CAPACITY: usize = 32;
const DEFAULT_STATUS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_STATUS_RECONCILIATION_INTERVAL: Duration = Duration::from_secs(2);

pub type CoordinatorTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorOptions {
    pub operation_timeout: Duration,
    pub status_query_timeout: Duration,
    pub status_reconciliation_interval: Duration,
    pub initial_generation: u64,
}

impl Default for CoordinatorOptions {
    fn default() -> Self {
        Self {
            operation_timeout: Duration::from_secs(15),
            status_query_timeout: DEFAULT_STATUS_QUERY_TIMEOUT,
            status_reconciliation_interval: DEFAULT_STATUS_RECONCILIATION_INTERVAL,
            initial_generation: 0,
        }
    }
}

#[derive(Clone)]
pub struct EngineModeCoordinator {
    commands: mpsc::Sender<Command>,
    snapshots: watch::Receiver<EngineSnapshot>,
    reconciliation: watch::Receiver<Option<Result<EngineSnapshot, EngineCoordinatorError>>>,
}

impl EngineModeCoordinator {
    pub fn spawn(backend: Arc<dyn EngineBackend>, session: EngineSessionIdentity) -> Self {
        Self::spawn_with_options(backend, session, CoordinatorOptions::default())
    }

    pub fn spawn_with_options(
        backend: Arc<dyn EngineBackend>,
        session: EngineSessionIdentity,
        options: CoordinatorOptions,
    ) -> Self {
        Self::spawn_inner(backend, session, options, None)
    }

    pub fn spawn_persisted(
        backend: Arc<dyn EngineBackend>,
        generation_store: Arc<dyn EngineGenerationStore>,
        operation_timeout: Duration,
    ) -> Result<Self, EngineCoordinatorError> {
        Self::spawn_persisted_with(backend, generation_store, operation_timeout, |task| {
            tokio::spawn(task);
        })
    }

    pub fn spawn_persisted_with(
        backend: Arc<dyn EngineBackend>,
        generation_store: Arc<dyn EngineGenerationStore>,
        operation_timeout: Duration,
        spawn: impl FnOnce(CoordinatorTask),
    ) -> Result<Self, EngineCoordinatorError> {
        let lineage = generation_store
            .load()
            .map_err(EngineCoordinatorError::Journal)?;
        validate_lineage(&lineage)?;
        let (coordinator, task) = Self::create_inner(
            backend,
            lineage.session,
            CoordinatorOptions {
                operation_timeout,
                status_query_timeout: DEFAULT_STATUS_QUERY_TIMEOUT,
                status_reconciliation_interval: DEFAULT_STATUS_RECONCILIATION_INTERVAL,
                initial_generation: lineage.generation,
            },
            Some(generation_store),
            StartupReconciliation::RecoverKnownLineage,
        );
        spawn(task);
        Ok(coordinator)
    }

    /// Starts a cleanup-only coordinator when the authoritative generation
    /// journal cannot be loaded. Native starts remain fail-closed because every
    /// generation reservation returns the original journal error. Startup still
    /// queries the signed native bridge and tears down any reported runtime;
    /// journal failure is never treated as evidence that the data plane is Off.
    pub fn spawn_journal_unavailable_with(
        backend: Arc<dyn EngineBackend>,
        journal_error: impl Into<String>,
        operation_timeout: Duration,
        spawn: impl FnOnce(CoordinatorTask),
    ) -> Self {
        Self::spawn_unavailable_with(backend, journal_error, operation_timeout, spawn)
    }

    /// Starts a capability-closed cleanup-only coordinator. This is used when
    /// an authoritative prerequisite is unavailable and no native mode can be
    /// opened. It may stop a reported native runtime but can never adopt it.
    pub fn spawn_unavailable_with(
        backend: Arc<dyn EngineBackend>,
        reason: impl Into<String>,
        operation_timeout: Duration,
        spawn: impl FnOnce(CoordinatorTask),
    ) -> Self {
        let generation_store = Arc::new(UnavailableGenerationStore {
            reason: reason.into(),
        });
        let (coordinator, task) = Self::create_inner(
            backend,
            EngineSessionIdentity {
                installation_id: "unavailable-keychain-lineage".into(),
                config_epoch: 1,
            },
            CoordinatorOptions {
                operation_timeout,
                status_query_timeout: DEFAULT_STATUS_QUERY_TIMEOUT,
                status_reconciliation_interval: DEFAULT_STATUS_RECONCILIATION_INTERVAL,
                initial_generation: 0,
            },
            Some(generation_store),
            StartupReconciliation::CleanupWithoutLineage,
        );
        spawn(task);
        coordinator
    }

    fn spawn_inner(
        backend: Arc<dyn EngineBackend>,
        session: EngineSessionIdentity,
        options: CoordinatorOptions,
        generation_store: Option<Arc<dyn EngineGenerationStore>>,
    ) -> Self {
        let (coordinator, task) = Self::create_inner(
            backend,
            session,
            options,
            generation_store,
            StartupReconciliation::RecoverKnownLineage,
        );
        tokio::spawn(task);
        coordinator
    }

    fn create_inner(
        backend: Arc<dyn EngineBackend>,
        session: EngineSessionIdentity,
        options: CoordinatorOptions,
        generation_store: Option<Arc<dyn EngineGenerationStore>>,
        startup_reconciliation: StartupReconciliation,
    ) -> (Self, CoordinatorTask) {
        assert!(
            !options.status_reconciliation_interval.is_zero(),
            "status reconciliation interval must be nonzero"
        );
        assert!(
            !options.status_query_timeout.is_zero(),
            "status query timeout must be nonzero"
        );
        let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let mut initial_snapshot = EngineSnapshot {
            generation: options.initial_generation,
            ..EngineSnapshot::default()
        };
        initial_snapshot.state = EngineState::Failed {
            generation: options.initial_generation,
            target: EngineMode::Off,
            error: "native startup reconciliation is pending".into(),
        };
        let (snapshot_tx, snapshot_rx) = watch::channel(initial_snapshot.clone());
        let (reconciliation_tx, reconciliation_rx) = watch::channel(None);
        let task = Box::pin(run_coordinator(
            command_rx,
            snapshot_tx,
            initial_snapshot,
            reconciliation_tx,
            CoordinatorRuntime {
                backend,
                session,
                generation_store,
                options,
                startup_reconciliation,
            },
        ));
        (
            Self {
                commands: command_tx,
                snapshots: snapshot_rx,
                reconciliation: reconciliation_rx,
            },
            task,
        )
    }

    /// Requests a stable target mode. Dropping this future after the command is
    /// accepted does not cancel a transition that may already own native state.
    pub async fn set_mode(
        &self,
        target: EngineMode,
        profile: ValidatedSingBoxProfile,
        settings: EngineSettings,
    ) -> Result<EngineSnapshot, EngineCoordinatorError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.commands
            .try_send(Command::SetMode(Box::new(SetModeCommand {
                target,
                profile,
                settings,
                response: response_tx,
            })))
            .map_err(map_send_error)?;
        response_rx
            .await
            .map_err(|_| EngineCoordinatorError::CoordinatorClosed)?
    }

    /// Builds both deterministic native projections for a one-way legacy
    /// cutover while the coordinator actor proves that its owned runtime is
    /// exactly Off. This does not reserve a generation or start native state.
    pub async fn prepare_cutover(
        &self,
        target: EngineMode,
        profile: ValidatedSingBoxProfile,
        settings: EngineSettings,
    ) -> Result<CutoverPreflightRequest, EngineCoordinatorError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.commands
            .try_send(Command::PrepareCutover(Box::new(
                crate::coordinator_actor::PrepareCutoverCommand {
                    target,
                    profile,
                    settings,
                    response: response_tx,
                },
            )))
            .map_err(map_send_error)?;
        response_rx
            .await
            .map_err(|_| EngineCoordinatorError::CoordinatorClosed)?
    }

    pub fn snapshot(&self) -> EngineSnapshot {
        self.snapshots.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<EngineSnapshot> {
        self.snapshots.clone()
    }

    /// Waits until the initial native status has either been reconciled or
    /// failed closed. Commands are serialized behind the same barrier.
    pub async fn wait_for_reconciliation(&self) -> Result<EngineSnapshot, EngineCoordinatorError> {
        let mut reconciliation = self.reconciliation.clone();
        loop {
            if let Some(result) = reconciliation.borrow().clone() {
                return result;
            }
            reconciliation
                .changed()
                .await
                .map_err(|_| EngineCoordinatorError::CoordinatorClosed)?;
        }
    }

    /// Stops the active or partially-started native runtime and closes the
    /// coordinator. A successful return is a native stop barrier.
    pub async fn shutdown(&self) -> Result<EngineSnapshot, EngineCoordinatorError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.commands
            .try_send(Command::Shutdown {
                response: response_tx,
            })
            .map_err(map_send_error)?;
        response_rx
            .await
            .map_err(|_| EngineCoordinatorError::CoordinatorClosed)?
    }
}

fn map_send_error<T>(error: mpsc::error::TrySendError<T>) -> EngineCoordinatorError {
    match error {
        mpsc::error::TrySendError::Full(_) => EngineCoordinatorError::CommandQueueFull,
        mpsc::error::TrySendError::Closed(_) => EngineCoordinatorError::CoordinatorClosed,
    }
}

struct UnavailableGenerationStore {
    reason: String,
}

impl EngineGenerationStore for UnavailableGenerationStore {
    fn load(&self) -> Result<cfw_engine_api::EngineLineage, String> {
        Err(self.reason.clone())
    }

    fn reserve_next(&self, _expected_generation: u64) -> Result<u64, String> {
        Err(self.reason.clone())
    }
}

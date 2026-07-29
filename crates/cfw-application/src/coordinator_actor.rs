use std::sync::Arc;

use cfw_engine_api::{
    CutoverPreflightRequest, EngineBackend, EngineGenerationStore, EngineMode,
    EngineSessionIdentity, EngineSnapshot,
};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::{Instant, MissedTickBehavior, interval_at},
};

use crate::{
    CoordinatorOptions, EngineCoordinatorError,
    coordinator_startup::reconcile_initial_state,
    cutover::prepare_cutover_request,
    runtime::{CoordinatorState, reconcile_active_runtime, set_failed, set_off},
    transition::{transition, transition_to_off},
};

#[derive(Clone, Copy)]
pub(crate) enum StartupReconciliation {
    CleanupKnownLineage,
    CleanupWithoutLineage,
}

pub(crate) struct CoordinatorRuntime {
    pub(crate) backend: Arc<dyn EngineBackend>,
    pub(crate) session: EngineSessionIdentity,
    pub(crate) generation_store: Option<Arc<dyn EngineGenerationStore>>,
    pub(crate) options: CoordinatorOptions,
    pub(crate) startup_reconciliation: StartupReconciliation,
}

pub(crate) struct SetModeCommand {
    pub(crate) target: EngineMode,
    pub(crate) profile_id: String,
    pub(crate) profile: ValidatedSingBoxProfile,
    pub(crate) settings: EngineSettings,
    pub(crate) response: oneshot::Sender<Result<EngineSnapshot, EngineCoordinatorError>>,
}

pub(crate) struct PrepareCutoverCommand {
    pub(crate) target: EngineMode,
    pub(crate) profile_id: String,
    pub(crate) profile: ValidatedSingBoxProfile,
    pub(crate) settings: EngineSettings,
    pub(crate) response: oneshot::Sender<Result<CutoverPreflightRequest, EngineCoordinatorError>>,
}

pub(crate) enum Command {
    SetMode(Box<SetModeCommand>),
    PrepareCutover(Box<PrepareCutoverCommand>),
    Shutdown {
        response: oneshot::Sender<Result<EngineSnapshot, EngineCoordinatorError>>,
    },
}

pub(crate) async fn run_coordinator(
    mut commands: mpsc::Receiver<Command>,
    snapshots: watch::Sender<EngineSnapshot>,
    initial_snapshot: EngineSnapshot,
    reconciliation: watch::Sender<Option<Result<EngineSnapshot, EngineCoordinatorError>>>,
    runtime: CoordinatorRuntime,
) {
    let CoordinatorRuntime {
        backend,
        session,
        generation_store,
        options,
        startup_reconciliation,
    } = runtime;
    let mut state = CoordinatorState {
        snapshot: initial_snapshot,
        native_lease: None,
        quarantine: None,
    };
    let startup_failure = match reconcile_initial_state(
        backend.as_ref(),
        &mut state,
        &snapshots,
        &session,
        options.operation_timeout,
        startup_reconciliation,
    )
    .await
    {
        Ok(()) => {
            reconciliation.send_replace(Some(Ok(state.snapshot.clone())));
            None
        }
        Err(failure) => {
            reconciliation.send_replace(Some(Err(failure.error.clone())));
            Some(failure)
        }
    };

    let interval_start = Instant::now() + options.status_reconciliation_interval;
    let mut status_reconciliation =
        interval_at(interval_start, options.status_reconciliation_interval);
    status_reconciliation.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    break;
                };
                if let Some(failure) = &startup_failure {
                    match command {
                        Command::SetMode(command)
                            if command.target == EngineMode::Off && failure.safely_off => {
                            state.snapshot.desired_mode = EngineMode::Off;
                            set_off(&mut state, &snapshots);
                            let _response_dropped = command.response.send(Ok(state.snapshot.clone()));
                        }
                        Command::SetMode(command) => {
                            let _response_dropped = command.response.send(Err(failure.error.clone()));
                        }
                        Command::PrepareCutover(command) => {
                            let _response_dropped = command.response.send(Err(failure.error.clone()));
                        }
                        Command::Shutdown { response } if failure.safely_off => {
                            state.snapshot.desired_mode = EngineMode::Off;
                            set_off(&mut state, &snapshots);
                            let _response_dropped = response.send(Ok(state.snapshot.clone()));
                            return;
                        }
                        Command::Shutdown { response } => {
                            let _response_dropped = response.send(Err(failure.error.clone()));
                        }
                    }
                    continue;
                }
                match command {
                    Command::SetMode(command) => {
                        let SetModeCommand {
                            target,
                            profile_id,
                            profile,
                            settings,
                            response,
                        } = *command;
                        let context = crate::runtime::TransitionContext {
                            backend: backend.as_ref(),
                            snapshots: &snapshots,
                            session: &session,
                            generation_store: generation_store.as_deref(),
                            operation_timeout: options.operation_timeout,
                            status_query_timeout: options.status_query_timeout,
                        };
                        let result = transition(
                            context,
                            &mut state,
                            target,
                            &profile_id,
                            &profile,
                            &settings,
                        ).await;
                        let _response_dropped = response.send(result);
                    }
                    Command::PrepareCutover(command) => {
                        let PrepareCutoverCommand {
                            target,
                            profile_id,
                            profile,
                            settings,
                            response,
                        } = *command;
                        let result = prepare_cutover_request(
                            &state,
                            &session,
                            target,
                            &profile_id,
                            &profile,
                            &settings,
                        );
                        let _response_dropped = response.send(result);
                    }
                    Command::Shutdown { response } => {
                        let result = transition_to_off(
                            backend.as_ref(),
                            &mut state,
                            &snapshots,
                            options.operation_timeout,
                            generation_store.as_deref(),
                        )
                        .await;
                        let should_close = state.native_lease.is_none()
                            && state.snapshot.state == cfw_engine_api::EngineState::Off;
                        let _response_dropped = response.send(result);
                        if should_close {
                            return;
                        }
                    }
                }
            }
            _ = status_reconciliation.tick(), if startup_failure.is_none() => {
                let _reconciliation_failure = reconcile_active_runtime(
                    backend.as_ref(),
                    &mut state,
                    &snapshots,
                    options.status_query_timeout,
                )
                .await;
            }
        }
    }

    if startup_failure.is_some() {
        return;
    }

    if let Err(error) = transition_to_off(
        backend.as_ref(),
        &mut state,
        &snapshots,
        options.operation_timeout,
        generation_store.as_deref(),
    )
    .await
    {
        let generation = state.snapshot.generation;
        set_failed(&mut state, &snapshots, EngineMode::Off, generation, &error);
    }
}

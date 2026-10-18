use super::{ManagedAutomation, policy::NetworkEdge, report};
use std::{sync::atomic::Ordering, time::Duration};
use tauri::{AppHandle, Manager};

pub(super) fn start(app: AppHandle) {
    let mut preferences = app.state::<ManagedAutomation>().preferences.subscribe();
    tauri::async_runtime::spawn(async move {
        let mut edge = NetworkEdge::default();
        let mut candidate_revision = app
            .state::<crate::engine::ManagedEngine>()
            .mode_intent_revision();
        let mut first_observation = true;
        let mut last_observed = None;
        loop {
            let enabled = preferences.borrow().network_enabled;
            if !enabled {
                if preferences.changed().await.is_err() {
                    break;
                }
                edge = NetworkEdge::default();
                candidate_revision = app
                    .state::<crate::engine::ManagedEngine>()
                    .mode_intent_revision();
                first_observation = true;
                last_observed = None;
                continue;
            }
            tokio::select! {
                changed=preferences.changed()=>{if changed.is_err(){break} edge=NetworkEdge::default();candidate_revision=app.state::<crate::engine::ManagedEngine>().mode_intent_revision();first_observation=true;last_observed=None;continue},
                _=tokio::time::sleep(Duration::from_secs(5))=>{}
            }
            if app
                .state::<ManagedAutomation>()
                .blocked
                .load(Ordering::Acquire)
            {
                continue;
            }
            let configuration = preferences.borrow().clone();
            let observed =
                tauri::async_runtime::spawn_blocking(cfw_platform::current_network_context).await;
            let network = match observed {
                Ok(Ok(network)) => network,
                Ok(Err(error)) => {
                    edge.uncertain();
                    report(&app, error.to_string());
                    continue;
                }
                Err(error) => {
                    edge.uncertain();
                    report(
                        &app,
                        format!("network observation did not complete: {error}"),
                    );
                    continue;
                }
            };
            if *preferences.borrow() != configuration {
                edge = NetworkEdge::default();
                continue;
            }
            if last_observed.as_ref() != Some(&network) && !first_observation {
                candidate_revision = app
                    .state::<crate::engine::ManagedEngine>()
                    .mode_intent_revision();
            }
            first_observation = false;
            last_observed = Some(network.clone());
            let Some(network) = edge.observe(network) else {
                continue;
            };
            let Some(mode) = configuration.mode_for(&network) else {
                continue;
            };
            let engine = app.state::<crate::engine::ManagedEngine>();
            let snapshot = engine.coordinator.snapshot();
            if snapshot.desired_mode == mode {
                continue;
            }
            let transition = async {
                let revision = candidate_revision.map_err(|error| error.to_string())?;
                let lease = engine
                    .begin_automatic_mode_change(mode, revision)
                    .await
                    .map_err(|error| error.to_string())?;
                if engine.coordinator.snapshot() != snapshot
                    || *preferences.borrow() != configuration
                {
                    return Err("network rule was superseded by a newer user operation".to_string());
                }
                crate::engine::apply_admitted_engine_mode(
                    &engine,
                    &app.state(),
                    &app.state(),
                    mode,
                    lease,
                )
                .await
                .map(|_| ())
            }
            .await;
            if let Err(error) = transition {
                report(&app, format!("network rule could not be applied: {error}"))
            }
        }
    });
}

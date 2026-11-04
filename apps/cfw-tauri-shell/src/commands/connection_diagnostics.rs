//! Bind diagnostic transport to the observed runtime; never start a core or
//! silently fall back after a proxy failure. The main WebView owns each run.
use crate::connection_diagnostics::{
    self as probes, ConnectivityReport, DiagnosticsGate, DnsReport, IpInformation, Route,
};
use crate::engine::ManagedEngine;
use cfw_engine_api::{EngineMode, EngineSnapshot, EngineState};
use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;
use tauri::{State, WebviewWindow};
use uuid::Uuid;

fn require_main(window: &WebviewWindow) -> Result<(), String> {
    if window.label() == "main" {
        Ok(())
    } else {
        Err("connection diagnostics require the main window".into())
    }
}

fn route(engine: &ManagedEngine, snapshot: &EngineSnapshot) -> Result<Route, String> {
    match &snapshot.state {
        EngineState::Off if snapshot.desired_mode == EngineMode::Off => Ok(Route::System),
        EngineState::TunnelActive { .. }
        | EngineState::LocalProxyActive { .. }
        | EngineState::ProxyActive { .. }
        | EngineState::TunnelSystemProxyActive { .. } => {
            let identity = super::controller::running_runtime_identity(
                engine.coordinator.runtime_platform(),
                snapshot,
            )
            .map_err(|_| "diagnostic runtime is not ready")?;
            if matches!(snapshot.state, EngineState::TunnelActive { .. }) {
                return Ok(Route::Tunnel);
            }
            let access = engine
                .active_controller_access(identity.context.generation, &identity.config_digest)?;
            Ok(Route::EngineProxy {
                port: access.settings().mixed_port,
            })
        }
        _ => Err("engine_transition_in_progress".into()),
    }
}

async fn selections(
    engine: &ManagedEngine,
    snapshot: &EngineSnapshot,
) -> Result<Vec<(String, Option<String>)>, String> {
    if snapshot.state == EngineState::Off {
        return Ok(Vec::new());
    }
    let proxies = super::controller::controller_client(engine)
        .map_err(|_| "runtime_changed")?
        .proxies()
        .await
        .map_err(|_| "node_selection_unavailable")?;
    let mut values = proxies
        .groups
        .into_iter()
        .map(|group| (group.name, group.now))
        .collect::<Vec<_>>();
    values.sort();
    Ok(values)
}

async fn observe<T, F, Fut>(
    engine: &ManagedEngine,
    gate: &DiagnosticsGate,
    id: Uuid,
    lookup: bool,
    operation: F,
) -> Result<T, String>
where
    F: FnOnce(Route) -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let mut activity = gate.begin(id, lookup)?;
    let mut changes = engine.coordinator.subscribe();
    let snapshot = changes.borrow_and_update().clone();
    let revision = engine
        .mode_intent_revision()
        .map_err(|_| "runtime_changed")?;
    let route = route(engine, &snapshot)?;
    let work = async {
        let initial_selection = selections(engine, &snapshot).await?;
        let result = operation(route).await?;
        if engine
            .mode_intent_revision()
            .map_err(|_| "runtime_changed")?
            != revision
            || engine.coordinator.snapshot() != snapshot
            || selections(engine, &snapshot).await? != initial_selection
        {
            return Err("runtime_changed".into());
        }
        Ok(result)
    };
    tokio::select! {
        _ = activity.cancelled.changed() => Err("cancelled".into()),
        _ = wait_for_snapshot_change(&mut changes, &snapshot) => Err("runtime_changed".into()),
        result = tokio::time::timeout(Duration::from_secs(30), work) => result.map_err(|_| "timeout".to_owned())?,
    }
}

async fn wait_for_snapshot_change(
    changes: &mut tokio::sync::watch::Receiver<EngineSnapshot>,
    expected: &EngineSnapshot,
) {
    loop {
        if changes.changed().await.is_err() || *changes.borrow_and_update() != *expected {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn duplicate_attestations_do_not_cancel_but_new_generations_do() {
        let expected = EngineSnapshot::default();
        let (sender, mut receiver) = tokio::sync::watch::channel(expected.clone());
        let mut waiting =
            tokio::spawn(async move { wait_for_snapshot_change(&mut receiver, &expected).await });
        sender.send_replace(EngineSnapshot::default());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        sender.send_replace(EngineSnapshot {
            generation: 1,
            ..EngineSnapshot::default()
        });
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tauri::command]
pub(crate) async fn connection_diagnostics(
    window: WebviewWindow,
    engine: State<'_, ManagedEngine>,
    gate: State<'_, DiagnosticsGate>,
    request_id: Uuid,
) -> Result<ConnectivityReport, String> {
    require_main(&window)?;
    observe(&engine, &gate, request_id, false, probes::run_connectivity).await
}

#[tauri::command]
pub(crate) async fn connection_dns_check(
    window: WebviewWindow,
    engine: State<'_, ManagedEngine>,
    gate: State<'_, DiagnosticsGate>,
    request_id: Uuid,
) -> Result<DnsReport, String> {
    require_main(&window)?;
    let gate = &*gate;
    observe(&engine, gate, request_id, false, |route| async move {
        probes::run_dns_check(route, gate)
            .await
            .map_err(str::to_owned)
    })
    .await
}

#[tauri::command]
pub(crate) async fn connection_ip_information(
    window: WebviewWindow,
    engine: State<'_, ManagedEngine>,
    gate: State<'_, DiagnosticsGate>,
    request_id: Uuid,
    ip: IpAddr,
) -> Result<IpInformation, String> {
    require_main(&window)?;
    let gate = &*gate;
    observe(&engine, gate, request_id, true, |route| async move {
        let result = probes::lookup_ip(route, ip).await;
        if matches!(result, Err("provider_rate_limited")) {
            gate.block_lookup()?;
        }
        result.map_err(str::to_owned)
    })
    .await
}

#[tauri::command]
pub(crate) fn cancel_connection_diagnostics(
    window: WebviewWindow,
    gate: State<'_, DiagnosticsGate>,
    request_id: Uuid,
) -> Result<(), String> {
    require_main(&window)?;
    gate.cancel(request_id)
}

use super::*;
use cfw_engine_api::{
    CredentialPresenceRequest, EngineMode, EngineOwner, EngineSnapshot, EngineState,
    NativeEngineStatus, ProfileDelayTestRequest, ProfileProbeFailure,
};
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use cfw_windows_engine::runtime_host::InstalledDesktop;

// Compile and exercise the application's actual platform assembly. This
// intentionally contains no Tauri/WebView substitute and makes no GUI claim.
#[path = "../../../../../../apps/cfw-tauri-shell/src/platform_runtime.rs"]
mod platform_runtime;

const PROFILE: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

pub(super) fn exercise(progress: &mut Progress) -> Result<serde_json::Value> {
    progress.record("coordinator_prepare", 5)?;
    let desktop = InstalledDesktop::open().map_err(|error| error.to_string())?;
    let before = checks::snapshot()?;
    let original_proxy = desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?;
    let process_observation = super::super::desktop_process::observe()?;
    let prepared = platform_runtime::PlatformRuntime::load(&desktop.paths().root)?.prepare()?;
    if !prepared.services.proxy_available
        || prepared.services.tunnel_available
        || prepared.services.legacy_preflight.is_some()
        || prepared.services.unavailable_reason.is_some()
        || prepared.services.backend.runtime_platform()
            != cfw_engine_api::EngineRuntimePlatform::Windows
        || prepared.coordinator.snapshot().generation != 5
        || !matches!(
            prepared.coordinator.snapshot().state,
            EngineState::Failed { .. }
        )
        || checks::snapshot()? != before
        || desktop
            .storage()
            .proxy()
            .snapshot()
            .map_err(|e| e.to_string())?
            != original_proxy
    {
        return Err("desktop preparation changed native state or overstated capability".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let platform_runtime::PreparedRuntime {
            services,
            coordinator,
            task,
        } = prepared;
        let task = tokio::spawn(task);
        let exercised = async {
            let initial = coordinator
                .wait_for_reconciliation()
                .await
                .map_err(|e| e.to_string())?;
            require_off(&initial, 5)?;
            progress.record("coordinator_initial_off", 5)?;
            let profile = ValidatedSingBoxProfile::parse(
                r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#,
            )
            .map_err(|e| e.to_string())?;
            let mixed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
            let controller =
                TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
            let address = mixed.local_addr().map_err(|e| e.to_string())?;
            let settings = EngineSettings {
                mixed_port: address.port(),
                controller_port: controller.local_addr().map_err(|e| e.to_string())?.port(),
                bypass_private_networks: false,
                ..Default::default()
            };
            // Use the same SystemProxy projection as the offline desktop command.
            let probe = profile
                .project_proxy_probe(PROFILE, ProjectionMode::SystemProxy, &settings)
                .map_err(|e| e.to_string())?;
            let presence = services
                .credentials
                .query_profile_credentials(
                    CredentialPresenceRequest::new(PROFILE, &profile).map_err(|e| e.to_string())?,
                )
                .await
                .map_err(|e| e.to_string())?;
            if !presence.is_empty() {
                return Err(
                    "credential-free profile returned unrelated credential presence".into(),
                );
            }
            let rows = services
                .probes
                .test_profile_delays(ProfileDelayTestRequest {
                    audience: probe.credential_audience().clone(),
                    config_json: probe.as_json().into(),
                    credential_slots: probe.credential_slots().to_vec(),
                    proxies: vec!["absent-node".into()],
                    timeout_ms: 100,
                    target_url: Some("http://127.0.0.1/desktop-probe".into()),
                    expected_status: Some("204".into()),
                })
                .await
                .map_err(|e| e.to_string())?;
            if rows.len() != 1
                || rows[0].name != "absent-node"
                || rows[0].delay.is_some()
                || rows[0].error_kind != Some(ProfileProbeFailure::NotFound)
                || checks::snapshot()? != before
            {
                return Err("desktop offline probe did not preserve native Off".into());
            }
            services
                .authorization
                .authorize_system_proxy(false)
                .await
                .map_err(|e| e.to_string())?;
            services
                .authorization
                .authorize_system_proxy(true)
                .await
                .map_err(|e| e.to_string())?;
            progress.record("coordinator_services_checked", 5)?;
            drop(mixed);
            drop(controller);
            let mut modes = Vec::new();
            for (mode, generation) in [(EngineMode::LocalProxy, 6), (EngineMode::SystemProxy, 7)] {
                progress.record("coordinator_set_mode", generation)?;
                let active = coordinator
                    .set_mode(mode, PROFILE.into(), profile.clone(), settings.clone())
                    .await
                    .map_err(|e| e.to_string())?;
                let identity = match (&active.state, mode) {
                    (EngineState::LocalProxyActive { runtime }, EngineMode::LocalProxy)
                    | (EngineState::ProxyActive { runtime }, EngineMode::SystemProxy) => runtime,
                    _ => return Err("application did not publish the requested active mode".into()),
                };
                if identity.owner != EngineOwner::WindowsUserAgent
                    || !identity.ready
                    || identity.context.generation != generation
                    || active.generation != generation
                {
                    return Err("application active identity differs from native ownership".into());
                }
                user_agent::traffic(address)?;
                let repeated = coordinator
                    .set_mode(mode, PROFILE.into(), profile.clone(), settings.clone())
                    .await
                    .map_err(|e| e.to_string())?;
                if repeated != active
                    || desktop
                        .generations()
                        .load_lineage()
                        .map_err(|e| e.to_string())?
                        .generation
                        != generation
                {
                    return Err(
                        "same-mode request changed the runtime or allocated a generation".into(),
                    );
                }
                let native = services
                    .backend
                    .query_status()
                    .await
                    .map_err(|e| e.to_string())?;
                let observed = match (&native, mode) {
                    (NativeEngineStatus::LocalProxy { runtime }, EngineMode::LocalProxy)
                    | (NativeEngineStatus::SystemProxy { runtime }, EngineMode::SystemProxy) => {
                        runtime
                    }
                    _ => return Err("coordinator and native mode disagree".into()),
                };
                let proxy_changed = desktop
                    .storage()
                    .proxy()
                    .snapshot()
                    .map_err(|e| e.to_string())?
                    != original_proxy;
                if observed != identity || proxy_changed != (mode == EngineMode::SystemProxy) {
                    return Err("coordinator and native identity or proxy settings disagree".into());
                }
                modes.push(
                    serde_json::json!({"snapshot":active,"native":native,"traffic":true,
                    "same_mode_preserved_generation":true,"proxy_changed":proxy_changed}),
                );
                progress.record("coordinator_active", generation)?;
            }
            Ok((initial, modes))
        }
        .await;
        // Always attempt the actual application's shutdown barrier, including
        // after a failed assertion. Keep both errors when cleanup also fails.
        progress.record("coordinator_shutdown", coordinator.snapshot().generation)?;
        let shutdown = coordinator.shutdown().await.map_err(|e| e.to_string());
        let result = match (exercised, shutdown) {
            (Ok(value), Ok(off)) => Ok((value, off)),
            (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
            (Err(operation), Err(cleanup)) => Err(format!("{operation}; shutdown: {cleanup}")),
        };
        let ((initial, modes), off) = result?;
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .map_err(|_| "application coordinator did not retire after shutdown")?
            .map_err(|e| e.to_string())?;
        require_off(&off, 8)?;
        let final_native = services
            .backend
            .query_status()
            .await
            .map_err(|e| e.to_string())?;
        let lineage = desktop
            .generations()
            .load_lineage()
            .map_err(|e| e.to_string())?;
        if final_native != NativeEngineStatus::Off
            || lineage.generation != 8
            || desktop
                .storage()
                .proxy()
                .snapshot()
                .map_err(|e| e.to_string())?
                != original_proxy
        {
            return Err("application shutdown did not preserve native cleanup and lineage".into());
        }
        progress.record("coordinator_off", 8)?;
        Ok(
            serde_json::json!({"shared_desktop_assembly":true,"shared_mode_coordinator":true,
            "prepared_without_starting":true,"credentials_and_probes_connected":true,
            "initial":initial,"modes":modes,"shutdown":off,"final_native":final_native,
            "authority":checks::snapshot()?,"lineage_generation":lineage.generation,
            "proxy_restored":true,"coordinator_retired":true,"gui_exercised":false,
            "process_observation":process_observation,
            "tunnel_available":false,"legacy_cutover_available":false}),
        )
    })
}

fn require_off(snapshot: &EngineSnapshot, generation: u64) -> Result<()> {
    if snapshot.state != EngineState::Off
        || snapshot.desired_mode != EngineMode::Off
        || snapshot.generation != generation
        || snapshot.config_digest.is_some()
    {
        return Err("application Off snapshot differs from the verified generation".into());
    }
    Ok(())
}

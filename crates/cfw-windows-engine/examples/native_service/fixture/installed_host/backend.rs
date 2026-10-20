use super::*;
use cfw_engine_api::{
    BackendErrorKind, EngineBackend, EngineCommandContext, NativeEngineStatus,
    SystemProxyAuthorization,
};
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use cfw_windows_engine::{backend::WindowsEngineBackend, runtime_host::InstalledDesktop};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::{
    Foundation::WAIT_OBJECT_0,
    System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Suite {
    Modes,
    EngineExit,
}
impl Suite {
    fn label(self) -> &'static str {
        match self {
            Self::Modes => "modes",
            Self::EngineExit => "engine-exit",
        }
    }
}

pub(super) fn exercise(progress: &mut Progress, suite: Suite) -> Result<serde_json::Value> {
    progress.record("backend_open", 0)?;
    let desktop = Arc::new(InstalledDesktop::open().map_err(|e| e.to_string())?);
    let diagnostics = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(desktop.paths().root.join(format!(
            "installed-validation-backend-{}.log",
            suite.label()
        )))
        .map_err(|e| e.to_string())?;
    let backend = WindowsEngineBackend::new(Arc::clone(&desktop), diagnostics);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(exercise_async(&desktop, &backend, progress, suite))
}
async fn exercise_async(
    desktop: &InstalledDesktop,
    backend: &WindowsEngineBackend,
    progress: &mut Progress,
    suite: Suite,
) -> Result<serde_json::Value> {
    if backend.runtime_platform() != cfw_engine_api::EngineRuntimePlatform::Windows
        || backend.query_status().await.map_err(|e| e.to_string())? != NativeEngineStatus::Off
    {
        return Err("installed backend did not establish initial native Off".into());
    }
    let original_proxy = desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?;
    let initial_generation = if suite == Suite::Modes { 2 } else { 4 };
    if desktop
        .generations()
        .load_lineage()
        .map_err(|e| e.to_string())?
        .generation
        != initial_generation
    {
        return Err("backend suite began with a different persisted generation".into());
    }
    let mut authorizations = Vec::new();
    if suite == Suite::Modes {
        authorizations.push(authorize_unchanged(desktop, backend, progress, 2).await?);
    }
    let profile =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .map_err(|e| e.to_string())?;
    let mut modes = Vec::new();
    let mut failure_case = None;
    let cases: &[(usize, ProjectionMode)] = match suite {
        Suite::Modes => &[
            (0, ProjectionMode::LocalProxy),
            (1, ProjectionMode::SystemProxy),
        ],
        Suite::EngineExit => &[(2, ProjectionMode::LocalProxy)],
    };
    for &(index, mode) in cases {
        let mixed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
        let controller = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
        let address = mixed.local_addr().map_err(|e| e.to_string())?;
        let controller_address = controller.local_addr().map_err(|e| e.to_string())?;
        let settings = EngineSettings {
            mixed_port: address.port(),
            controller_port: controller_address.port(),
            bypass_private_networks: false,
            ..Default::default()
        };
        let lineage = desktop
            .generations()
            .load_lineage()
            .map_err(|e| e.to_string())?;
        let generation = desktop
            .generations()
            .reserve_generation(lineage.generation)
            .map_err(|e| e.to_string())?;
        let context = EngineCommandContext {
            installation_id: lineage.session.installation_id,
            config_epoch: lineage.session.config_epoch,
            generation,
        };
        let request = checks::candidate(
            &profile,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            mode,
            &settings,
            context.clone(),
        )?;
        progress.record("backend_check", generation)?;
        backend
            .check_configuration(request.clone())
            .await
            .map_err(|e| e.to_string())?;
        progress.record("backend_check_complete", generation)?;
        if index == 0 {
            let rejected = backend
                .start_system_proxy(request.clone())
                .await
                .expect_err("different mode must be rejected");
            if rejected.kind != BackendErrorKind::ConfigurationRejected {
                return Err(format!("different mode failure changed: {rejected}"));
            }
            let before = checks::snapshot()?;
            let mut foreign = request.clone();
            foreign.context.config_epoch += 1;
            let rejected_context = foreign.context.clone();
            progress.record("backend_rejected_prepare", generation)?;
            let rejected = backend
                .start_local_proxy(foreign)
                .await
                .err()
                .ok_or("foreign epoch was accepted")?;
            progress.record("backend_rejection_received", generation)?;
            if rejected.kind != BackendErrorKind::ReplayRejected {
                return Err(format!(
                    "foreign epoch lost its native rejection: {rejected}"
                ));
            }
            let retained = backend
                .query_status()
                .await
                .err()
                .ok_or("unlaunched failure was not retained")?;
            if retained.kind != BackendErrorKind::ReplayRejected
                || backend.query_status().await.map_err(|e| e.to_string())?
                    != NativeEngineStatus::Off
                || checks::snapshot()? != before
            {
                return Err(
                    "rejected preparation could not retire against unchanged native Off".into(),
                );
            }
            backend
                .stop_local_proxy(rejected_context)
                .await
                .map_err(|e| e.to_string())?;
            if checks::snapshot()? != before {
                return Err("rejected runtime stop changed the proven Off scope".into());
            }
            progress.record("backend_rejection_retired", generation)?;
        }
        drop((mixed, controller));
        progress.record("backend_start", generation)?;
        let started = match mode {
            ProjectionMode::LocalProxy => backend.start_local_proxy(request).await,
            ProjectionMode::SystemProxy => backend.start_system_proxy(request).await,
            _ => return Err("invalid fixture proxy mode".into()),
        }
        .map_err(|e| e.to_string())?;
        progress.record("backend_ready", generation)?;
        if started.context != context
            || !started.ready
            || started.owner != cfw_engine_api::EngineOwner::WindowsUserAgent
        {
            return Err("shared backend started an unrelated runtime".into());
        }
        let active = checks::snapshot()?;
        let expected = match mode {
            ProjectionMode::LocalProxy => NativeEngineStatus::LocalProxy {
                runtime: started.clone(),
            },
            _ => NativeEngineStatus::SystemProxy {
                runtime: started.clone(),
            },
        };
        progress.record("backend_queries", generation)?;
        for _ in 0..3 {
            if backend.query_status().await.map_err(|e| e.to_string())? != expected {
                return Err("shared backend status changed its live identity".into());
            }
        }
        progress.record("backend_queries_complete", generation)?;
        if mode == ProjectionMode::SystemProxy {
            authorizations.push(authorize_unchanged(desktop, backend, progress, generation).await?);
        }
        user_agent::traffic(address)?;
        progress.record("backend_traffic_complete", generation)?;
        let mut wrong = context.clone();
        wrong.generation = wrong
            .generation
            .checked_add(1)
            .ok_or("generation overflow")?;
        let rejected = backend
            .stop_local_proxy(wrong)
            .await
            .expect_err("foreign runtime stop must fail");
        if rejected.kind != BackendErrorKind::StaleOperation {
            return Err(format!("foreign stop failure changed: {rejected}"));
        }
        if index == 2 {
            let live = backend
                .observe_runtime_for_validation()
                .await
                .map_err(|e| e.to_string())?;
            let raw = unsafe {
                OpenProcess(
                    PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
                    0,
                    live.engine_process_id,
                )
            };
            if raw.is_null() {
                return Err(error(
                    "retain native backend engine for exit counterexample",
                ));
            }
            let process = unsafe { OwnedHandle::from_raw_handle(raw) };
            // Reobserve after retaining the process object. The Agent's held
            // engine and fresh response must still identify this exact PID.
            let fresh = backend
                .observe_runtime_for_validation()
                .await
                .map_err(|e| e.to_string())?;
            if fresh.engine_process_id != live.engine_process_id || fresh.runtime != live.runtime {
                return Err("native engine changed before exit counterexample".into());
            }
            if unsafe { TerminateProcess(process.as_raw_handle(), 77) } == 0
                || unsafe { WaitForSingleObject(process.as_raw_handle(), 10000) } != WAIT_OBJECT_0
            {
                return Err(error("terminate and observe exact test engine exit"));
            }
            progress.record("backend_engine_exit", generation)?;
            let rejected = backend
                .query_status()
                .await
                .expect_err("exited real engine must not return cached Active");
            progress.record("backend_exited_query_rejected", generation)?;
            progress.record("backend_failed_stop", generation)?;
            let stop_result = backend.stop_local_proxy(context.clone()).await;
            // The first failed query may already have observed independent Off
            // and retired this owner. A subsequent exact stop can then succeed.
            let stop_outcome = match stop_result {
                Ok(()) => serde_json::json!({"status":"verified_off"}),
                Err(error) => serde_json::json!({"status":"error","error":error.to_string()}),
            };
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut retained_errors = Vec::new();
            loop {
                match backend.query_status().await {
                    Ok(NativeEngineStatus::Off) => break,
                    Ok(_) => return Err("exited engine became active again".into()),
                    Err(error) => retained_errors.push(error.to_string()),
                }
                if Instant::now() >= deadline || retained_errors.len() > 100 {
                    return Err(format!(
                        "native exit recovery did not reach verified Off: {retained_errors:?}"
                    ));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            progress.record("backend_recovery_off", generation)?;
            failure_case = Some(
                serde_json::json!({"context":context,"engine_process_id":live.engine_process_id,
                "exact_engine_exit_observed":true,"query_error":rejected.to_string(),"stop_outcome":stop_outcome,
                "recovery_errors":retained_errors,"off":checks::snapshot()?}),
            );
        } else {
            progress.record("backend_stop", generation)?;
            match mode {
                ProjectionMode::LocalProxy => backend.stop_local_proxy(context.clone()).await,
                _ => backend.stop_system_proxy(context.clone()).await,
            }
            .map_err(|e| e.to_string())?;
            // An exact repeated stop is a read of independently verified Off.
            match mode {
                ProjectionMode::LocalProxy => backend.stop_local_proxy(context.clone()).await,
                _ => backend.stop_system_proxy(context.clone()).await,
            }
            .map_err(|e| e.to_string())?;
            if backend.query_status().await.map_err(|e| e.to_string())? != NativeEngineStatus::Off {
                return Err("shared backend stop omitted native Off".into());
            }
            progress.record("backend_off", generation)?;
            modes.push(serde_json::json!({"mode":mode,"runtime":started,"active":active,"off":checks::snapshot()?,
                "http_proxy_traffic":true,"fresh_queries":3,"stale_stop_rejected":true,"idempotent_stop":true}));
        }
        if desktop
            .storage()
            .proxy()
            .snapshot()
            .map_err(|e| e.to_string())?
            != original_proxy
        {
            return Err("shared backend left changed proxy settings".into());
        }
        let _mixed = TcpListener::bind(address)
            .map_err(|e| format!("backend mixed listener remained: {e}"))?;
        let _controller = TcpListener::bind(controller_address)
            .map_err(|e| format!("backend controller remained: {e}"))?;
    }
    match suite {
        Suite::Modes => Ok(serde_json::json!({"shared_engine_backend":true,
            "unlaunched_rejection_retired":true,"modes":modes,"proxy_restored":true,
            "listeners_released":true,"authorizations":authorizations,"release_accepted":false})),
        Suite::EngineExit => {
            authorizations.push(authorize_unchanged(desktop, backend, progress, 5).await?);
            Ok(serde_json::json!({"shared_engine_backend":true,
                "failure_case":failure_case.ok_or("missing actual engine-exit case")?,
                "exited_engine_query_rejected":true,"proxy_restored":true,"listeners_released":true,
                "authorizations":authorizations,"release_accepted":false}))
        }
    }
}

async fn authorize_unchanged(
    desktop: &InstalledDesktop,
    backend: &WindowsEngineBackend,
    progress: &mut Progress,
    generation: u64,
) -> Result<serde_json::Value> {
    progress.record("backend_authorization", generation)?;
    let before = checks::snapshot()?;
    let lineage = desktop
        .generations()
        .load_lineage()
        .map_err(|e| e.to_string())?;
    let proxy = desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?;
    for restoration_only in [false, true] {
        backend
            .authorize_system_proxy(restoration_only)
            .await
            .map_err(|e| e.to_string())?;
    }
    if checks::snapshot()? != before
        || desktop
            .generations()
            .load_lineage()
            .map_err(|e| e.to_string())?
            != lineage
        || desktop
            .storage()
            .proxy()
            .snapshot()
            .map_err(|e| e.to_string())?
            != proxy
    {
        return Err("proxy authorization changed runtime, lineage or native settings".into());
    }
    progress.record("backend_authorization_complete", generation)?;
    Ok(
        serde_json::json!({"snapshot":before,"lineage":{"installation_id":lineage.session.installation_id,
        "config_epoch":lineage.session.config_epoch,"generation":lineage.generation},"activation_allowed":true,
        "restoration_allowed":true,"authority_unchanged":true,"lineage_unchanged":true,"proxy_unchanged":true}),
    )
}

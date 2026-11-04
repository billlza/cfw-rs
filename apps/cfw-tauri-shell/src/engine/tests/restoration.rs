//! The recovery's settings restoration and the system proxy authorization:
//! asking only for restoration rights, a combined mode's own capability, and
//! what each authorization outcome tells the user.

use super::*;

/// What the recovery asks the platform for, and what the platform answers.
fn restoration_answer(
    requests: &Arc<Mutex<Vec<bool>>>,
    answer: Result<(), cfw_engine_api::BackendError>,
) -> impl FnOnce(bool) -> std::future::Ready<Result<(), cfw_engine_api::BackendError>> {
    let requests = requests.clone();
    move |restoration_only| {
        requests
            .lock()
            .expect("restoration requests")
            .push(restoration_only);
        std::future::ready(answer)
    }
}

#[tokio::test]
async fn a_declined_settings_restoration_ends_the_recovery_before_it_starts() {
    use cfw_engine_api::{BackendError, BackendErrorKind as Code};
    for code in [Code::Timeout, Code::ApprovalDenied, Code::PermissionDenied] {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recoveries = Arc::new(AtomicUsize::new(0));
        let recovered = recoveries.clone();
        let outcome = crate::engine::recover_after_settings_restoration(
            restoration_answer(&requests, Err(BackendError::new(code, "the prompt"))),
            async move {
                recovered.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        let message = outcome.expect_err("a declined restoration must end the recovery");
        #[cfg(target_os = "macos")]
        {
            let expected = if code == Code::Timeout {
                "or the ProxyAgent did not reply"
            } else {
                "cancelled or denied"
            };
            assert!(message.contains(expected), "{message}");
            assert!(
                message.contains("Recover background services again"),
                "{message}"
            );
        }
        #[cfg(windows)]
        assert_eq!(
            message,
            "Restoring System Proxy settings was not authorized: the prompt. Check Windows proxy policy and the user session, then recover background services again."
        );
        assert_eq!(recoveries.load(Ordering::SeqCst), 0, "{code:?}");
        assert_eq!(*requests.lock().expect("requests"), vec![true]);
    }
}

#[tokio::test]
async fn a_granted_settings_restoration_runs_the_recovery_and_reports_its_result() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    assert_eq!(
        crate::engine::recover_after_settings_restoration(
            restoration_answer(&requests, Ok(())),
            async { Ok(()) }
        )
        .await,
        Ok(())
    );
    assert_eq!(
        crate::engine::recover_after_settings_restoration(
            restoration_answer(&requests, Ok(())),
            async { Err("the services are not registered".to_owned()) }
        )
        .await,
        Err("the services are not registered".to_owned())
    );
    // Restoration rights alone: with nothing to restore, macOS shows no prompt.
    assert_eq!(*requests.lock().expect("requests"), vec![true, true]);
}

/// Answers every rights request, records whether it asked for restoration
/// rights alone, and has no other native operation.
#[derive(Default)]
struct RestorationRightsBridge {
    requests: Mutex<Vec<bool>>,
}

impl RestorationRightsBridge {
    fn requests(&self) -> Vec<bool> {
        self.requests.lock().expect("rights requests").clone()
    }
}

impl cfw_engine_api::SystemProxyAuthorization for RestorationRightsBridge {
    fn authorize_system_proxy(
        &self,
        restoration_only: bool,
    ) -> cfw_engine_api::BackendFuture<'_, ()> {
        self.requests
            .lock()
            .expect("rights requests")
            .push(restoration_only);
        Box::pin(async { Ok(()) })
    }
}

impl cfw_engine_api::ProfileDelayBackend for RestorationRightsBridge {
    fn test_profile_delays(
        &self,
        _request: cfw_engine_api::ProfileDelayTestRequest,
    ) -> cfw_engine_api::BackendFuture<'_, Vec<cfw_engine_api::ProfileProxyDelay>> {
        panic!("a network restoration rights test must never start a latency probe")
    }
}

/// An engine whose rights requests reach `bridge`.
fn engine_with_rights_bridge(bridge: Arc<RestorationRightsBridge>) -> crate::engine::ManagedEngine {
    crate::engine::ManagedEngine {
        coordinator: endpoint_retry_coordinator(Arc::new(EndpointRetryBackend::new(0))),
        capabilities: crate::engine::EngineCapabilities {
            local_proxy: true,
            system_proxy: true,
            tunnel: true,
            tunnel_system_proxy: true,
            provider_management: true,
        },
        unavailable_reason: None,
        preflight_backend: None,
        profile_delay_backend: bridge.clone(),
        system_proxy_authorization: bridge,
        tunnel_approval: None,
        #[cfg(target_os = "macos")]
        cutover: crate::engine::cutover::CutoverPreparationGate::default(),
        maintenance: EngineMaintenanceGate::default(),
        endpoints: Arc::new(std::sync::RwLock::new(endpoint_binding(
            EngineSettings::default(),
        ))),
    }
}

/// Each integration on its own does not admit their combination: Windows
/// offers Tunnel and System Proxy separately while the combined mode is closed,
/// and the UI reads the separate capability from the status payload.
#[tokio::test]
async fn combined_mode_requires_its_own_capability() {
    let mut engine = engine_with_rights_bridge(Arc::new(RestorationRightsBridge::default()));
    engine.capabilities.tunnel_system_proxy = false;
    for mode in [
        EngineMode::LocalProxy,
        EngineMode::SystemProxy,
        EngineMode::Tunnel,
    ] {
        assert_eq!(engine.require_capability(mode), Ok(()));
    }
    assert!(
        engine
            .require_capability(EngineMode::TunnelSystemProxy)
            .is_err()
    );
    let payload = serde_json::to_value(engine.capabilities).unwrap();
    assert_eq!(payload["tunnel"], true);
    assert_eq!(payload["system_proxy"], true);
    assert_eq!(payload["tunnel_system_proxy"], false);
    engine.capabilities.tunnel_system_proxy = true;
    assert_eq!(
        engine.require_capability(EngineMode::TunnelSystemProxy),
        Ok(())
    );
}

/// "Recover background services" asks macOS for the rights to restore settings
/// alone, which shows no prompt when none are left, and runs the recovery once
/// they are granted.
#[tokio::test]
async fn background_recovery_asks_only_for_restoration_rights_then_recovers() {
    let bridge = Arc::new(RestorationRightsBridge::default());
    let engine = engine_with_rights_bridge(bridge.clone());
    let recoveries = Arc::new(AtomicUsize::new(0));
    let recovered = recoveries.clone();
    assert_eq!(
        engine
            .recover_with_restoration_rights(async move {
                recovered.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await,
        Ok(())
    );
    assert_eq!(bridge.requests(), vec![true]);
    assert_eq!(recoveries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_service_fault_before_the_restoration_leaves_the_recovery_to_repair_it() {
    use cfw_engine_api::{BackendError, BackendErrorKind as Code};
    let requests = Arc::new(Mutex::new(Vec::new()));
    let fault = || {
        restoration_answer(
            &requests,
            Err(BackendError::new(
                Code::Unavailable,
                "ProxyAgent connection-retired",
            )),
        )
    };
    assert_eq!(
        crate::engine::recover_after_settings_restoration(fault(), async { Ok(()) }).await,
        Ok(())
    );
    let failed = crate::engine::recover_after_settings_restoration(fault(), async {
        Err("the services are not registered".to_owned())
    })
    .await
    .expect_err("a failed recovery must report its cause");
    assert!(
        failed.starts_with("the services are not registered; "),
        "{failed}"
    );
    assert!(
        failed.contains("Unavailable: ProxyAgent connection-retired"),
        "{failed}"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn system_proxy_authorization_outcomes_tell_the_user_what_to_do() {
    use cfw_engine_api::BackendErrorKind as Code;
    let timed_out = crate::engine::authorization_failure_message(
        Code::Timeout,
        "The native operation timed out.",
    );
    assert!(timed_out.contains("did not get an answer"), "{timed_out}");
    assert!(
        timed_out.contains("Turn System Proxy on again"),
        "{timed_out}"
    );
    for code in [Code::ApprovalDenied, Code::PermissionDenied] {
        let denied = crate::engine::authorization_failure_message(code, "denied");
        assert!(denied.contains("cancelled or denied"), "{denied}");
        assert!(denied.contains("Turn System Proxy on again"), "{denied}");
    }
    assert_eq!(
        crate::engine::authorization_failure_message(
            Code::Unavailable,
            "signed macOS Host Bridge is not linked"
        ),
        "System Proxy authorization failed: Unavailable: signed macOS Host Bridge is not linked"
    );
}

#[test]
#[cfg(windows)]
fn system_proxy_authorization_outcomes_preserve_windows_failure_and_recovery_guidance() {
    use cfw_engine_api::BackendErrorKind as Code;
    for (code, detail) in [
        (Code::Timeout, "The native operation timed out"),
        (Code::ApprovalDenied, "denied"),
        (Code::PermissionDenied, "denied"),
        (
            Code::Unavailable,
            "installed Windows runtime is unavailable",
        ),
    ] {
        let message = crate::engine::authorization_failure_message(code, detail);
        assert_eq!(
            message,
            format!(
                "System Proxy authorization failed: {code:?}: {detail}. Check Windows proxy policy and the user session before trying again."
            )
        );
    }
}

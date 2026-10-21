//! Coordinator identity contracts. The scripted backend here is not Windows
//! service or real-network evidence; those have separate native integration gates.
use std::sync::Arc;

use cfw_engine_api::{
    EngineCommandContext, EngineMode, EngineOwner, EngineRuntimePlatform, EngineState,
    NativeEngineStatus, RuntimeIdentity,
};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

use super::support::{FakeBackend, coordinator};
use crate::{EngineCoordinatorError, EngineModeCoordinator};

const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

#[tokio::test]
async fn windows_profile_check_and_start_use_the_same_packet_configuration() {
    for mode in [EngineMode::Tunnel, EngineMode::TunnelSystemProxy] {
        let backend = Arc::new(FakeBackend::windows());
        let coordinator = coordinator(backend.clone());
        let settings = EngineSettings::default();
        coordinator
            .set_mode(
                mode,
                PROFILE.into(),
                ValidatedSingBoxProfile::direct(),
                settings.clone(),
            )
            .await
            .unwrap();
        coordinator
            .change_profile(settings, async {
                Ok(crate::ProfileChange {
                    profile_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
                    profile: ValidatedSingBoxProfile::direct(),
                    activate: true,
                    previous_profile: Some((PROFILE.into(), ValidatedSingBoxProfile::direct())),
                    commit: Box::new(|| Ok(())),
                })
            })
            .await
            .unwrap();
        let checks = backend.configuration_check_requests.lock().unwrap();
        let starts = backend.tunnel_requests();
        assert_eq!(checks.len(), 1);
        assert_eq!(starts.len(), 2);
        assert_eq!(checks[0], starts[1]);
        assert!(checks[0].config_json.contains(r#""stack":"gvisor""#));
        assert_ne!(starts[0].config_digest, starts[1].config_digest);
    }
}

#[tokio::test]
async fn windows_startup_cleanup_still_requires_independent_global_off() {
    for tunnel in [false, true] {
        for owner_survives in [false, true] {
            let backend = Arc::new(FakeBackend::windows());
            *backend.stop_leaves_owner_present.lock().unwrap() = owner_survives;
            let runtime = RuntimeIdentity {
                owner: if tunnel {
                    EngineOwner::WindowsTunnelService
                } else {
                    EngineOwner::WindowsUserAgent
                },
                context: EngineCommandContext {
                    installation_id: PROFILE.into(),
                    config_epoch: 2,
                    generation: 9,
                },
                config_digest: "a".repeat(64),
                ready: true,
            };
            backend.set_native_status(if tunnel {
                NativeEngineStatus::Tunnel { runtime }
            } else {
                NativeEngineStatus::LocalProxy { runtime }
            });
            let coordinator = EngineModeCoordinator::spawn_journal_unavailable_with(
                backend.clone(),
                "test lineage unavailable",
                std::time::Duration::from_millis(100),
                |task| {
                    tokio::spawn(task);
                },
            );
            let result = coordinator.wait_for_reconciliation().await;
            if owner_survives {
                assert!(result.is_err());
                assert!(matches!(
                    coordinator.snapshot().state,
                    EngineState::Failed { .. }
                ));
            } else {
                assert_eq!(result.unwrap().state, EngineState::Off);
            }
            assert!(
                backend.query_count() >= 2,
                "stop receipt cannot substitute for global observation"
            );
            assert_eq!(
                if tunnel {
                    backend.tunnel_stop_contexts().len()
                } else {
                    backend.proxy_stop_contexts().len()
                },
                1
            );
        }
    }
}

#[tokio::test]
async fn windows_modes_bind_platform_owners_and_preserve_exact_restart_identity() {
    let backend = Arc::new(FakeBackend::windows());
    let coordinator = coordinator(backend.clone());
    assert_eq!(
        coordinator.runtime_platform(),
        EngineRuntimePlatform::Windows
    );
    for mode in [
        EngineMode::LocalProxy,
        EngineMode::SystemProxy,
        EngineMode::Tunnel,
        EngineMode::TunnelSystemProxy,
    ] {
        let snapshot = coordinator
            .set_mode(
                mode,
                PROFILE.into(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .unwrap();
        let runtime = match &snapshot.state {
            EngineState::LocalProxyActive { runtime } | EngineState::ProxyActive { runtime } => {
                assert_eq!(runtime.owner, EngineOwner::WindowsUserAgent);
                runtime
            }
            EngineState::TunnelActive { runtime }
            | EngineState::TunnelSystemProxyActive { runtime } => {
                assert_eq!(runtime.owner, EngineOwner::WindowsTunnelService);
                let requests = backend.tunnel_requests();
                let request = requests.last().unwrap();
                assert!(request.config_json.contains(r#""stack":"gvisor""#));
                assert!(request.config_json.contains(r#""auto_route":false"#));
                assert_eq!(request.config_digest, runtime.config_digest);
                assert_eq!(
                    request.config_content_digest,
                    cfw_singbox_config::sha256_hex(request.config_json.as_bytes())
                );
                runtime
            }
            state => panic!("expected active state, got {state:?}"),
        };
        let accepted = coordinator.restart_spec().await.unwrap().unwrap();
        assert!(accepted.matches_ready_snapshot(&snapshot));
        for mutation in 0..3 {
            let mut changed = snapshot.clone();
            let changed_runtime = match &mut changed.state {
                EngineState::LocalProxyActive { runtime }
                | EngineState::ProxyActive { runtime }
                | EngineState::TunnelActive { runtime }
                | EngineState::TunnelSystemProxyActive { runtime } => runtime,
                _ => unreachable!(),
            };
            match mutation {
                0 => {
                    changed_runtime.owner = if runtime.owner == EngineOwner::WindowsUserAgent {
                        EngineOwner::ProxyAgent
                    } else {
                        EngineOwner::PacketTunnelSystemExtension
                    }
                }
                1 => {
                    changed_runtime.context.installation_id =
                        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into()
                }
                _ => changed_runtime.context.config_epoch += 1,
            }
            assert!(
                !accepted.matches_ready_snapshot(&changed),
                "restart identity mutation {mutation}"
            );
        }
    }
}

#[tokio::test]
async fn windows_start_cannot_accept_an_apple_proxy_owner() {
    let backend = Arc::new(FakeBackend::windows());
    *backend.wrong_proxy_platform.lock().unwrap() = true;
    let coordinator = coordinator(backend.clone());
    let result = coordinator
        .set_mode(
            EngineMode::LocalProxy,
            PROFILE.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await;
    assert!(matches!(
        result,
        Err(EngineCoordinatorError::RuntimeIdentityMismatch {
            expected_owner: EngineOwner::WindowsUserAgent,
            ..
        })
    ));
    assert_eq!(coordinator.snapshot().state.active_mode(), EngineMode::Off);
    assert_eq!(backend.proxy_stop_contexts().len(), 1);
}

#[tokio::test]
async fn status_reconciliation_rejects_a_foreign_platform_even_with_matching_generation_and_digest()
{
    let backend = Arc::new(FakeBackend::windows());
    let coordinator = coordinator(backend.clone());
    let snapshot = coordinator
        .set_mode(
            EngineMode::LocalProxy,
            PROFILE.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    let EngineState::LocalProxyActive { mut runtime } = snapshot.state else {
        panic!("local runtime")
    };
    runtime.owner = EngineOwner::ProxyAgent;
    backend.replace_reported_platform_for_test(false);
    assert_eq!(
        coordinator.runtime_platform(),
        EngineRuntimePlatform::Windows
    );
    assert_eq!(
        coordinator.clone().runtime_platform(),
        EngineRuntimePlatform::Windows
    );
    backend.set_native_status(NativeEngineStatus::LocalProxy { runtime });
    assert!(
        coordinator
            .set_mode(
                EngineMode::LocalProxy,
                PROFILE.into(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default()
            )
            .await
            .is_err()
    );
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
}

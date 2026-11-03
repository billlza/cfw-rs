//! Binding controller access to the exact Active runtime: its generation,
//! digest and owner.

use super::*;

#[test]
fn windows_controller_binding_accepts_the_ready_user_agent() {
    let settings = EngineSettings::default();
    let endpoints = std::sync::RwLock::new(endpoint_binding(settings));
    let active = EngineSnapshot {
        desired_mode: EngineMode::LocalProxy,
        state: EngineState::LocalProxyActive {
            runtime: RuntimeIdentity {
                owner: EngineOwner::WindowsUserAgent,
                context: EngineCommandContext {
                    installation_id: "installation".into(),
                    config_epoch: 1,
                    generation: 7,
                },
                config_digest: "digest-a".into(),
                ready: true,
            },
        },
        generation: 7,
        config_digest: Some("digest-a".into()),
    };
    record_endpoint_runtime(&endpoints, EngineRuntimePlatform::Windows, &active)
        .expect("bind the Windows controller");
    assert!(read_active_controller_access(&endpoints, 7, "digest-a").is_ok());
    let original = endpoints.read().unwrap().clone();
    assert!(record_endpoint_runtime(&endpoints, EngineRuntimePlatform::MacOs, &active).is_err());
    assert_eq!(*endpoints.read().unwrap(), original);
    record_endpoint_runtime(
        &endpoints,
        EngineRuntimePlatform::Windows,
        &EngineSnapshot::default(),
    )
    .expect("Off invalidates the controller");
    assert!(read_active_controller_access(&endpoints, 7, "digest-a").is_err());
}

#[test]
fn controller_access_is_bound_to_the_exact_active_generation_and_digest() {
    let settings = EngineSettings::default();
    let endpoints = std::sync::RwLock::new(EngineEndpointBinding {
        controller: EngineControllerAccess::resolve(settings.clone()).expect("controller"),
        cursor: EndpointCandidateCursor::from_persisted(settings).expect("cursor"),
        active: None,
    });
    assert!(read_active_controller_access(&endpoints, 7, "digest-a").is_err());

    let active = EngineSnapshot {
        desired_mode: EngineMode::SystemProxy,
        state: EngineState::ProxyActive {
            runtime: RuntimeIdentity {
                owner: EngineOwner::ProxyAgent,
                context: EngineCommandContext {
                    installation_id: "installation".into(),
                    config_epoch: 1,
                    generation: 7,
                },
                config_digest: "digest-a".into(),
                ready: true,
            },
        },
        generation: 7,
        config_digest: Some("digest-a".into()),
    };
    record_endpoint_runtime(&endpoints, EngineRuntimePlatform::MacOs, &active)
        .expect("bind active controller");
    assert!(record_endpoint_runtime(&endpoints, EngineRuntimePlatform::Windows, &active).is_err());
    assert!(read_active_controller_access(&endpoints, 7, "digest-a").is_ok());
    assert!(read_active_controller_access(&endpoints, 8, "digest-a").is_err());
    assert!(read_active_controller_access(&endpoints, 7, "digest-b").is_err());

    let expected = endpoints.read().expect("endpoint lock").clone();
    let mut replacement_settings = expected.controller.settings().clone();
    replacement_settings.controller_port += 1;
    let replacement = EngineEndpointBinding {
        controller: EngineControllerAccess::resolve(replacement_settings.clone())
            .expect("replacement controller"),
        cursor: EndpointCandidateCursor::from_persisted(replacement_settings)
            .expect("replacement cursor"),
        active: None,
    };
    let staged = StagedEndpointRebind {
        expected: expected.clone(),
        replacement: replacement.clone(),
    };
    commit_endpoint_rebind(&endpoints, staged).expect("commit endpoint CAS");
    assert!(
        read_active_controller_access(&endpoints, 7, "digest-a").is_err(),
        "an endpoint rebind invalidates the prior active identity"
    );
    assert!(
        commit_endpoint_rebind(
            &endpoints,
            StagedEndpointRebind {
                expected,
                replacement,
            },
        )
        .is_err(),
        "a stale staged endpoint binding cannot overwrite current state"
    );
}

#[test]
fn invalid_active_snapshot_cannot_bind_controller_access() {
    let settings = EngineSettings::default();
    let endpoints = std::sync::RwLock::new(EngineEndpointBinding {
        controller: EngineControllerAccess::resolve(settings.clone()).expect("controller"),
        cursor: EndpointCandidateCursor::from_persisted(settings).expect("cursor"),
        active: Some(ActiveControllerBinding {
            generation: 1,
            config_digest: "prior".into(),
        }),
    });
    let invalid = EngineSnapshot {
        desired_mode: EngineMode::SystemProxy,
        state: EngineState::ProxyActive {
            runtime: RuntimeIdentity {
                owner: EngineOwner::PacketTunnelSystemExtension,
                context: EngineCommandContext {
                    installation_id: "installation".into(),
                    config_epoch: 1,
                    generation: 2,
                },
                config_digest: "digest".into(),
                ready: true,
            },
        },
        generation: 2,
        config_digest: Some("digest".into()),
    };
    assert!(record_endpoint_runtime(&endpoints, EngineRuntimePlatform::MacOs, &invalid).is_err());
    assert!(read_active_controller_access(&endpoints, 1, "prior").is_ok());
}

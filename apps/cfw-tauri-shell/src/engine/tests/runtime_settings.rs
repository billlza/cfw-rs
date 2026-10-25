use super::*;
use cfw_application::ProfileChange;
use cfw_core::{AppPaths, SettingsStore};
use cfw_singbox_config::{EngineLogLevel, RuntimePreferences};

#[tokio::test]
async fn online_settings_publish_the_new_binding_only_after_a_successful_commit() {
    for stale_revision in [false, true] {
        let root =
            std::env::temp_dir().join(format!("cfm-runtime-transaction-{}", uuid::Uuid::new_v4()));
        let store = SettingsStore::new(AppPaths::from_app_home(root.clone()));
        let previous = store.runtime_settings::<RuntimePreferences>().unwrap();
        let backend = Arc::new(EndpointRetryBackend::new(0));
        let coordinator = endpoint_retry_coordinator(backend.clone());
        let old_settings = EngineSettings::default();
        let endpoints = Arc::new(std::sync::RwLock::new(endpoint_binding(
            old_settings.clone(),
        )));
        let profile = ValidatedSingBoxProfile::direct();
        let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let initial = coordinator
            .set_mode(
                EngineMode::LocalProxy,
                id.into(),
                profile.clone(),
                old_settings.clone(),
            )
            .await
            .unwrap();
        record_endpoint_runtime(&endpoints, coordinator.runtime_platform(), &initial).unwrap();
        let expected = endpoints.read().unwrap().clone();
        let settings = EngineSettings {
            mixed_port: 8890,
            log_level: EngineLogLevel::Debug,
            ..old_settings.clone()
        };
        let replacement = endpoint_binding(settings.clone());
        let preferences = RuntimePreferences {
            preferred_mixed_port: Some(8890),
            log_level: EngineLogLevel::Debug,
            ..RuntimePreferences::default()
        };
        if stale_revision {
            let external = RuntimePreferences {
                tunnel_mtu: 1400,
                ..RuntimePreferences::default()
            };
            store
                .compare_and_swap_runtime_settings(None, &external)
                .unwrap();
        }
        let commit_store = store.clone();
        let commit_endpoints = endpoints.clone();
        let result = coordinator
            .change_profile(settings, async move {
                Ok(ProfileChange {
                    profile_id: id.into(),
                    profile,
                    activate: true,
                    previous_profile: None,
                    commit: Box::new(move || {
                        super::super::runtime_settings::commit_runtime_settings(
                            &commit_endpoints,
                            &expected,
                            replacement,
                            &commit_store,
                            &previous,
                            &preferences,
                        )
                    }),
                })
            })
            .await;
        let current = coordinator.snapshot();
        record_endpoint_runtime(&endpoints, coordinator.runtime_platform(), &current).unwrap();
        if stale_revision {
            assert!(result.unwrap_err().to_string().contains("restored"));
            assert_eq!(
                endpoints.read().unwrap().controller.settings(),
                &old_settings
            );
            assert_eq!(backend.starts(), vec![(1, 7890), (2, 8890), (3, 7890)]);
            assert_eq!(
                store
                    .runtime_settings::<RuntimePreferences>()
                    .unwrap()
                    .settings
                    .tunnel_mtu,
                1400,
                "a conflicting writer is never overwritten"
            );
        } else {
            result.unwrap();
            assert_eq!(
                endpoints.read().unwrap().controller.settings().mixed_port,
                8890
            );
            assert_eq!(backend.starts(), vec![(1, 7890), (2, 8890)]);
            assert_eq!(
                store
                    .runtime_settings::<RuntimePreferences>()
                    .unwrap()
                    .settings
                    .log_level,
                EngineLogLevel::Debug
            );
        }
        assert!(
            matches!(current.state, EngineState::LocalProxyActive {ref runtime} if runtime.ready)
        );
        assert!(
            read_active_controller_access(
                &endpoints,
                current.generation,
                current.config_digest.as_deref().unwrap()
            )
            .is_ok()
        );
        coordinator.shutdown().await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn a_mainland_switch_whose_rule_sets_cannot_download_restores_the_previous_runtime() {
    for failure in [
        cfw_engine_api::BackendErrorKind::SystemProxyRuntimeFailed,
        cfw_engine_api::BackendErrorKind::Timeout,
    ] {
        let root =
            std::env::temp_dir().join(format!("cfm-mainland-transaction-{}", uuid::Uuid::new_v4()));
        let store = SettingsStore::new(AppPaths::from_app_home(root.clone()));
        let previous = store.runtime_settings::<RuntimePreferences>().unwrap();
        let mut backend = EndpointRetryBackend::new(0);
        backend.rule_set_start_failure = Some(failure);
        let backend = Arc::new(backend);
        let coordinator = endpoint_retry_coordinator(backend.clone());
        let old_settings = EngineSettings::default();
        let endpoints = Arc::new(std::sync::RwLock::new(endpoint_binding(
            old_settings.clone(),
        )));
        // Two remote outbounds and no rules: the switch applies, and only it
        // adds rule sets.
        let profile = ValidatedSingBoxProfile::parse(
            r#"{"outbounds":[
                {"type":"socks5","tag":"first","server":"first.example.com","server_port":1080},
                {"type":"socks5","tag":"second","server":"second.example.com","server_port":1080}]}"#,
        )
        .unwrap();
        let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let initial = coordinator
            .set_mode(
                EngineMode::LocalProxy,
                id.into(),
                profile.clone(),
                old_settings.clone(),
            )
            .await
            .unwrap();
        record_endpoint_runtime(&endpoints, coordinator.runtime_platform(), &initial).unwrap();
        let expected = endpoints.read().unwrap().clone();
        let settings = EngineSettings {
            mainland_china_direct: true,
            ..old_settings.clone()
        };
        let replacement = endpoint_binding(settings.clone());
        let preferences = RuntimePreferences {
            mainland_china_direct: true,
            ..RuntimePreferences::default()
        };
        let commit_store = store.clone();
        let commit_endpoints = endpoints.clone();
        let result = coordinator
            .change_profile(settings, async move {
                Ok(ProfileChange {
                    profile_id: id.into(),
                    profile,
                    activate: true,
                    previous_profile: None,
                    commit: Box::new(move || {
                        super::super::runtime_settings::commit_runtime_settings(
                            &commit_endpoints,
                            &expected,
                            replacement,
                            &commit_store,
                            &previous,
                            &preferences,
                        )
                    }),
                })
            })
            .await;
        let current = coordinator.snapshot();
        record_endpoint_runtime(&endpoints, coordinator.runtime_platform(), &current).unwrap();
        let error = result.unwrap_err().to_string();
        assert!(error.contains("rule-set"), "{failure:?}: {error}");
        assert!(error.contains("restored"), "{failure:?}: {error}");
        assert!(
            !endpoints
                .read()
                .unwrap()
                .controller
                .settings()
                .mainland_china_direct,
            "{failure:?}"
        );
        assert_eq!(
            backend.starts(),
            vec![(1, 7890), (2, 7890), (3, 7890)],
            "{failure:?}"
        );
        let stored = store.runtime_settings::<RuntimePreferences>().unwrap();
        assert!(!stored.settings.mainland_china_direct, "{failure:?}");
        assert_eq!(stored.revision, None, "{failure:?}: nothing was written");
        assert!(
            matches!(current.state, EngineState::LocalProxyActive {ref runtime} if runtime.ready),
            "{failure:?}"
        );
        coordinator.shutdown().await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

/// Turned on while the engine was Off, the switch is saved; a start whose
/// rule sets cannot be downloaded then fails with that cause and leaves no
/// runtime, instead of serving without the mainland rules.
#[tokio::test]
async fn a_start_whose_mainland_rule_sets_cannot_download_fails_and_leaves_no_runtime() {
    let mut backend = EndpointRetryBackend::new(0);
    backend.rule_set_start_failure =
        Some(cfw_engine_api::BackendErrorKind::SystemProxyRuntimeFailed);
    let backend = Arc::new(backend);
    let coordinator = endpoint_retry_coordinator(backend.clone());
    let profile = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[
            {"type":"socks5","tag":"first","server":"first.example.com","server_port":1080},
            {"type":"socks5","tag":"second","server":"second.example.com","server_port":1080}]}"#,
    )
    .unwrap();
    let settings = EngineSettings {
        mainland_china_direct: true,
        ..EngineSettings::default()
    };
    let error = coordinator
        .set_mode(
            EngineMode::LocalProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            profile,
            settings,
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("rule-set"), "{error}");
    assert_eq!(backend.starts(), vec![(1, 7890)]);
    let current = coordinator.snapshot();
    assert!(
        matches!(
            current.state,
            EngineState::Failed { ref error, recheck_pending: false, .. } if error.contains("rule-set")
        ),
        "{:?}",
        current.state
    );
    assert_eq!(current.state.active_mode(), EngineMode::Off);
    coordinator.shutdown().await.unwrap();
}

/// While a cutover journal governs startup, its cleanup checks the running
/// engine against the journal's settings and the next launch starts from
/// them: a committed preference would block the cleanup and be reverted on
/// relaunch while the saved preferences, and the settings page, still showed
/// it. The commit is refused instead, and nothing changes. Only the Mac has
/// such a journal.
#[cfg(target_os = "macos")]
#[test]
fn settings_are_not_committed_while_a_cutover_journal_governs_startup() {
    let root = tempfile::tempdir().expect("temporary app home");
    let store = SettingsStore::new(AppPaths::from_app_home(root.path()));
    let journal_settings = EngineSettings::default();
    crate::legacy::write_journal_governing_startup(
        &store.paths().app_home,
        journal_settings.clone(),
    );
    let previous = store.runtime_settings::<RuntimePreferences>().unwrap();
    let endpoints = std::sync::RwLock::new(endpoint_binding(journal_settings.clone()));
    let expected = endpoints.read().unwrap().clone();
    let preferences = RuntimePreferences {
        log_level: EngineLogLevel::Debug,
        ..RuntimePreferences::default()
    };
    let replacement = endpoint_binding(EngineSettings {
        log_level: EngineLogLevel::Debug,
        ..journal_settings.clone()
    });
    let error = super::super::runtime_settings::commit_runtime_settings(
        &endpoints,
        &expected,
        replacement,
        &store,
        &previous,
        &preferences,
    )
    .expect_err("a preference cannot be committed while the journal governs startup");
    assert!(error.contains("legacy cleanup"), "{error}");
    let saved = store.runtime_settings::<RuntimePreferences>().unwrap();
    assert_eq!(saved.revision, previous.revision);
    assert_eq!(saved.settings, previous.settings);
    assert_eq!(
        endpoints.read().unwrap().controller.settings(),
        &journal_settings
    );
}

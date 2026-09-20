use super::*;
use cfw_application::ProfileChange;
use cfw_core::{MacOsAppPaths, SettingsStore};
use cfw_singbox_config::{EngineLogLevel, RuntimePreferences};

#[tokio::test]
async fn online_settings_publish_the_new_binding_only_after_a_successful_commit() {
    for stale_revision in [false, true] {
        let root =
            std::env::temp_dir().join(format!("cfm-runtime-transaction-{}", uuid::Uuid::new_v4()));
        let store = SettingsStore::new(MacOsAppPaths::from_app_home(root.clone()));
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
        record_endpoint_runtime(&endpoints, &initial).unwrap();
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
        record_endpoint_runtime(&endpoints, &current).unwrap();
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

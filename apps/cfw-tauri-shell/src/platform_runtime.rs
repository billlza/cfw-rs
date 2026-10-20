//! Platform-owned services for the shared desktop. Preparation performs I/O on
//! the startup worker but leaves the coordinator task unstarted until the
//! application lifecycle admits it.
use std::{path::Path, sync::Arc};

use cfw_application::{CoordinatorTask, EngineModeCoordinator};
use cfw_engine_api::{
    CredentialVaultProvisioner, CutoverPreflightBackend, EngineBackend, EngineGenerationStore,
    ProfileDelayBackend, SystemProxyAuthorization,
};

pub(crate) struct PlatformRuntime {
    pub(crate) credentials: Arc<dyn CredentialVaultProvisioner>,
    pub(crate) backend: Arc<dyn EngineBackend>,
    pub(crate) authorization: Arc<dyn SystemProxyAuthorization>,
    pub(crate) probes: Arc<dyn ProfileDelayBackend>,
    pub(crate) legacy_preflight: Option<Arc<dyn CutoverPreflightBackend>>,
    pub(crate) proxy_available: bool,
    pub(crate) tunnel_available: bool,
    pub(crate) unavailable_reason: Option<String>,
    generations: Result<Arc<dyn EngineGenerationStore>, String>,
    operation_timeout: std::time::Duration,
}

pub(crate) struct PreparedRuntime {
    pub(crate) services: PlatformRuntime,
    pub(crate) coordinator: EngineModeCoordinator,
    pub(crate) task: CoordinatorTask,
}

impl PlatformRuntime {
    pub(crate) fn prepare(mut self) -> Result<PreparedRuntime, String> {
        let mut task = None;
        let persisted = match &self.generations {
            Ok(generations) => EngineModeCoordinator::spawn_persisted_with(
                Arc::clone(&self.backend),
                Arc::clone(generations),
                self.operation_timeout,
                |value| task = Some(value),
            ),
            Err(error) => Err(cfw_application::EngineCoordinatorError::Journal(
                error.clone(),
            )),
        };
        let coordinator = match persisted {
            Ok(coordinator) => coordinator,
            Err(error) => {
                let reason = format!("authoritative engine lineage is unavailable: {error}");
                self.proxy_available = false;
                self.tunnel_available = false;
                self.unavailable_reason = Some(reason.clone());
                EngineModeCoordinator::spawn_journal_unavailable_with(
                    Arc::clone(&self.backend),
                    reason,
                    self.operation_timeout,
                    |value| task = Some(value),
                )
            }
        };
        Ok(PreparedRuntime {
            services: self,
            coordinator,
            task: task.ok_or("engine preparation produced no coordinator task")?,
        })
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use cfw_apple_network::{AppleNetworkBackend, MissingNativeBridge, NativeFrameworkBridge};
    use cfw_engine_api::{EngineLineage, EngineSessionIdentity, EngineState};

    struct Lineage;
    impl EngineGenerationStore for Lineage {
        fn load(&self) -> Result<EngineLineage, String> {
            Ok(EngineLineage {
                session: EngineSessionIdentity {
                    installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                    config_epoch: 1,
                },
                generation: 12,
            })
        }
        fn reserve_next(&self, _: u64) -> Result<u64, String> {
            panic!("preparation must never allocate a runtime generation")
        }
    }

    fn services(generations: Result<Arc<dyn EngineGenerationStore>, String>) -> PlatformRuntime {
        let backend = Arc::new(AppleNetworkBackend::new(MissingNativeBridge));
        // These ports are retained but never invoked by preparation.
        let bridge = Arc::new(NativeFrameworkBridge::load());
        PlatformRuntime {
            credentials: bridge.clone(),
            backend: backend.clone(),
            authorization: backend.clone(),
            probes: bridge,
            legacy_preflight: Some(backend),
            proxy_available: true,
            tunnel_available: true,
            unavailable_reason: None,
            generations,
            operation_timeout: std::time::Duration::from_secs(1),
        }
    }

    #[test]
    fn preparation_retains_lineage_without_publishing_off_or_starting_the_actor() {
        let prepared = services(Ok(Arc::new(Lineage))).prepare().unwrap();
        assert_eq!(prepared.coordinator.snapshot().generation, 12);
        assert!(matches!(
            prepared.coordinator.snapshot().state,
            EngineState::Failed { .. }
        ));
        assert!(prepared.services.proxy_available);
        assert!(prepared.services.tunnel_available);
        assert!(prepared.services.unavailable_reason.is_none());
        // Dropping an unadmitted task must remain possible outside a Tokio runtime.
        drop(prepared.task);
    }

    #[test]
    fn lineage_failure_closes_every_runtime_capability_and_remains_observable() {
        let prepared = services(Err("lineage access denied".into()))
            .prepare()
            .unwrap();
        assert!(!prepared.services.proxy_available);
        assert!(!prepared.services.tunnel_available);
        assert!(
            prepared
                .services
                .unavailable_reason
                .as_deref()
                .unwrap()
                .contains("lineage access denied")
        );
        assert!(matches!(
            prepared.coordinator.snapshot().state,
            EngineState::Failed { .. }
        ));
        drop(prepared.task);
    }
}

#[cfg(target_os = "macos")]
impl PlatformRuntime {
    pub(crate) fn load(app_home: &Path) -> Result<Self, String> {
        use cfw_apple_network::{
            AppleNetworkBackend, KeychainEngineGenerationStore, NATIVE_BRIDGE_OUTER_WATCHDOG,
            NativeFrameworkBridge,
        };
        let bridge = NativeFrameworkBridge::load();
        let available = bridge.is_available();
        let unavailable_reason = bridge.unavailable_reason().map(ToOwned::to_owned);
        let backend = Arc::new(AppleNetworkBackend::new(bridge.clone()));
        Ok(Self {
            credentials: Arc::new(bridge.clone()),
            backend: backend.clone(),
            authorization: backend.clone(),
            probes: Arc::new(bridge),
            legacy_preflight: Some(backend),
            proxy_available: available,
            tunnel_available: available,
            unavailable_reason,
            generations: KeychainEngineGenerationStore::new(app_home.join("engine"))
                .map(|store| Arc::new(store) as Arc<dyn EngineGenerationStore>)
                .map_err(|error| error.to_string()),
            operation_timeout: NATIVE_BRIDGE_OUTER_WATCHDOG,
        })
    }
}

#[cfg(windows)]
impl PlatformRuntime {
    pub(crate) fn load(app_home: &Path) -> Result<Self, String> {
        use cfw_windows_engine::{backend::WindowsEngineBackend, runtime_host::InstalledDesktop};
        // Installation, service and credential identities come exclusively from
        // the protected installed manifest. app_home selects only diagnostics.
        let desktop = Arc::new(InstalledDesktop::open().map_err(|error| error.to_string())?);
        let directory = cfw_windows_storage::PrivateDirectory::open_or_create(
            &app_home.join("logs").join("native"),
        )
        .map_err(|error| error.to_string())?;
        let diagnostics = directory
            .write()
            .and_then(|mut transaction| {
                transaction.create_private_output(&format!("runtime-{}.log", uuid::Uuid::new_v4()))
            })
            .map_err(|error| format!("native diagnostics are unavailable: {error}"))?;
        let backend = Arc::new(WindowsEngineBackend::new(Arc::clone(&desktop), diagnostics));
        Ok(Self {
            credentials: Arc::new(desktop.credentials().clone()),
            generations: Ok(Arc::new(desktop.generations().clone())),
            backend: backend.clone(),
            authorization: backend.clone(),
            probes: backend,
            // The CFM legacy handoff attestation is not a Windows capability.
            // Absence is explicit; callers must reject before any migration.
            legacy_preflight: None,
            proxy_available: true,
            tunnel_available: false,
            unavailable_reason: None,
            operation_timeout: cfw_windows_engine::backend::OUTER_WATCHDOG,
        })
    }
}

use serde::Serialize;
use tauri::AppHandle;

#[derive(Serialize)]
pub(crate) struct InstallationRecoveryOutcome {
    recovered: bool,
    requires_restart: bool,
    error: Option<String>,
}

/// No target identity, epoch, or authorization decision is accepted from IPC.
#[tauri::command]
pub(crate) async fn recover_installation_identity(
    app: AppHandle,
) -> Result<InstallationRecoveryOutcome, String> {
    #[cfg(target_os = "macos")]
    {
        use cfw_apple_network::{KeychainEngineGenerationStore, NativeFrameworkBridge};
        use cfw_engine_api::EngineGenerationStore;
        use tauri::Manager;

        if crate::lifecycle::identity_recovery_requires_restart(&app) {
            return Ok(InstallationRecoveryOutcome {
                recovered: false,
                requires_restart: true,
                error: Some("Restart the application before attempting another recovery.".into()),
            });
        }
        let mut lifecycle = crate::lifecycle::begin_identity_recovery(&app)?;
        let engine = app.state::<crate::engine::ManagedEngine>();
        let maintenance = engine
            .reserve_maintenance()
            .map_err(|error| error.to_string())?;
        if !engine.is_off_under(&maintenance) {
            return Err("Stop the engine before recovering its installation identity.".into());
        }
        let store = KeychainEngineGenerationStore::new(
            crate::settings_store()?.paths().app_home.join("engine"),
        )
        .map_err(|error| error.to_string())?;
        let baseline = store.load()?;
        let identity = NativeFrameworkBridge::load()
            .authorize_installation_recovery()
            .await
            .map_err(|error| format!("{:?}: {}", error.code, error.message))?
            .ok_or("This Mac has no enrolled installation identity to recover. Try starting the engine normally.")?;

        crate::lifecycle::prepare_identity_recovery_exit(&app, &mut lifecycle, maintenance).await?;
        // No await between retiring the old session and resolving the atomic
        // write. Failure retains maintenance: an ambiguous write requires a
        // restart to reload Keychain authority, never a return to stale memory.
        match store.recover_installation(
            &baseline,
            identity.installation_id,
            identity.accepted_epoch,
        ) {
            Ok(_) => Ok(InstallationRecoveryOutcome {
                recovered: true,
                requires_restart: true,
                error: None,
            }),
            Err(error) => {
                eprintln!("installation identity recovery failed; restart is required: {error}");
                Ok(InstallationRecoveryOutcome {
                    recovered: false,
                    requires_restart: true,
                    error: Some(error.to_string()),
                })
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        Err("Installation identity recovery is available only on macOS.".into())
    }
}

#[tauri::command]
pub(crate) fn restart_after_identity_recovery(app: AppHandle) -> Result<(), String> {
    if !crate::lifecycle::identity_recovery_requires_restart(&app) {
        return Err("No installation identity recovery is awaiting restart.".into());
    }
    app.restart();
}

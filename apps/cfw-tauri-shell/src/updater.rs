mod contract;
mod error;
mod metadata;
mod state;

use semver::Version;
use tauri::{AppHandle, Emitter, Manager};

use crate::commands::open_trusted_external_url;
use contract::UpdateAuthorization;
use error::{Result, UpdateError};
use metadata::check_bounded_update;
pub(crate) use state::UpdaterSecurityState;

const RELEASE_PAGE_PREFIX: &str = "https://github.com/billlza/cfw-rs/releases/tag/v";

#[tauri::command]
pub(crate) async fn check_for_updates(
    app: AppHandle,
) -> std::result::Result<serde_json::Value, String> {
    check_for_updates_inner(app)
        .await
        .map_err(|error| error.to_string())
}

async fn check_for_updates_inner(app: AppHandle) -> Result<serde_json::Value> {
    let security = app.state::<UpdaterSecurityState>();
    let _serialized_check = security.try_serialize_checks()?;
    security.clear_authorization()?;
    let update = check_bounded_update().await?;
    let payload = match update {
        Some(update) => {
            security.authorize(update.authorization.clone())?;
            serde_json::json!({
                "available": true,
                "current": env!("CARGO_PKG_VERSION"),
                "version": update.authorization.version,
                "notes": update.notes,
                "date": update.publication_date,
            })
        }
        None => serde_json::json!({
            "available": false,
            "current": env!("CARGO_PKG_VERSION"),
        }),
    };
    if app.emit("cfw://update-available", payload.clone()).is_err() {
        security.clear_authorization()?;
        return Err(UpdateError::ProgressEvent);
    }
    Ok(payload)
}

/// Opens the exact GitHub release page authorized by the update metadata.
///
/// v0.4.0 deliberately does not replace its own application bundle: the bundle
/// owns an SMAppService Agent and Daemon, and an in-process swap without a
/// crash-safe unregister/register transaction can leave launchd executing the
/// previous helpers. The signed DMG remains the supported installation path.
#[tauri::command]
pub(crate) async fn open_available_update(
    app: AppHandle,
    expected_version: String,
) -> std::result::Result<serde_json::Value, String> {
    open_available_update_inner(app, expected_version)
        .await
        .map_err(|error| error.to_string())
}

async fn open_available_update_inner(
    app: AppHandle,
    expected_version: String,
) -> Result<serde_json::Value> {
    let security = app.state::<UpdaterSecurityState>();
    let _serialized_check = security.try_serialize_checks()?;
    let authorized = security.authorization(&expected_version)?;
    let update = match check_bounded_update().await {
        Ok(Some(update)) => update,
        Ok(None) => {
            security.clear_authorization()?;
            return Err(UpdateError::AuthorizationChanged);
        }
        Err(error) => {
            security.clear_authorization()?;
            return Err(error);
        }
    };
    let version = update.authorization.version.clone();
    let release_url = release_page_url(&update.authorization)?;

    // Validate and consume atomically before the external side effect. A
    // mismatch or failed opener therefore requires a fresh check and can never
    // replay metadata that changed after it was presented.
    security.consume_if_current(&authorized, &update.authorization)?;
    open_trusted_external_url(&release_url).map_err(|_| UpdateError::OpenReleasePage)?;
    Ok(serde_json::json!({
        "opened": true,
        "installed": false,
        "version": version,
    }))
}

fn release_page_url(authorization: &UpdateAuthorization) -> Result<String> {
    let parsed =
        Version::parse(&authorization.version).map_err(|_| UpdateError::InvalidReleaseVersion)?;
    if parsed.to_string() != authorization.version {
        return Err(UpdateError::InvalidReleaseVersion);
    }
    Ok(format!("{RELEASE_PAGE_PREFIX}{}", authorization.version))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization(version: &str) -> UpdateAuthorization {
        UpdateAuthorization {
            version: version.to_owned(),
            archive_name: format!("Clash.for.Mac_{version}_aarch64.app.tar.gz"),
            download_url: format!(
                "https://github.com/billlza/cfw-rs/releases/download/v{version}/archive.tar.gz"
            ),
            signature: "signature".to_owned(),
        }
    }

    #[test]
    fn release_page_is_derived_only_from_a_canonical_version() {
        assert_eq!(
            release_page_url(&authorization("0.4.1")).expect("canonical release"),
            "https://github.com/billlza/cfw-rs/releases/tag/v0.4.1"
        );
        for rejected in ["01.4.1", "0.4", "0.4.1+build.1/"] {
            assert!(
                release_page_url(&authorization(rejected)).is_err(),
                "accepted unsafe release version {rejected:?}"
            );
        }
    }
}

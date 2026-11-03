//! Checking for an update, the installation it offers, and opening or
//! rechecking the release it presented.

use super::*;

pub(super) async fn check_for_updates_inner(app: AppHandle) -> Result<serde_json::Value> {
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
                "install": install_support(security.is_rejected(&update.authorization)?),
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

/// Whether this installation can install the presented release itself, so
/// the renderer offers the in-app installation only where it can succeed.
pub(super) fn install_support(release_rejected: bool) -> serde_json::Value {
    let refusal = if release_rejected {
        Some(UpdateError::ReleaseRejected.failure().code)
    } else {
        admission_refusal().err().map(|error| error.failure().code)
    };
    match refusal {
        None => serde_json::json!({ "supported": true }),
        Some(code) => serde_json::json!({ "supported": false, "code": code }),
    }
}

/// Everything that refuses an installation before anything is downloaded:
/// the running bundle's identity and location, and the volume the staged
/// release would have to share with it.
pub(super) fn admission_refusal() -> Result<()> {
    admit_running_installation()?;
    #[cfg(target_os = "macos")]
    if !staging::on_installed_volume(&app_home()?, ReleaseSignedComponent::Application.path())? {
        return Err(InstallAdmissionError::StagingVolumeMismatch.into());
    }
    Ok(())
}

pub(super) async fn open_available_update_inner(
    app: AppHandle,
    expected_version: String,
) -> Result<serde_json::Value> {
    let security = app.state::<UpdaterSecurityState>();
    let update = recheck_presented_update(&security, &expected_version).await?;
    if security.is_rejected(&update)? {
        // Its download page offers the same release that failed authentication.
        return Err(UpdateError::ReleaseRejected);
    }
    let release_url = release_page_url(&update)?;
    open_trusted_external_url(&release_url)
        .await
        .map_err(|_| UpdateError::OpenReleasePage)?;
    Ok(serde_json::json!({
        "opened": true,
        "installed": false,
        "version": update.version,
    }))
}

/// Confirms that the release the user was shown is still the published one
/// and consumes the authorization. Every action therefore needs a fresh check
/// and can never replay metadata that changed after it was presented.
pub(super) async fn recheck_presented_update(
    security: &UpdaterSecurityState,
    expected_version: &str,
) -> Result<UpdateAuthorization> {
    let _serialized_check = security.try_serialize_checks()?;
    let authorized = security.authorization(expected_version)?;
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
    security.consume_if_current(&authorized, &update.authorization)?;
    Ok(update.authorization)
}

pub(super) fn release_page_url(authorization: &UpdateAuthorization) -> Result<String> {
    contract::target()?
        .release_page_url(&authorization.version)
        .map_err(|_| UpdateError::InvalidReleaseVersion)
}

//! The real installed inspector from a medium-integrity, non-admin Desktop.
use super::*;
use cfw_windows_engine::{
    Error as EngineError,
    runtime_host::{InstalledRuntime, MANIFEST_FILE},
    update_package::{MAX_PACKAGE_BYTES, PackageError, UpdateStaging, WorkerFailureCategory},
};
use std::io::Read as _;
use uuid::Uuid;

#[path = "../../../../../apps/cfw-tauri-shell/src/updater/windows_staged.rs"]
mod windows_staged;

pub(super) fn observe() -> Result<serde_json::Value> {
    let native = restricted::require_medium_user_context()?;
    let installed = InstalledRuntime::open().map_err(|e| e.to_string())?;
    installed
        .require_desktop_process()
        .map_err(|e| e.to_string())?;
    let release = installed.release();
    let original = installed.snapshot();
    if release.version != "0.5.0" || release.build != 1 {
        return Err("unexpected protected installed release".into());
    }
    let image = std::env::current_exe().map_err(|e| e.to_string())?;
    let manifest = image
        .parent()
        .ok_or("missing installed Desktop parent")?
        .join(MANIFEST_FILE);
    match std::fs::OpenOptions::new().write(true).open(manifest) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
        Err(error) => {
            return Err(format!(
                "installed manifest access failed unexpectedly: {error}"
            ));
        }
        Ok(_) => return Err("ordinary Desktop can overwrite the installation manifest".into()),
    }
    let fixtures = PathBuf::from(
        std::env::var_os("CFW_NATIVE_PACKAGE_FIXTURES").ok_or("missing package fixtures")?,
    );
    let receipts = PathBuf::from(
        std::env::var_os("CFW_NATIVE_SERVICE_RECEIPTS").ok_or("missing update receipts")?,
    );
    if !fixtures.is_absolute() || !receipts.is_absolute() {
        return Err("package fixture paths must be absolute".into());
    }
    let candidate = fixtures.join("有效 安装包.msi");
    let staging_home = receipts.join("staging-home");
    let staging =
        UpdateStaging::create(&staging_home, Uuid::new_v4()).map_err(|e| e.to_string())?;
    let mut input = std::fs::File::open(&candidate).map_err(|e| e.to_string())?;
    let mut output = staging
        .directory()
        .begin_stream(
            "package.msi",
            ".package.copy.tmp",
            MAX_PACKAGE_BYTES as usize,
        )
        .map_err(|e| e.to_string())?;
    let mut chunk = [0; 32 * 1024];
    loop {
        let count = input.read(&mut chunk).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        output
            .write_chunk(&chunk[..count])
            .map_err(|e| e.to_string())?;
    }
    // A bounded copy of the signed local test fixture, not a substitute for
    // the product download's separate release and Minisign authorization.
    output.commit().map_err(|e| e.to_string())?;
    let staged_candidate = staging.package();
    let package = installed
        .package_inspector()
        .map_err(|e| e.to_string())?
        .inspect(
            &staged_candidate,
            "0.5.0",
            staging.root(),
            Duration::from_secs(30),
            || false,
        )
        .map_err(|e| e.to_string())?;
    if package.identity().build != 2
        || package.identity().version != "0.5.0"
        || package.sha256() != digest(&candidate)?
        || package.sha256() != digest(&staged_candidate)?
        || package.publisher().spki_sha256() == [0; 32]
    {
        return Err("ordinary Desktop lost the signed package identity".into());
    }
    let signature_key = package.publisher().spki_sha256();
    // These are retained claims, not Minisign proof. This fixture exercises
    // native inspection/custody; the GUI separately authenticates release bytes.
    let target = cfw_core::update::ReleaseTarget::WindowsX64;
    let archive_name = target.archive_name(&package.identity().version);
    let authorization = cfw_core::update::UpdateAuthorization {
        version: package.identity().version.clone(),
        download_url: target.download_url(&package.identity().version, &archive_name),
        archive_name,
        signature: "unverified-claim-outside-this-native-inspection-fixture".into(),
    };
    let resources = windows_staged::WindowsStagedResources::new(
        staging,
        package,
        authorization.clone(),
        original.clone(),
    )
    .map_err(|e| e.to_string())?;
    if resources.authorization != authorization || resources.original != original {
        return Err("staged desktop resources changed the retained release expectations".into());
    }
    // The actual desktop owner must retain both the native candidate and the
    // lifecycle lease while it waits for install/cancel. A path-only state
    // would let either operation below replace or remove verified bytes.
    match std::fs::OpenOptions::new()
        .write(true)
        .open(&staged_candidate)
    {
        Err(error) if error.raw_os_error() == Some(32) => {}
        Err(error) => return Err(format!("staged write failed for another reason: {error}")),
        Ok(_) => return Err("staged desktop candidate allowed writes".into()),
    }
    match std::fs::rename(
        &staged_candidate,
        staged_candidate.with_extension("replaced"),
    ) {
        Err(error) if error.raw_os_error() == Some(32) => {}
        Err(error) => return Err(format!("staged rename failed for another reason: {error}")),
        Ok(()) => return Err("staged desktop candidate allowed replacement".into()),
    }
    if !matches!(
        UpdateStaging::recover(&staging_home),
        Err(cfw_windows_engine::update_package::StagingError::Storage {
            operation: "acquire lifecycle lease",
            source: cfw_windows_storage::Error::Busy,
        })
    ) {
        return Err("staged desktop resources did not retain the lifecycle lease".into());
    }
    resources.discard().map_err(|e| e.to_string())?;
    if staged_candidate.try_exists().map_err(|e| e.to_string())?
        || UpdateStaging::recover(&staging_home).map_err(|e| e.to_string())? != 0
    {
        return Err("ordinary Desktop left a staged package after cleanup".into());
    }
    std::fs::remove_dir_all(&staging_home).map_err(|e| e.to_string())?;
    let inspector = InstalledRuntime::open()
        .map_err(|e| e.to_string())?
        .package_inspector()
        .map_err(|e| e.to_string())?;
    match inspector.inspect(
        &fixtures.join("other-publisher.msi"),
        "0.5.0",
        &receipts.join("rejection"),
        Duration::from_secs(30),
        || false,
    ) {
        Err(PackageError::WorkerRejected {
            category: WorkerFailureCategory::Authenticity,
            ..
        }) => {}
        Err(error) => {
            return Err(format!(
                "ordinary Desktop returned the wrong rejection: {error}"
            ));
        }
        Ok(_) => return Err("ordinary Desktop accepted another publisher".into()),
    }
    let cancelled_directory = receipts.join("cancelled");
    let inspector = InstalledRuntime::open()
        .map_err(|e| e.to_string())?
        .package_inspector()
        .map_err(|e| e.to_string())?;
    if !matches!(
        inspector.inspect(
            &candidate,
            "0.5.0",
            &cancelled_directory,
            Duration::from_secs(30),
            || true
        ),
        Err(PackageError::File(EngineError::Cancelled))
    ) || cancelled_directory.exists()
    {
        return Err("ordinary Desktop cancellation created a worker or changed category".into());
    }
    let after = restricted::require_medium_user_context()?;
    if after.identity() != native.identity() {
        return Err("Desktop identity changed during package inspection".into());
    }
    Ok(serde_json::json!({
        "medium_integrity": true, "administrator_member": false,
        "installed_desktop_identity": true, "protected_manifest_write_denied": true,
        "signed_msi_verified": true, "different_publisher_rejected": true,
        "private_staged_copy_inspected": true, "staging_cleanup_observed": true,
        "desktop_staging_owner_retained": true,
        "precreation_cancellation_observed": true, "release": release,
        "publisher_spki_sha256": signature_key,
        "pid": native.process_id(), "creation_filetime": native.identity().process_creation_time(),
        "service_started": false, "installer_exercised": false,
    }))
}

//! Native resources retained while a verified MSI is offered to the user.
use cfw_core::update::UpdateAuthorization;
use cfw_windows_engine::runtime_host::InstallationSnapshot;
use cfw_windows_engine::update_package::{InspectedMsi, PackageError, StagingError, UpdateStaging};

pub(crate) struct WindowsStagedResources {
    // Drop order matters: release the candidate's non-delete-shared handles
    // before the namespace lease can be acquired by cleanup or recovery.
    pub(super) package: InspectedMsi,
    pub(super) staging: UpdateStaging,
    pub(super) authorization: UpdateAuthorization,
    pub(super) original: InstallationSnapshot,
}

impl WindowsStagedResources {
    pub(super) fn new(
        staging: UpdateStaging,
        package: InspectedMsi,
        authorization: UpdateAuthorization,
        original: InstallationSnapshot,
    ) -> Result<Self, PackageError> {
        if package.path() != staging.package() {
            return Err(PackageError::Invalid("staged package location"));
        }
        if package.identity().version != authorization.version {
            return Err(PackageError::Invalid("staged authorization version"));
        }
        Ok(Self {
            package,
            staging,
            authorization,
            original,
        })
    }

    /// Cancellation takes ownership out of updater state before calling this.
    /// A sharing/identity/I/O failure is reported, leaving explicit recovery
    /// responsible for any remaining transaction files.
    pub(super) fn discard(self) -> Result<(), StagingError> {
        let Self {
            package, staging, ..
        } = self;
        drop(package);
        staging.remove()
    }
}

use std::path::Path;

use cfw_platform::{AppUpdateToolError, verify_update_application_signature};
use thiserror::Error;

use super::admission::{BundleIdentity, BundleIdentityError, INFO_PLIST, read_bundle_identity};
use super::error::{FailureCategory, bounded_diagnostic};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum StagedBundleError {
    #[error("the staged update does not describe this product")]
    WrongProduct,
    #[error("the staged update has an unreadable or invalid Info.plist")]
    InvalidInfo,
    #[error("the staged update is not the announced version")]
    VersionMismatch,
    #[error("the staged update is not a newer build than the installed application")]
    BuildNotNewer,
    #[error("the staged update requires a newer version of macOS")]
    RequiresNewerSystem,
    #[error("the running macOS version could not be determined")]
    SystemVersionUnavailable,
    #[error("the staged update is not signed as this product's release: {0}")]
    SignatureRejected(String),
    #[error("the staged update's signature could not be evaluated")]
    SignatureUnavailable,
}

impl StagedBundleError {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::WrongProduct => "bundle_wrong_product",
            Self::InvalidInfo => "bundle_info_invalid",
            Self::VersionMismatch => "bundle_version_mismatch",
            Self::BuildNotNewer => "bundle_build_not_newer",
            Self::RequiresNewerSystem => "bundle_requires_newer_system",
            Self::SystemVersionUnavailable => "system_version_unavailable",
            Self::SignatureRejected(_) => "bundle_signature_rejected",
            Self::SignatureUnavailable => "bundle_signature_unavailable",
        }
    }

    pub(super) const fn category(&self) -> FailureCategory {
        match self {
            Self::SignatureRejected(_) => FailureCategory::Authenticity,
            Self::SystemVersionUnavailable | Self::SignatureUnavailable => {
                FailureCategory::Internal
            }
            Self::WrongProduct
            | Self::InvalidInfo
            | Self::VersionMismatch
            | Self::BuildNotNewer
            | Self::RequiresNewerSystem => FailureCategory::Package,
        }
    }
}

/// What a staged bundle must be before it may replace the installed one.
#[derive(Debug, Clone, Copy)]
pub(super) struct StagedExpectation<'a> {
    /// The version the signed release metadata announced.
    pub(super) version: &'a str,
    /// The build of the installed application; the update must exceed it.
    pub(super) installed_build: u64,
    /// The running system's product version.
    pub(super) system_version: &'a str,
}

/// Verifies a staged bundle's declared identity and its code signature.
pub(super) fn verify_staged_bundle(
    bundle: &Path,
    expectation: StagedExpectation<'_>,
) -> Result<BundleIdentity, StagedBundleError> {
    verify_staged_bundle_with(bundle, expectation, |bundle| {
        verify_update_application_signature(bundle).map_err(|error| {
            // The verdict is the tool's status; its words are kept for
            // people, whole in the log and as one bounded line in the journal.
            eprintln!("staged update signature verification failed: {error}");
            match error {
                AppUpdateToolError::Rejected { diagnostic, .. } => {
                    StagedBundleError::SignatureRejected(bounded_diagnostic(&diagnostic))
                }
                AppUpdateToolError::UnsafeArgument(_) | AppUpdateToolError::Unavailable { .. } => {
                    StagedBundleError::SignatureUnavailable
                }
            }
        })
    })
}

fn verify_staged_bundle_with(
    bundle: &Path,
    expectation: StagedExpectation<'_>,
    verify_signature: impl FnOnce(&Path) -> Result<(), StagedBundleError>,
) -> Result<BundleIdentity, StagedBundleError> {
    let identity = read_bundle_identity(bundle).map_err(|error| match error {
        BundleIdentityError::WrongIdentifier => StagedBundleError::WrongProduct,
        BundleIdentityError::Unreadable
        | BundleIdentityError::InvalidVersion
        | BundleIdentityError::InvalidBuild => StagedBundleError::InvalidInfo,
    })?;
    if identity.version != expectation.version {
        return Err(StagedBundleError::VersionMismatch);
    }
    // Monotonic builds are the only rollback protection: the privileged
    // helpers accept any build signed by this team.
    if identity.build <= expectation.installed_build {
        return Err(StagedBundleError::BuildNotNewer);
    }
    if let Some(minimum) = minimum_system_version(bundle)? {
        let running = parse_system_version(expectation.system_version)
            .ok_or(StagedBundleError::SystemVersionUnavailable)?;
        if running < minimum {
            return Err(StagedBundleError::RequiresNewerSystem);
        }
    }
    verify_signature(bundle)?;
    Ok(identity)
}

fn minimum_system_version(bundle: &Path) -> Result<Option<[u64; 3]>, StagedBundleError> {
    let value = plist::Value::from_file(bundle.join(INFO_PLIST))
        .map_err(|_| StagedBundleError::InvalidInfo)?;
    let Some(minimum) = value
        .as_dictionary()
        .and_then(|dictionary| dictionary.get("LSMinimumSystemVersion"))
    else {
        return Ok(None);
    };
    minimum
        .as_string()
        .and_then(parse_system_version)
        .map(Some)
        .ok_or(StagedBundleError::InvalidInfo)
}

/// Parses `major[.minor[.patch]]`; omitted components are zero.
fn parse_system_version(value: &str) -> Option<[u64; 3]> {
    let mut parsed = [0_u64; 3];
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() > parsed.len() {
        return None;
    }
    for (component, part) in parsed.iter_mut().zip(parts) {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *component = part.parse().ok()?;
    }
    Some(parsed)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::super::admission::tests::write_bundle;
    use super::*;

    const PRODUCT: &str = super::super::admission::BUNDLE_IDENTIFIER;

    fn expectation(system_version: &str) -> StagedExpectation<'_> {
        StagedExpectation {
            version: "0.5.0",
            installed_build: 40074,
            system_version,
        }
    }

    fn staged(
        identifier: &str,
        version: &str,
        build: &str,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let scratch = tempfile::tempdir().expect("scratch");
        let bundle = write_bundle(scratch.path(), identifier, version, build).bundle;
        (scratch, bundle)
    }

    #[test]
    fn a_newer_build_of_the_announced_version_is_accepted_after_signature_verification() {
        let (_guard, bundle) = staged(PRODUCT, "0.5.0", "50021");
        let verified = Cell::new(false);
        let identity = verify_staged_bundle_with(&bundle, expectation("15.0"), |path| {
            assert_eq!(path, bundle);
            verified.set(true);
            Ok(())
        })
        .expect("accepted");
        assert_eq!(
            identity,
            BundleIdentity {
                version: "0.5.0".into(),
                build: 50021,
            }
        );
        assert!(verified.get(), "the signature must be evaluated");
    }

    #[test]
    fn identity_mismatches_are_refused_before_the_signature_is_consulted() {
        let cases = [
            (
                "com.example.other",
                "0.5.0",
                "50021",
                StagedBundleError::WrongProduct,
            ),
            (
                PRODUCT,
                "0.5.1",
                "50021",
                StagedBundleError::VersionMismatch,
            ),
            (PRODUCT, "0.5.0", "40074", StagedBundleError::BuildNotNewer),
            (PRODUCT, "0.5.0", "40073", StagedBundleError::BuildNotNewer),
            (PRODUCT, "0.5.0", "x", StagedBundleError::InvalidInfo),
        ];
        for (identifier, version, build, expected) in cases {
            let (_guard, bundle) = staged(identifier, version, build);
            assert_eq!(
                verify_staged_bundle_with(&bundle, expectation("27.0"), |_| {
                    panic!("signature must not be evaluated for {identifier} {version} {build}")
                }),
                Err(expected)
            );
        }
    }

    #[test]
    fn a_rejected_signature_refuses_an_otherwise_valid_bundle() {
        let (_guard, bundle) = staged(PRODUCT, "0.5.0", "50021");
        assert_eq!(
            verify_staged_bundle_with(&bundle, expectation("27.0"), |_| {
                Err(StagedBundleError::SignatureRejected("codesign".into()))
            }),
            Err(StagedBundleError::SignatureRejected("codesign".into()))
        );
        assert_eq!(
            StagedBundleError::SignatureRejected(String::new()).category(),
            FailureCategory::Authenticity
        );
    }

    #[test]
    fn the_declared_minimum_system_version_is_enforced() {
        // The fixture bundle declares LSMinimumSystemVersion 15.0.
        let (_guard, bundle) = staged(PRODUCT, "0.5.0", "50021");
        for (system, accepted) in [
            ("14.7.1", false),
            ("15", true),
            ("15.0", true),
            ("15.0.1", true),
            ("27.0", true),
        ] {
            let outcome = verify_staged_bundle_with(&bundle, expectation(system), |_| Ok(()));
            assert_eq!(outcome.is_ok(), accepted, "system {system}: {outcome:?}");
            if !accepted {
                assert_eq!(outcome, Err(StagedBundleError::RequiresNewerSystem));
            }
        }
        assert_eq!(
            verify_staged_bundle_with(&bundle, expectation("unknown"), |_| Ok(())),
            Err(StagedBundleError::SystemVersionUnavailable)
        );
    }

    #[test]
    fn system_versions_parse_as_up_to_three_decimal_components() {
        assert_eq!(parse_system_version("15"), Some([15, 0, 0]));
        assert_eq!(parse_system_version("15.4"), Some([15, 4, 0]));
        assert_eq!(parse_system_version("15.4.1"), Some([15, 4, 1]));
        for invalid in ["", "15.", ".4", "15.4.1.2", "15.x", "-1"] {
            assert_eq!(parse_system_version(invalid), None, "{invalid:?}");
        }
        assert!(parse_system_version("26.0") > parse_system_version("15.9.9"));
    }

    #[test]
    fn the_real_verifier_rejects_an_unsigned_staged_bundle() {
        let (_guard, bundle) = staged(PRODUCT, "0.5.0", "50021");
        let bundle = std::fs::canonicalize(&bundle).expect("canonical bundle");
        let verdict = verify_staged_bundle(&bundle, expectation("27.0"));
        assert!(
            matches!(&verdict, Err(StagedBundleError::SignatureRejected(detail)) if !detail.is_empty()),
            "{verdict:?}"
        );
    }
}

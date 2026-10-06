//! Bounded platform steps for replacing the installed application bundle.
//!
//! Every function runs one fixed system tool, or the installed Host itself,
//! with a deadline and bounded output. The tools run in a closed environment;
//! the Host's own modes also see who the user is, and the application
//! launcher runs in this process's environment because the application it
//! starts inherits it. Nothing here registers a service, starts networking or
//! elevates privileges; the Host's unregister modes remove registrations.

use std::fmt;
use std::path::{Component, Path};
use std::time::Duration;

use crate::bounded_command::{
    BoundedCommandError, BoundedCommandOutput, CommandEnvironment, run_bounded_command,
    run_bounded_command_with_environment,
};
use crate::release_security::ReleaseSignedComponent;

const TAR: &str = "/usr/bin/tar";
const CODESIGN: &str = "/usr/bin/codesign";
const OPEN: &str = "/usr/bin/open";
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(180);
const SIGNATURE_TIMEOUT: Duration = Duration::from_secs(120);
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const MAX_HOST_STDOUT_BYTES: usize = 16 * 1024;
const MAX_HOST_ARGUMENTS: usize = 4;
/// What identifies the user to the Host's own modes. The release tooling runs
/// them with exactly these variables beside the closed defaults.
const HOST_USER_ENVIRONMENT: [&str; 3] = ["HOME", "LOGNAME", "USER"];

/// The release identity every replacement bundle must satisfy: this product's
/// identifier, signed by its Developer ID Application certificate. It is the
/// installed application's designated requirement, so a bundle that passes is
/// the same code identity to the system as the one it replaces.
const RELEASE_APPLICATION_REQUIREMENT: &str = concat!(
    "=identifier \"com.bill.clashformac\" and anchor apple generic",
    " and certificate 1[field.1.2.840.113635.100.6.2.6] exists",
    " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists",
    " and certificate leaf[subject.OU] = \"YKUPL7Z869\"",
);

#[derive(Debug)]
pub enum AppUpdateToolError {
    /// The caller supplied a path or argument this boundary refuses to hand
    /// to a tool.
    UnsafeArgument(&'static str),
    /// The tool could not be run to completion within its bounds.
    Unavailable { tool: &'static str, detail: String },
    /// The tool ran and reported failure.
    Rejected {
        tool: &'static str,
        status: Option<i32>,
        diagnostic: String,
    },
}

impl fmt::Display for AppUpdateToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeArgument(role) => {
                write!(formatter, "{role} is outside the accepted argument form")
            }
            Self::Unavailable { tool, detail } => {
                write!(formatter, "{tool} could not complete: {detail}")
            }
            Self::Rejected {
                tool,
                status,
                diagnostic,
            } => write!(
                formatter,
                "{tool} reported failure (status {status:?}): {diagnostic}"
            ),
        }
    }
}

impl std::error::Error for AppUpdateToolError {}

/// Standard output of a completed Host invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledHostOutput {
    pub stdout: String,
}

/// Extracts a gzip-compressed tar archive into an existing private directory.
///
/// The system extractor never writes outside the destination: it removes the
/// leading `/` of an absolute member path and refuses a member with a `..`
/// component or one reached through an archive-provided symlink. Ownership,
/// extended attributes, ACLs and file flags recorded in the archive are not
/// applied.
pub fn extract_update_archive(
    archive: &Path,
    destination: &Path,
) -> Result<(), AppUpdateToolError> {
    let archive = canonical_argument(archive, "update archive")?;
    let destination = canonical_argument(destination, "update staging directory")?;
    finish(
        "archive extraction",
        run_bounded_command(
            TAR,
            &[
                "-x",
                "-z",
                "-f",
                archive,
                "-C",
                destination,
                "--no-same-owner",
                "--no-xattrs",
                "--no-mac-metadata",
                "--no-acls",
                "--no-fflags",
            ],
            EXTRACT_TIMEOUT,
            MAX_DIAGNOSTIC_BYTES,
            MAX_DIAGNOSTIC_BYTES,
        ),
    )
    .map(|_| ())
}

/// Verifies every nested signature and sealed resource of an application
/// bundle and requires the release code identity. The verdict is the tool's
/// exit status; its diagnostics are never interpreted.
pub fn verify_update_application_signature(bundle: &Path) -> Result<(), AppUpdateToolError> {
    let bundle = canonical_argument(bundle, "staged application bundle")?;
    finish(
        "code signature verification",
        run_bounded_command(
            CODESIGN,
            &[
                "--verify",
                "--deep",
                "--strict",
                "-R",
                RELEASE_APPLICATION_REQUIREMENT,
                bundle,
            ],
            SIGNATURE_TIMEOUT,
            MAX_DIAGNOSTIC_BYTES,
            MAX_DIAGNOSTIC_BYTES,
        ),
    )
    .map(|_| ())
}

/// Runs the installed Host executable in one of its non-dashboard modes and
/// returns its standard output. Arguments are passed verbatim; no shell is
/// involved. The Host sees the closed default environment and this process's
/// own `HOME`, `LOGNAME` and `USER`, so it identifies the user exactly as this
/// process does; nothing else of the environment reaches it.
pub fn run_installed_host(
    arguments: &[&str],
    timeout: Duration,
) -> Result<InstalledHostOutput, AppUpdateToolError> {
    if arguments.is_empty()
        || arguments.len() > MAX_HOST_ARGUMENTS
        || arguments
            .iter()
            .any(|argument| argument.is_empty() || argument.len() > 128 || argument.contains('\0'))
    {
        return Err(AppUpdateToolError::UnsafeArgument(
            "installed Host arguments",
        ));
    }
    let user_environment = host_user_environment(|name| std::env::var_os(name));
    let user_environment = user_environment
        .iter()
        .map(|(name, value)| (*name, value.as_os_str()))
        .collect::<Vec<_>>();
    let executable = ReleaseSignedComponent::MainExecutable
        .path()
        .to_str()
        .expect("fixed path is UTF-8");
    let output = finish(
        "installed Host",
        run_bounded_command_with_environment(
            executable,
            arguments,
            CommandEnvironment::Closed(&user_environment),
            timeout,
            MAX_HOST_STDOUT_BYTES,
            MAX_DIAGNOSTIC_BYTES,
        ),
    )?;
    String::from_utf8(output.stdout)
        .map(|stdout| InstalledHostOutput { stdout })
        .map_err(|_| AppUpdateToolError::Unavailable {
            tool: "installed Host",
            detail: "standard output is not UTF-8".into(),
        })
}

fn host_user_environment(
    variable: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Vec<(&'static str, std::ffi::OsString)> {
    HOST_USER_ENVIRONMENT
        .into_iter()
        .filter_map(|name| {
            variable(name)
                .filter(|value| !value.is_empty())
                .map(|value| (name, value))
        })
        .collect()
}

/// The running system's product version, for example `15.4.1`.
pub fn operating_system_version() -> Result<String, AppUpdateToolError> {
    const NAME: &std::ffi::CStr = c"kern.osproductversion";
    let unavailable = |detail: String| AppUpdateToolError::Unavailable {
        tool: "system version query",
        detail,
    };
    let mut buffer = [0_u8; 64];
    let mut length = buffer.len();
    // SAFETY: the name is NUL-terminated, the buffer is writable for `length`
    // bytes, and no new value is supplied.
    let status = unsafe {
        libc::sysctlbyname(
            NAME.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(unavailable(std::io::Error::last_os_error().to_string()));
    }
    let value = buffer
        .get(..length)
        .and_then(|bytes| bytes.strip_suffix(&[0]))
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| unavailable("the reported version is not text".into()))?;
    Ok(value.to_owned())
}

/// Asks LaunchServices to start the application at its canonical location.
///
/// An application opened this way inherits the launcher's environment (see
/// open(1)), so the launcher runs in this process's own: the one the user's
/// session gave the dashboard that started the installer. A tool's closed
/// environment would follow the application for as long as it runs.
///
/// Success means the request was accepted, not that a process stays alive.
pub fn open_installed_application() -> Result<(), AppUpdateToolError> {
    let bundle = ReleaseSignedComponent::Application
        .path()
        .to_str()
        .expect("fixed path is UTF-8");
    finish(
        "application launch",
        run_bounded_command_with_environment(
            OPEN,
            &[bundle],
            CommandEnvironment::Inherited,
            OPEN_TIMEOUT,
            MAX_DIAGNOSTIC_BYTES,
            MAX_DIAGNOSTIC_BYTES,
        ),
    )
    .map(|_| ())
}

fn canonical_argument<'a>(
    path: &'a Path,
    role: &'static str,
) -> Result<&'a str, AppUpdateToolError> {
    let rendered = path
        .to_str()
        .ok_or(AppUpdateToolError::UnsafeArgument(role))?;
    if !path.is_absolute()
        || rendered.contains('\0')
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(AppUpdateToolError::UnsafeArgument(role));
    }
    Ok(rendered)
}

fn finish(
    tool: &'static str,
    result: Result<BoundedCommandOutput, BoundedCommandError>,
) -> Result<BoundedCommandOutput, AppUpdateToolError> {
    let output = result.map_err(|error| AppUpdateToolError::Unavailable {
        tool,
        detail: error.to_string(),
    })?;
    if !output.status.success() {
        return Err(AppUpdateToolError::Rejected {
            tool,
            status: output.status.code(),
            diagnostic: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(output)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "cfw-app-update-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            fs::create_dir(&root).expect("scratch directory");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private scratch");
            Self(fs::canonicalize(&root).expect("canonical scratch"))
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove scratch directory");
        }
    }

    /// One ustar member with an arbitrary name, as a hostile archive would
    /// carry it. The system `tar` refuses to create such names itself.
    fn single_member_tar(name: &str, contents: &[u8]) -> Vec<u8> {
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", contents.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        let mut archive = header.to_vec();
        archive.extend_from_slice(contents);
        archive.resize(archive.len().div_ceil(512) * 512, 0);
        archive.extend_from_slice(&[0_u8; 1024]);
        archive
    }

    #[test]
    fn extraction_restores_a_release_shaped_archive_without_recorded_ownership() {
        let scratch = Scratch::new("extract");
        let source = scratch.path("source");
        let bundle = source.join("Sample.app/Contents/MacOS");
        fs::create_dir_all(&bundle).expect("bundle layout");
        fs::write(bundle.join("sample"), b"#!/bin/sh\n").expect("executable");
        fs::set_permissions(bundle.join("sample"), fs::Permissions::from_mode(0o755))
            .expect("executable mode");
        std::os::unix::fs::symlink("MacOS/sample", source.join("Sample.app/Contents/Current"))
            .expect("relative symlink");
        let archive = scratch.path("sample.tar.gz");
        let packed = Command::new(TAR)
            .current_dir(&source)
            .env("COPYFILE_DISABLE", "1")
            .args(["-czf"])
            .arg(&archive)
            .args(["--no-xattrs", "--no-mac-metadata", "Sample.app"])
            .status()
            .expect("pack fixture");
        assert!(packed.success());

        let destination = scratch.path("stage");
        fs::create_dir(&destination).expect("destination");
        extract_update_archive(&archive, &destination).expect("extraction");

        let executable = destination.join("Sample.app/Contents/MacOS/sample");
        assert_eq!(fs::read(&executable).expect("contents"), b"#!/bin/sh\n");
        assert_eq!(
            fs::metadata(&executable)
                .expect("mode")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::read_link(destination.join("Sample.app/Contents/Current")).expect("symlink"),
            PathBuf::from("MacOS/sample")
        );
    }

    #[test]
    fn extraction_refuses_members_that_leave_the_destination() {
        let scratch = Scratch::new("escape");
        let destination = scratch.path("stage");
        fs::create_dir(&destination).expect("destination");
        for name in ["../escaped", "nested/../../escaped"] {
            let archive = scratch.path("hostile.tar");
            fs::write(&archive, single_member_tar(name, b"escaped")).expect("hostile archive");
            let error = extract_update_archive(&archive, &destination)
                .expect_err("a traversing member must fail extraction");
            assert!(
                matches!(error, AppUpdateToolError::Rejected { tool, .. } if tool == "archive extraction"),
                "{name}: {error}"
            );
            assert!(
                !scratch.path("escaped").exists(),
                "{name} escaped the destination"
            );
        }
    }

    #[test]
    fn extraction_keeps_an_absolute_member_inside_the_destination() {
        let scratch = Scratch::new("absolute");
        let destination = scratch.path("stage");
        fs::create_dir(&destination).expect("destination");
        let outside = PathBuf::from(format!("/tmp/cfw-absolute-member-{}", std::process::id()));
        let archive = scratch.path("absolute.tar");
        fs::write(
            &archive,
            single_member_tar(outside.to_str().expect("UTF-8 path"), b"member"),
        )
        .expect("archive with an absolute member");

        let extracted = extract_update_archive(&archive, &destination);
        let escaped = outside.exists();
        if escaped {
            fs::remove_file(&outside).expect("remove the escaped member");
        }
        assert!(!escaped, "an absolute member left the destination");
        extracted.expect("the member is extracted without its leading separator");
        assert_eq!(
            fs::read(destination.join(outside.strip_prefix("/").expect("absolute path")))
                .expect("member inside the destination"),
            b"member"
        );
    }

    #[test]
    fn extraction_and_verification_refuse_noncanonical_paths() {
        for path in [
            "relative/archive.tar.gz",
            "/tmp/../etc/archive.tar.gz",
            "../archive.tar.gz",
        ] {
            assert!(matches!(
                extract_update_archive(Path::new(path), Path::new("/tmp")),
                Err(AppUpdateToolError::UnsafeArgument("update archive"))
            ));
            assert!(matches!(
                verify_update_application_signature(Path::new(path)),
                Err(AppUpdateToolError::UnsafeArgument(
                    "staged application bundle"
                ))
            ));
        }
    }

    #[test]
    fn signature_verification_rejects_validly_signed_code_of_another_identity() {
        // A system application has a valid signature and sealed resources but
        // is neither this product nor signed by its Developer ID.
        let foreign = Path::new("/System/Applications/Calculator.app");
        assert!(foreign.is_dir(), "fixture system application is missing");
        let error = verify_update_application_signature(foreign)
            .expect_err("a foreign identity must not satisfy the release requirement");
        assert!(
            matches!(error, AppUpdateToolError::Rejected { tool, .. } if tool == "code signature verification"),
            "{error}"
        );
    }

    #[test]
    fn signature_verification_rejects_unsigned_bundles() {
        let scratch = Scratch::new("unsigned");
        let executable = scratch.path("Unsigned.app/Contents/MacOS");
        fs::create_dir_all(&executable).expect("bundle layout");
        fs::write(executable.join("unsigned"), b"not code").expect("payload");
        let error = verify_update_application_signature(&scratch.path("Unsigned.app"))
            .expect_err("an unsigned bundle must be rejected");
        assert!(
            matches!(error, AppUpdateToolError::Rejected { .. }),
            "{error}"
        );
    }

    #[test]
    fn operating_system_version_is_a_dotted_decimal() {
        let version = operating_system_version().expect("system version");
        let parts = version.split('.').collect::<Vec<_>>();
        assert!((2..=3).contains(&parts.len()), "{version}");
        assert!(
            parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
            "{version}"
        );
    }

    #[test]
    fn installed_host_invocation_refuses_unbounded_or_empty_arguments() {
        let long = "x".repeat(129);
        for arguments in [
            &[][..],
            &["a", "b", "c", "d", "e"][..],
            &[""][..],
            &[long.as_str()][..],
        ] {
            assert!(matches!(
                run_installed_host(arguments, Duration::from_secs(1)),
                Err(AppUpdateToolError::UnsafeArgument(
                    "installed Host arguments"
                ))
            ));
        }
    }

    #[test]
    fn the_host_is_given_exactly_the_variables_that_identify_the_user() {
        let ambient = |name: &str| match name {
            "HOME" | "LOGNAME" | "USER" | "PATH" | "DYLD_INSERT_LIBRARIES" => {
                Some(std::ffi::OsString::from(format!("value-of-{name}")))
            }
            _ => None,
        };
        assert_eq!(
            host_user_environment(ambient),
            [
                ("HOME", "value-of-HOME".into()),
                ("LOGNAME", "value-of-LOGNAME".into()),
                ("USER", "value-of-USER".into()),
            ]
        );
        // What this process does not have is not invented for the Host.
        assert_eq!(
            host_user_environment(|name| match name {
                "HOME" => Some("/Users/example".into()),
                "USER" => Some(std::ffi::OsString::new()),
                _ => None,
            }),
            [("HOME", "/Users/example".into())]
        );
    }
}

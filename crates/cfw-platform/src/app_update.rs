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
    run_host_at(
        ReleaseSignedComponent::MainExecutable
            .path()
            .to_str()
            .expect("fixed path is UTF-8"),
        arguments,
        timeout,
    )
}

fn run_host_at(
    executable: &str,
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

/// Asks LaunchServices to start the application at its canonical location.
///
/// An application opened this way inherits the launcher's environment (see
/// open(1)), so the launcher runs in this process's own: the one the user's
/// session gave the dashboard that started the installer. A tool's closed
/// environment would follow the application for as long as it runs.
///
/// Success means the request was accepted, not that a process stays alive.
pub fn open_installed_application() -> Result<(), AppUpdateToolError> {
    open_application_at(
        ReleaseSignedComponent::Application
            .path()
            .to_str()
            .expect("fixed path is UTF-8"),
    )
}

fn open_application_at(bundle: &str) -> Result<(), AppUpdateToolError> {
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
mod tests;

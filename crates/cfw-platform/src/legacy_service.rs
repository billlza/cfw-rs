use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::login_item::ensure_path_absent;
use crate::{MacOsPlatformService, ServiceModeStatus, launchctl};

const LEGACY_HELPER_LABEL: &str = "com.bill.clashformac.helper";
const LEGACY_HELPER_PLIST_NAME: &str = "com.bill.clashformac.helper.plist";
const LEGACY_HELPER_PLIST_PATH: &str = "/Library/LaunchDaemons/com.bill.clashformac.helper.plist";
const LEGACY_HELPER_TARGET: &str = "system/com.bill.clashformac.helper";
const LEGACY_PARENT_BUNDLE_IDENTIFIER: &str = "com.bill.clashformac";
const LEGACY_TEAM_IDENTIFIER: &str = "YKUPL7Z869";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyServiceJobProgram {
    LegacyHelper,
    RetirementTombstone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LegacyServiceJobObservation {
    Unloaded,
    LoadedInactive { program: LegacyServiceJobProgram },
    LoadedActive { program: LegacyServiceJobProgram },
}

/// One-way retirement surface for the historical privileged helper.
pub trait LegacyServiceRetirement {
    fn service_mode_status(&self) -> ServiceModeStatus;
    fn legacy_service_job_observation(&self) -> Result<LegacyServiceJobObservation>;
    fn retire_legacy_service(&self) -> Result<()>;
    fn verify_legacy_service_retired(&self) -> Result<()>;
}

impl LegacyServiceRetirement for MacOsPlatformService {
    fn service_mode_status(&self) -> ServiceModeStatus {
        #[cfg(target_os = "macos")]
        {
            service_management::status()
        }
        #[cfg(not(target_os = "macos"))]
        {
            ServiceModeStatus::Unknown
        }
    }

    fn legacy_service_job_observation(&self) -> Result<LegacyServiceJobObservation> {
        #[cfg(target_os = "macos")]
        {
            match launchctl::print_target(LEGACY_HELPER_TARGET)? {
                Some(output) => parse_legacy_service_job(&output),
                None => Ok(LegacyServiceJobObservation::Unloaded),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("legacy Service Mode observation is only available on macOS")
        }
    }

    fn retire_legacy_service(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            // The migration release embeds a non-starting tombstone plist with
            // this exact name, so SMAppService can instantiate the supported
            // descriptor for the historical registration. A normal GUI app
            // has no authority to mutate the system launchd domain or unlink
            // /Library/LaunchDaemons directly; those are verification-only
            // boundaries here, not unreliable privileged fallbacks.
            let status = service_management::status();
            let job = self.legacy_service_job_observation()?;
            match retirement_step(status, job)? {
                RetirementStep::Unregister => {
                    service_management::unregister().map_err(anyhow::Error::msg)?;
                }
                RetirementStep::AlreadyRetired => {}
            }
            self.verify_legacy_service_retired()
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("legacy Service Mode retirement is only available on macOS")
        }
    }

    fn verify_legacy_service_retired(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            retirement_verdict(
                launchctl::ensure_unloaded(LEGACY_HELPER_TARGET),
                ensure_path_absent(std::path::Path::new(LEGACY_HELPER_PLIST_PATH)),
                service_management::status(),
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("legacy Service Mode verification is only available on macOS")
        }
    }
}

/// What retiring the helper does from its observed registration and job.
#[derive(Debug, PartialEq, Eq)]
enum RetirementStep {
    Unregister,
    AlreadyRetired,
}

/// Only an enabled registration whose fixed job is loaded but idle is
/// unregistered; only an absent registration without a job is already retired.
/// Anything else is partial, active or untrusted, and is left alone.
fn retirement_step(
    status: ServiceModeStatus,
    job: LegacyServiceJobObservation,
) -> Result<RetirementStep> {
    match (status, job) {
        (
            ServiceModeStatus::Enabled,
            LegacyServiceJobObservation::LoadedInactive {
                program:
                    LegacyServiceJobProgram::LegacyHelper | LegacyServiceJobProgram::RetirementTombstone,
            },
        ) => Ok(RetirementStep::Unregister),
        (
            ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound,
            LegacyServiceJobObservation::Unloaded,
        ) => Ok(RetirementStep::AlreadyRetired),
        _ => bail!(
            "legacy helper unregister boundary is partial, active, untrusted, or has the wrong fixed program identity: status={status:?}, job={job:?}"
        ),
    }
}

/// Retired means the fixed job is unloaded, its plist is gone and the
/// registration is absent; every unmet condition is reported.
fn retirement_verdict(
    unloaded: Result<()>,
    plist_absent: Result<()>,
    final_status: ServiceModeStatus,
) -> Result<()> {
    let mut errors = Vec::new();
    collect_error(
        &mut errors,
        "verify fixed launchd job is unloaded",
        unloaded,
    );
    collect_error(
        &mut errors,
        "verify fixed daemon plist is absent",
        plist_absent,
    );
    if !matches!(
        final_status,
        ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound
    ) {
        errors.push(format!(
            "verify SMAppService retirement: legacy Service Mode remains registered: {final_status:?}"
        ));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("legacy helper retirement incomplete: {}", errors.join("; "))
    }
}

fn parse_legacy_service_job(output: &str) -> Result<LegacyServiceJobObservation> {
    let mut lines = output.lines();
    if lines.next() != Some(format!("system/{LEGACY_HELPER_LABEL} = {{").as_str())
        || lines.next().is_none()
        || output.lines().last() != Some("}")
    {
        bail!("legacy launchd observation is not bound to the fixed system target")
    }
    let top_level = output
        .lines()
        .filter_map(|line| {
            let value = line.strip_prefix('\t')?;
            (!value.starts_with('\t')).then_some(value)
        })
        .collect::<Vec<_>>();
    require_unique_line(
        &top_level,
        "managed_by = com.apple.xpc.ServiceManagement",
        "ServiceManagement ownership",
    )?;
    require_unique_line(
        &top_level,
        &format!("parent bundle identifier = {LEGACY_PARENT_BUNDLE_IDENTIFIER}"),
        "parent bundle identity",
    )?;
    require_unique_line(&top_level, "domain = system", "launchd domain")?;
    let program = unique_assignment(&top_level, "program identifier")?;
    let program = program
        .split_once(" (mode: ")
        .map_or(program, |(path, _)| path);
    let program = match program {
        "Contents/Resources/resources/helpers/cfw-helper" => LegacyServiceJobProgram::LegacyHelper,
        "Contents/Library/HelperTools/cfw-helper-tombstone" => {
            LegacyServiceJobProgram::RetirementTombstone
        }
        _ => bail!("legacy launchd job has an unrecognized program identity"),
    };
    let expected_team = format!("\"team-identifier\" => \"{LEGACY_TEAM_IDENTIFIER}\"");
    if output
        .lines()
        .filter(|line| line.trim() == expected_team)
        .count()
        != 1
    {
        bail!("legacy launchd job signing identity is absent or ambiguous")
    }
    let active_count = unique_assignment(&top_level, "active count")?
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("legacy launchd active count is invalid"))?;
    let state = unique_assignment(&top_level, "state")?;
    match (active_count, state) {
        (0, "not running") => Ok(LegacyServiceJobObservation::LoadedInactive { program }),
        (count, "running") if count > 0 => {
            Ok(LegacyServiceJobObservation::LoadedActive { program })
        }
        _ => bail!("legacy launchd activity state is inconsistent or unsupported"),
    }
}

fn require_unique_line(lines: &[&str], expected: &str, label: &str) -> Result<()> {
    if lines.iter().filter(|line| **line == expected).count() == 1 {
        Ok(())
    } else {
        bail!("legacy launchd {label} is absent or ambiguous")
    }
}

fn unique_assignment<'a>(lines: &'a [&str], key: &str) -> Result<&'a str> {
    let prefix = format!("{key} = ");
    let values = lines
        .iter()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    match values.as_slice() {
        [value] => Ok(value),
        _ => bail!("legacy launchd {key} is absent or ambiguous"),
    }
}

fn collect_error(errors: &mut Vec<String>, operation: &str, result: Result<()>) {
    if let Err(error) = result {
        errors.push(format!("{operation}: {error}"));
    }
}

#[cfg(target_os = "macos")]
mod service_management;

#[cfg(test)]
mod tests;

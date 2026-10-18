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
            sm_legacy_service::status()
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
            let status = sm_legacy_service::status();
            let job = self.legacy_service_job_observation()?;
            match (status, job) {
                (
                    ServiceModeStatus::Enabled,
                    LegacyServiceJobObservation::LoadedInactive {
                        program:
                            LegacyServiceJobProgram::LegacyHelper
                            | LegacyServiceJobProgram::RetirementTombstone,
                    },
                ) => sm_legacy_service::unregister().map_err(anyhow::Error::msg)?,
                (
                    ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound,
                    LegacyServiceJobObservation::Unloaded,
                ) => {}
                _ => bail!(
                    "legacy helper unregister boundary is partial, active, untrusted, or has the wrong fixed program identity: status={status:?}, job={job:?}"
                ),
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
            let plist = std::path::Path::new(LEGACY_HELPER_PLIST_PATH);
            let mut errors = Vec::new();
            collect_error(
                &mut errors,
                "verify fixed launchd job is unloaded",
                launchctl::ensure_unloaded(LEGACY_HELPER_TARGET),
            );
            collect_error(
                &mut errors,
                "verify fixed daemon plist is absent",
                ensure_path_absent(plist),
            );
            let final_status = sm_legacy_service::status();
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
        #[cfg(not(target_os = "macos"))]
        {
            bail!("legacy Service Mode verification is only available on macOS")
        }
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
mod sm_legacy_service {
    use objc2::rc::Retained;
    use objc2_foundation::NSString;
    use objc2_service_management::SMAppService;

    use crate::{ServiceModeStatus, map_service_status};

    use super::LEGACY_HELPER_PLIST_NAME;

    fn service() -> Retained<SMAppService> {
        let name = NSString::from_str(LEGACY_HELPER_PLIST_NAME);
        // SAFETY: this creates a descriptor for one compile-time plist name.
        unsafe { SMAppService::daemonServiceWithPlistName(&name) }
    }

    pub(super) fn status() -> ServiceModeStatus {
        // SAFETY: status is a read-only query.
        map_service_status(unsafe { service().status() })
    }

    pub(super) fn unregister() -> Result<(), String> {
        // SAFETY: the service descriptor is fixed and this path only unregisters it.
        unsafe { service().unregisterAndReturnError() }
            .map_err(|error| format!("SMAppService legacy helper unregister failed: {error:?}"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn privileged_identity_is_compile_time_fixed() {
        assert_eq!(LEGACY_HELPER_LABEL, "com.bill.clashformac.helper");
        assert_eq!(
            PathBuf::from(LEGACY_HELPER_PLIST_PATH),
            PathBuf::from("/Library/LaunchDaemons/com.bill.clashformac.helper.plist")
        );
    }

    #[test]
    fn retirement_error_collection_keeps_every_failure() {
        let mut errors = Vec::new();
        collect_error(&mut errors, "first", Err(anyhow::anyhow!("one")));
        collect_error(&mut errors, "second", Ok(()));
        collect_error(&mut errors, "third", Err(anyhow::anyhow!("three")));
        assert_eq!(errors, ["first: one", "third: three"]);
    }

    #[test]
    fn launchd_parser_accepts_only_exact_owned_inactive_or_active_jobs() {
        let inactive = launchd_fixture("0", "not running", "cfw-helper");
        assert_eq!(
            parse_legacy_service_job(&inactive).expect("inactive"),
            LegacyServiceJobObservation::LoadedInactive {
                program: LegacyServiceJobProgram::LegacyHelper
            }
        );
        let active = launchd_fixture("1", "running", "cfw-helper-tombstone");
        assert_eq!(
            parse_legacy_service_job(&active).expect("active"),
            LegacyServiceJobObservation::LoadedActive {
                program: LegacyServiceJobProgram::RetirementTombstone
            }
        );
        assert!(parse_legacy_service_job(&inactive.replace("YKUPL7Z869", "ATTACKER00")).is_err());
        assert!(
            parse_legacy_service_job(&inactive.replace("active count = 0", "active count = 2"))
                .is_err()
        );
        assert!(
            parse_legacy_service_job(&inactive.replace("domain = system", "domain = gui")).is_err()
        );
    }

    fn launchd_fixture(active_count: &str, state: &str, program: &str) -> String {
        let path = if program == "cfw-helper" {
            "Contents/Resources/resources/helpers/cfw-helper"
        } else {
            "Contents/Library/HelperTools/cfw-helper-tombstone"
        };
        format!(
            "system/{LEGACY_HELPER_LABEL} = {{\n\tactive count = {active_count}\n\ttype = Submitted\n\tmanaged_by = com.apple.xpc.ServiceManagement\n\tstate = {state}\n\tprogram identifier = {path} (mode: 2)\n\tparent bundle identifier = {LEGACY_PARENT_BUNDLE_IDENTIFIER}\n\tLWCR = {{\n\t\t\"team-identifier\" => \"{LEGACY_TEAM_IDENTIFIER}\"\n\t}}\n\tdomain = system\n}}"
        )
    }
}

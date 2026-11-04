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

const STATUSES: [ServiceModeStatus; 5] = [
    ServiceModeStatus::NotRegistered,
    ServiceModeStatus::Enabled,
    ServiceModeStatus::RequiresApproval,
    ServiceModeStatus::NotFound,
    ServiceModeStatus::Unknown,
];

fn jobs() -> Vec<LegacyServiceJobObservation> {
    let programs = [
        LegacyServiceJobProgram::LegacyHelper,
        LegacyServiceJobProgram::RetirementTombstone,
    ];
    std::iter::once(LegacyServiceJobObservation::Unloaded)
        .chain(
            programs
                .into_iter()
                .map(|program| LegacyServiceJobObservation::LoadedInactive { program }),
        )
        .chain(
            programs
                .into_iter()
                .map(|program| LegacyServiceJobObservation::LoadedActive { program }),
        )
        .collect()
}

#[test]
fn only_an_idle_enabled_job_is_unregistered_and_only_an_absent_one_is_retired() {
    for status in STATUSES {
        for job in jobs() {
            let step = retirement_step(status, job).map_err(|error| error.to_string());
            let expected = match (status, job) {
                (
                    ServiceModeStatus::Enabled,
                    LegacyServiceJobObservation::LoadedInactive { .. },
                ) => Ok(RetirementStep::Unregister),
                (
                    ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound,
                    LegacyServiceJobObservation::Unloaded,
                ) => Ok(RetirementStep::AlreadyRetired),
                _ => Err(format!(
                    "legacy helper unregister boundary is partial, active, untrusted, or has the wrong fixed program identity: status={status:?}, job={job:?}"
                )),
            };
            assert_eq!(step, expected, "{status:?} {job:?}");
        }
    }
}

#[test]
fn retirement_holds_only_when_every_condition_holds_and_reports_each_one_unmet() {
    for status in [
        ServiceModeStatus::NotRegistered,
        ServiceModeStatus::NotFound,
    ] {
        retirement_verdict(Ok(()), Ok(()), status).expect("retired");
    }
    let error = retirement_verdict(
        Err(anyhow::anyhow!("loaded")),
        Err(anyhow::anyhow!("present")),
        ServiceModeStatus::RequiresApproval,
    )
    .expect_err("nothing retired");
    assert_eq!(
        error.to_string(),
        "legacy helper retirement incomplete: verify fixed launchd job is unloaded: loaded; verify fixed daemon plist is absent: present; verify SMAppService retirement: legacy Service Mode remains registered: RequiresApproval"
    );
    let error = retirement_verdict(
        Ok(()),
        Err(anyhow::anyhow!("present")),
        ServiceModeStatus::NotFound,
    )
    .expect_err("the plist remains");
    assert_eq!(
        error.to_string(),
        "legacy helper retirement incomplete: verify fixed daemon plist is absent: present"
    );
    let error = retirement_verdict(Ok(()), Ok(()), ServiceModeStatus::Enabled)
        .expect_err("still registered");
    assert_eq!(
        error.to_string(),
        "legacy helper retirement incomplete: verify SMAppService retirement: legacy Service Mode remains registered: Enabled"
    );
}

#[test]
fn launchd_parser_requires_the_fixed_target_frame() {
    let inactive = launchd_fixture("0", "not running", "cfw-helper");
    for (output, message) in [
        (
            inactive.replace("system/com.bill.clashformac.helper", "system/com.example"),
            "legacy launchd observation is not bound to the fixed system target",
        ),
        (
            format!("system/{LEGACY_HELPER_LABEL} = {{"),
            "legacy launchd observation is not bound to the fixed system target",
        ),
        (
            inactive.trim_end_matches('}').to_owned(),
            "legacy launchd observation is not bound to the fixed system target",
        ),
    ] {
        let error = parse_legacy_service_job(&output).expect_err(message);
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn launchd_parser_requires_each_ownership_line_exactly_once_at_top_level() {
    let inactive = launchd_fixture("0", "not running", "cfw-helper");
    let managed = "\tmanaged_by = com.apple.xpc.ServiceManagement\n";
    let parent = format!("\tparent bundle identifier = {LEGACY_PARENT_BUNDLE_IDENTIFIER}\n");
    for (output, message) in [
        (
            inactive.replace(managed, ""),
            "legacy launchd ServiceManagement ownership is absent or ambiguous",
        ),
        (
            inactive.replace(managed, &format!("{managed}{managed}")),
            "legacy launchd ServiceManagement ownership is absent or ambiguous",
        ),
        (
            // A nested line is not the job's own.
            inactive.replace(managed, &format!("\t{managed}")),
            "legacy launchd ServiceManagement ownership is absent or ambiguous",
        ),
        (
            inactive.replace(&parent, ""),
            "legacy launchd parent bundle identity is absent or ambiguous",
        ),
        (
            inactive.replace("\tdomain = system\n", ""),
            "legacy launchd launchd domain is absent or ambiguous",
        ),
        (
            inactive.replace("\tstate = not running\n", ""),
            "legacy launchd state is absent or ambiguous",
        ),
        (
            inactive.replace("\tactive count = 0\n", ""),
            "legacy launchd active count is absent or ambiguous",
        ),
        (
            inactive.replace(
                "\tprogram identifier = Contents/Resources/resources/helpers/cfw-helper (mode: 2)\n",
                "",
            ),
            "legacy launchd program identifier is absent or ambiguous",
        ),
    ] {
        let error = parse_legacy_service_job(&output).expect_err(message);
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn launchd_parser_requires_a_known_program_one_team_and_a_consistent_state() {
    let inactive = launchd_fixture("0", "not running", "cfw-helper");
    let team = format!("\t\t\"team-identifier\" => \"{LEGACY_TEAM_IDENTIFIER}\"\n");
    for (output, message) in [
        (
            inactive.replace("helpers/cfw-helper", "helpers/other-helper"),
            "legacy launchd job has an unrecognized program identity",
        ),
        (
            inactive.replace(&team, &format!("{team}{team}")),
            "legacy launchd job signing identity is absent or ambiguous",
        ),
        (
            inactive.replace("active count = 0", "active count = many"),
            "legacy launchd active count is invalid",
        ),
        (
            inactive.replace("state = not running", "state = running"),
            "legacy launchd activity state is inconsistent or unsupported",
        ),
        (
            launchd_fixture("1", "not running", "cfw-helper"),
            "legacy launchd activity state is inconsistent or unsupported",
        ),
        (
            inactive.replace("state = not running", "state = spawn scheduled"),
            "legacy launchd activity state is inconsistent or unsupported",
        ),
    ] {
        let error = parse_legacy_service_job(&output).expect_err(message);
        assert_eq!(error.to_string(), message);
    }
    // launchd omits the mode suffix on some releases.
    assert_eq!(
        parse_legacy_service_job(&inactive.replace(" (mode: 2)", "")).expect("no mode suffix"),
        LegacyServiceJobObservation::LoadedInactive {
            program: LegacyServiceJobProgram::LegacyHelper
        }
    );
}

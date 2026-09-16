use std::path::Path;
use std::time::{Duration, Instant};

use objc2_app_kit::NSRunningApplication;

#[cfg(test)]
use super::handoff_ticket::ProcessStartIdentity;
use super::handoff_ticket::{ProcessIdentity, list_exact_processes};
use super::runtime_plan::LegacyRuntimePlanKind;

const LEGACY_GUI_EXECUTABLE: &str = "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac";
const TERMINATION_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) type LegacyGuiIdentity = ProcessIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyGuiExpectation {
    Required,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyGuiPresence {
    ExactPresent,
    Missing,
}

impl From<LegacyRuntimePlanKind> for LegacyGuiExpectation {
    fn from(kind: LegacyRuntimePlanKind) -> Self {
        if kind.requires_legacy_gui() {
            Self::Required
        } else {
            Self::Absent
        }
    }
}

pub(super) struct LegacyGuiHandoff {
    identity: Option<LegacyGuiIdentity>,
    expectation: LegacyGuiExpectation,
    terminated: bool,
    network_retirement_sealed: bool,
}

impl LegacyGuiHandoff {
    pub(super) fn capture(
        parent: &ProcessIdentity,
        runtime_kind: LegacyRuntimePlanKind,
    ) -> Result<Self, String> {
        let expectation = runtime_kind.into();
        let candidates = legacy_gui_processes()?;
        let identity = classify_legacy_gui_processes(&candidates, parent, expectation)?;
        Ok(Self {
            identity,
            expectation,
            terminated: false,
            network_retirement_sealed: false,
        })
    }

    pub(super) fn identity(&self) -> Option<&LegacyGuiIdentity> {
        self.identity.as_ref()
    }

    pub(super) fn verify_before_network_retirement_seal(&self) -> Result<(), String> {
        match (self.expectation, self.identity.as_ref()) {
            (LegacyGuiExpectation::Required, Some(identity)) => {
                require_revalidated_legacy_gui(identity, false).map(|_| ())
            }
            (LegacyGuiExpectation::Absent, None) => Self::verify_no_persisted_legacy_gui(),
            _ => Err("legacy GUI handoff plan is internally inconsistent".into()),
        }
    }

    /// `NetworkRetiring` is already durable before this one-way exit. The
    /// legacy network is not mutated until the exact GUI is proven absent.
    pub(super) fn terminate_for_network_retirement(&mut self) -> Result<(), String> {
        if !self.network_retirement_sealed {
            return Err("NetworkRetiring was not durably sealed before legacy GUI exit".into());
        }
        match (self.expectation, self.identity.as_ref()) {
            (LegacyGuiExpectation::Required, Some(identity)) => {
                terminate_exact_or_missing(identity)?;
                self.terminated = true;
                verify_exact_missing(identity)
            }
            (LegacyGuiExpectation::Absent, None) => {
                Self::verify_no_persisted_legacy_gui()?;
                self.terminated = true;
                Ok(())
            }
            _ => Err("legacy GUI handoff plan is internally inconsistent".into()),
        }
    }

    pub(super) fn revalidate_for_network_mutation(&self) -> Result<(), String> {
        match (self.expectation, self.identity.as_ref()) {
            (LegacyGuiExpectation::Required, Some(identity)) => {
                validate_network_mutation_gate(self.terminated, self.network_retirement_sealed)?;
                verify_exact_missing(identity)
            }
            (LegacyGuiExpectation::Absent, None) => {
                validate_network_mutation_gate(self.terminated, self.network_retirement_sealed)?;
                Self::verify_no_persisted_legacy_gui()
            }
            _ => Err("legacy GUI handoff plan is internally inconsistent".into()),
        }
    }

    pub(super) fn seal_network_retirement(&mut self) {
        self.network_retirement_sealed = true;
    }

    pub(super) fn verify_terminated_after_replacement_active(&self) -> Result<(), String> {
        match (self.expectation, self.identity.as_ref()) {
            (LegacyGuiExpectation::Required, Some(identity)) => {
                validate_network_mutation_gate(self.terminated, self.network_retirement_sealed)?;
                verify_exact_missing(identity)
            }
            (LegacyGuiExpectation::Absent, None) => Self::verify_no_persisted_legacy_gui(),
            _ => Err("legacy GUI handoff plan is internally inconsistent".into()),
        }
    }

    pub(super) fn verify_persisted_identity_or_missing(
        identity: &LegacyGuiIdentity,
    ) -> Result<(), String> {
        require_revalidated_legacy_gui(identity, true).map(|_| ())
    }

    pub(super) fn terminate_persisted_for_network_retirement(
        identity: &LegacyGuiIdentity,
    ) -> Result<(), String> {
        terminate_exact_or_missing(identity)
    }

    pub(super) fn verify_persisted_terminated(identity: &LegacyGuiIdentity) -> Result<(), String> {
        verify_exact_missing(identity)
    }

    pub(super) fn terminate_persisted_after_replacement_active(
        identity: &LegacyGuiIdentity,
    ) -> Result<(), String> {
        terminate_exact_or_missing(identity)
    }

    pub(super) fn verify_no_persisted_legacy_gui() -> Result<(), String> {
        classify_revalidated_legacy_gui_processes(&legacy_gui_processes()?, None, true).map(|_| ())
    }
}

fn legacy_gui_processes() -> Result<Vec<LegacyGuiIdentity>, String> {
    let parsed = list_exact_processes(Path::new(LEGACY_GUI_EXECUTABLE))?;
    let current_uid = unsafe { libc::geteuid() };
    let self_pid = std::process::id();
    Ok(parsed
        .into_iter()
        .filter(|process| process.uid == current_uid && process.pid != self_pid)
        .collect())
}

fn require_revalidated_legacy_gui(
    identity: &LegacyGuiIdentity,
    allow_expected_missing: bool,
) -> Result<LegacyGuiPresence, String> {
    classify_revalidated_legacy_gui_processes(
        &legacy_gui_processes()?,
        Some(identity),
        allow_expected_missing,
    )
}

fn classify_revalidated_legacy_gui_processes(
    candidates: &[LegacyGuiIdentity],
    expected: Option<&LegacyGuiIdentity>,
    allow_expected_missing: bool,
) -> Result<LegacyGuiPresence, String> {
    match (expected, candidates) {
        (None, []) => Ok(LegacyGuiPresence::Missing),
        (None, _) => {
            Err("an unexpected legacy GUI process exists at an exact-path absence boundary".into())
        }
        (Some(expected), [actual]) if actual == expected => Ok(LegacyGuiPresence::ExactPresent),
        (Some(_), []) if allow_expected_missing => Ok(LegacyGuiPresence::Missing),
        (Some(_), []) => Err("the exact legacy GUI disappeared before one-way retirement".into()),
        (Some(_), _) => Err(
            "the legacy GUI exact process set contains a new, replaced, or additional identity"
                .into(),
        ),
    }
}

fn terminate_exact_or_missing(identity: &LegacyGuiIdentity) -> Result<(), String> {
    match require_revalidated_legacy_gui(identity, true)? {
        LegacyGuiPresence::Missing => return Ok(()),
        LegacyGuiPresence::ExactPresent => {}
    }
    if let Err(error) = force_terminate_exact_application(identity) {
        return accept_only_missing_after_identity_error(identity, error).map(|_| ());
    }
    let deadline = Instant::now() + TERMINATION_CONFIRMATION_TIMEOUT;
    loop {
        match require_revalidated_legacy_gui(identity, true)? {
            LegacyGuiPresence::Missing => return Ok(()),
            LegacyGuiPresence::ExactPresent if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            LegacyGuiPresence::ExactPresent => {
                return Err("retired legacy GUI did not terminate within two seconds".into());
            }
        }
    }
}

fn verify_exact_missing(identity: &LegacyGuiIdentity) -> Result<(), String> {
    match require_revalidated_legacy_gui(identity, true)? {
        LegacyGuiPresence::Missing => Ok(()),
        LegacyGuiPresence::ExactPresent => {
            Err("the exact legacy GUI remains after the one-way exit boundary".into())
        }
    }
}

fn validate_network_mutation_gate(terminated: bool, sealed: bool) -> Result<(), String> {
    match (terminated, sealed) {
        (true, true) => Ok(()),
        (false, _) => Err("legacy GUI has not completed its one-way exit".into()),
        (true, false) => {
            Err("NetworkRetiring was not durably sealed before network mutation".into())
        }
    }
}

fn accept_only_missing_after_identity_error(
    identity: &LegacyGuiIdentity,
    identity_error: String,
) -> Result<LegacyGuiPresence, String> {
    match require_revalidated_legacy_gui(identity, true) {
        Ok(LegacyGuiPresence::Missing) => Ok(LegacyGuiPresence::Missing),
        Ok(LegacyGuiPresence::ExactPresent) => Err(identity_error),
        Err(set_error) => Err(format!(
            "{identity_error}; exact legacy GUI process-set revalidation also failed: {set_error}"
        )),
    }
}

fn classify_legacy_gui_processes(
    candidates: &[LegacyGuiIdentity],
    parent: &ProcessIdentity,
    expectation: LegacyGuiExpectation,
) -> Result<Option<LegacyGuiIdentity>, String> {
    let remaining = candidates
        .iter()
        .filter(|candidate| *candidate != parent)
        .cloned()
        .collect::<Vec<_>>();
    match remaining.as_slice() {
        [] if expectation == LegacyGuiExpectation::Absent => Ok(None),
        [] => Err(
            "upgrade cutover requires exactly one legacy GUI after excluding the ticket-bound 0.4.0 parent"
                .into(),
        ),
        [legacy] if expectation == LegacyGuiExpectation::Required => Ok(Some(legacy.clone())),
        [_] => Err(
            "offline upgrade requires the legacy GUI to be absent; no process was terminated"
                .into(),
        ),
        _ => Err(
            "multiple legacy GUI identities remain after excluding the ticket-bound 0.4.0 parent"
                .into(),
        ),
    }
}

fn force_terminate_exact_application(identity: &LegacyGuiIdentity) -> Result<(), String> {
    // NSRunningApplication is an instance object that remains valid after the
    // represented app exits; AppKit explicitly says not to compare instances
    // by PID. Acquiring it between two exact libproc observations closes the
    // destructive PID-reuse gap that a raw SIGKILL cannot close on macOS.
    require_revalidated_legacy_gui(identity, false).map_err(|error| {
        format!("legacy GUI process set changed before AppKit instance binding: {error}")
    })?;
    let pid = libc::pid_t::try_from(identity.pid)
        .map_err(|_| "legacy GUI PID is outside Darwin's signed PID range".to_owned())?;
    let application = NSRunningApplication::runningApplicationWithProcessIdentifier(pid)
        .ok_or_else(|| "AppKit cannot bind the exact retired legacy GUI instance".to_owned())?;
    if application.processIdentifier() != pid || application.isTerminated() {
        return Err(
            "AppKit legacy GUI instance is already terminated or has a different PID".into(),
        );
    }
    require_revalidated_legacy_gui(identity, false).map_err(|error| {
        format!(
            "legacy GUI process set changed after AppKit instance binding; force termination was not requested: {error}"
        )
    })?;
    if !application.forceTerminate() {
        return Err("AppKit rejected force termination of the exact retired legacy GUI".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_excludes_parent_and_distinguishes_fresh_from_upgrade() {
        let parent = identity(40);
        let legacy = identity(41);
        assert_eq!(
            classify_legacy_gui_processes(
                std::slice::from_ref(&parent),
                &parent,
                LegacyGuiExpectation::Absent,
            )
            .expect("fresh"),
            None
        );
        assert!(
            classify_legacy_gui_processes(
                std::slice::from_ref(&parent),
                &parent,
                LegacyGuiExpectation::Required,
            )
            .is_err()
        );
        assert_eq!(
            classify_legacy_gui_processes(
                &[parent.clone(), legacy.clone()],
                &parent,
                LegacyGuiExpectation::Required,
            )
            .expect("upgrade"),
            Some(legacy.clone())
        );
        assert!(
            classify_legacy_gui_processes(
                &[parent, legacy, identity(42)],
                &identity(40),
                LegacyGuiExpectation::Required,
            )
            .is_err()
        );
    }

    #[test]
    fn every_revalidated_boundary_requires_the_exact_closed_process_set() {
        let expected = identity(41);
        assert_eq!(
            classify_revalidated_legacy_gui_processes(
                std::slice::from_ref(&expected),
                Some(&expected),
                false,
            )
            .expect("exact identity"),
            LegacyGuiPresence::ExactPresent
        );
        assert_eq!(
            classify_revalidated_legacy_gui_processes(&[], Some(&expected), true)
                .expect("one-way disappearance"),
            LegacyGuiPresence::Missing
        );
        assert!(classify_revalidated_legacy_gui_processes(&[], Some(&expected), false).is_err());

        let mut reused_pid = expected.clone();
        reused_pid.start_identity.microseconds += 1;
        assert!(
            classify_revalidated_legacy_gui_processes(
                std::slice::from_ref(&reused_pid),
                Some(&expected),
                true,
            )
            .is_err()
        );
        assert!(
            classify_revalidated_legacy_gui_processes(
                &[expected.clone(), identity(42)],
                Some(&expected),
                true,
            )
            .is_err()
        );
        assert!(
            classify_revalidated_legacy_gui_processes(
                std::slice::from_ref(&identity(42)),
                Some(&expected),
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn absence_boundaries_reject_every_same_path_process() {
        assert_eq!(
            classify_revalidated_legacy_gui_processes(&[], None, true).expect("exact absence"),
            LegacyGuiPresence::Missing
        );
        assert!(
            classify_revalidated_legacy_gui_processes(
                std::slice::from_ref(&identity(40)),
                None,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn network_mutation_requires_both_gui_exit_and_durable_retirement_intent() {
        assert!(validate_network_mutation_gate(false, false).is_err());
        assert!(validate_network_mutation_gate(false, true).is_err());
        assert!(validate_network_mutation_gate(true, false).is_err());
        validate_network_mutation_gate(true, true).expect("sealed one-way boundary");
    }

    #[test]
    fn gui_handoff_has_no_raw_stop_resume_or_kill_path() {
        let source = include_str!("gui_handoff.rs");
        let forbidden = [
            ["SIG", "STOP"].concat(),
            ["SIG", "CONT"].concat(),
            ["libc::", "kill"].concat(),
        ];
        for forbidden in forbidden {
            assert!(
                !source.contains(forbidden.as_str()),
                "forbidden raw signal: {forbidden}"
            );
        }
    }

    fn identity(pid: u32) -> LegacyGuiIdentity {
        LegacyGuiIdentity {
            uid: unsafe { libc::geteuid() },
            pid,
            start_identity: ProcessStartIdentity {
                seconds: 1_721_599_857,
                microseconds: 123_456,
            },
            executable: Path::new(LEGACY_GUI_EXECUTABLE).to_path_buf(),
        }
    }
}

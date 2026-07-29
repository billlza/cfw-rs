use std::path::Path;
use std::time::{Duration, Instant};

use objc2_app_kit::NSRunningApplication;

#[cfg(test)]
use super::handoff_ticket::ProcessStartIdentity;
use super::handoff_ticket::{
    ProcessIdentity, identity_exists, identity_is_stopped, list_exact_processes,
};

const LEGACY_GUI_EXECUTABLE: &str = "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac";
const SIGNAL_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) type LegacyGuiIdentity = ProcessIdentity;

pub(super) struct LegacyGuiHandoff {
    identity: Option<LegacyGuiIdentity>,
    stopped: bool,
    resume_on_drop: bool,
}

impl LegacyGuiHandoff {
    pub(super) fn capture(
        parent: &ProcessIdentity,
        fresh_install_absence_proven: bool,
    ) -> Result<Self, String> {
        let candidates = legacy_gui_processes()?;
        let identity =
            classify_legacy_gui_processes(&candidates, parent, fresh_install_absence_proven)?;
        Ok(Self {
            identity,
            stopped: false,
            resume_on_drop: true,
        })
    }

    pub(super) fn identity(&self) -> Option<&LegacyGuiIdentity> {
        self.identity.as_ref()
    }

    pub(super) fn stop(&mut self) -> Result<(), String> {
        let Some(identity) = self.identity.as_ref() else {
            return Ok(());
        };
        signal_exact(identity, libc::SIGSTOP, "stop legacy GUI")?;
        self.stopped = true;
        wait_for_stopped_state(identity, true)?;
        Ok(())
    }

    pub(super) fn seal_legacy_retired(&mut self) {
        self.resume_on_drop = false;
    }

    pub(super) fn terminate_after_replacement_active(&mut self) -> Result<(), String> {
        let Some(identity) = self.identity.as_ref() else {
            return Ok(());
        };
        if !self.stopped || self.resume_on_drop {
            return Err(
                "legacy GUI termination requires a stopped identity and proven legacy retirement"
                    .into(),
            );
        }
        force_terminate_exact_application(identity)?;
        let deadline = Instant::now() + SIGNAL_CONFIRMATION_TIMEOUT;
        loop {
            if !identity_exists(identity)? {
                self.stopped = false;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("retired legacy GUI did not terminate within two seconds".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub(super) fn resume_persisted_if_stopped(identity: &LegacyGuiIdentity) -> Result<(), String> {
        if !identity_exists(identity)? {
            return Err("persisted legacy GUI identity no longer exists".into());
        }
        if !identity_is_stopped(identity)? {
            return Ok(());
        }
        signal_exact(identity, libc::SIGCONT, "resume persisted legacy GUI")?;
        wait_for_stopped_state(identity, false)
    }

    pub(super) fn ensure_persisted_stopped_for_network_retirement(
        identity: &LegacyGuiIdentity,
    ) -> Result<(), String> {
        if identity_is_stopped(identity)? {
            return Ok(());
        }
        signal_exact(
            identity,
            libc::SIGSTOP,
            "re-stop the persisted legacy GUI before network retirement recovery",
        )?;
        wait_for_stopped_state(identity, true)
    }

    pub(super) fn terminate_persisted_after_replacement_active(
        identity: &LegacyGuiIdentity,
    ) -> Result<(), String> {
        if !identity_exists(identity)? {
            return Ok(());
        }
        if !identity_is_stopped(identity)? {
            return Err(
                "persisted legacy GUI is not stopped; refusing to signal an ambiguous process"
                    .into(),
            );
        }
        force_terminate_exact_application(identity)?;
        let deadline = Instant::now() + SIGNAL_CONFIRMATION_TIMEOUT;
        while identity_exists(identity)? {
            if Instant::now() >= deadline {
                return Err(
                    "persisted retired legacy GUI did not terminate within two seconds".into(),
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }
}

impl Drop for LegacyGuiHandoff {
    fn drop(&mut self) {
        if self.stopped
            && self.resume_on_drop
            && let Some(identity) = self.identity.as_ref()
            && let Err(error) = signal_exact(identity, libc::SIGCONT, "resume legacy GUI")
        {
            eprintln!("failed to resume the exact legacy GUI during cutover rollback: {error}");
        }
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

fn classify_legacy_gui_processes(
    candidates: &[LegacyGuiIdentity],
    parent: &ProcessIdentity,
    fresh_install_absence_proven: bool,
) -> Result<Option<LegacyGuiIdentity>, String> {
    let remaining = candidates
        .iter()
        .filter(|candidate| *candidate != parent)
        .cloned()
        .collect::<Vec<_>>();
    match remaining.as_slice() {
        [] if fresh_install_absence_proven => Ok(None),
        [] => Err(
            "upgrade cutover requires exactly one legacy GUI after excluding the ticket-bound 0.4.0 parent"
                .into(),
        ),
        [legacy] => Ok(Some(legacy.clone())),
        _ => Err(
            "multiple legacy GUI identities remain after excluding the ticket-bound 0.4.0 parent"
                .into(),
        ),
    }
}

fn signal_exact(
    identity: &LegacyGuiIdentity,
    signal: libc::c_int,
    operation: &str,
) -> Result<(), String> {
    // macOS has no pidfd-style stable process handle. The kernel PID, uid,
    // executable vnode path, and microsecond start time are therefore rebound
    // immediately at every signal boundary; argv/`ps` text is never authority.
    // A non-zero check-to-signal reuse window remains for SIGSTOP/SIGCONT until
    // the legacy app implements a cooperating handoff protocol. No destructive
    // termination uses this boundary; post-signal identity/state drift fails.
    if !identity_exists(identity)? {
        return Err(format!(
            "legacy GUI identity changed at the {operation} signal boundary"
        ));
    }
    if unsafe { libc::kill(identity.pid as libc::pid_t, signal) } == -1 {
        Err(format!(
            "failed to {operation}: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

fn force_terminate_exact_application(identity: &LegacyGuiIdentity) -> Result<(), String> {
    // NSRunningApplication is an instance object that remains valid after the
    // represented app exits; AppKit explicitly says not to compare instances
    // by PID. Acquiring it between two exact libproc observations closes the
    // destructive PID-reuse gap that a raw SIGKILL cannot close on macOS.
    if !identity_exists(identity)? {
        return Err("legacy GUI identity changed before AppKit instance binding".into());
    }
    let pid = libc::pid_t::try_from(identity.pid)
        .map_err(|_| "legacy GUI PID is outside Darwin's signed PID range".to_owned())?;
    let application = NSRunningApplication::runningApplicationWithProcessIdentifier(pid)
        .ok_or_else(|| "AppKit cannot bind the exact retired legacy GUI instance".to_owned())?;
    if application.processIdentifier() != pid || application.isTerminated() {
        return Err(
            "AppKit legacy GUI instance is already terminated or has a different PID".into(),
        );
    }
    if !identity_exists(identity)? {
        return Err(
            "legacy GUI kernel identity changed after AppKit instance binding; force termination was not requested"
                .into(),
        );
    }
    if !application.forceTerminate() {
        return Err("AppKit rejected force termination of the exact retired legacy GUI".into());
    }
    Ok(())
}

fn wait_for_stopped_state(
    identity: &LegacyGuiIdentity,
    expected_stopped: bool,
) -> Result<(), String> {
    let deadline = Instant::now() + SIGNAL_CONFIRMATION_TIMEOUT;
    loop {
        if identity_is_stopped(identity)? == expected_stopped {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("legacy GUI signal state was not confirmed within two seconds".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_excludes_parent_and_distinguishes_fresh_from_upgrade() {
        let parent = identity(40);
        let legacy = identity(41);
        assert_eq!(
            classify_legacy_gui_processes(std::slice::from_ref(&parent), &parent, true)
                .expect("fresh"),
            None
        );
        assert!(
            classify_legacy_gui_processes(std::slice::from_ref(&parent), &parent, false).is_err()
        );
        assert_eq!(
            classify_legacy_gui_processes(&[parent.clone(), legacy.clone()], &parent, false)
                .expect("upgrade"),
            Some(legacy.clone())
        );
        assert!(
            classify_legacy_gui_processes(&[parent, legacy, identity(42)], &identity(40), false,)
                .is_err()
        );
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

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const LEGACY_GUI_EXECUTABLE: &str = "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac";
const SIGNAL_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyGuiIdentity {
    pub(super) uid: u32,
    pub(super) pid: u32,
    pub(super) start_identity: String,
    pub(super) executable: PathBuf,
}

pub(super) struct LegacyGuiHandoff {
    identity: LegacyGuiIdentity,
    stopped: bool,
    resume_on_drop: bool,
}

impl LegacyGuiHandoff {
    pub(super) fn capture() -> Result<Self, String> {
        let candidates = legacy_gui_processes()?;
        let identity = match candidates.as_slice() {
            [identity] => identity.clone(),
            [] => {
                return Err(
                    "migration handoff requires exactly one running legacy GUI; do not quit it normally because that would tear down the current VPN"
                        .into(),
                );
            }
            _ => {
                return Err(
                    "multiple legacy GUI identities are running; close neither and resolve the ambiguity before cutover"
                        .into(),
                );
            }
        };
        Ok(Self {
            identity,
            stopped: false,
            resume_on_drop: true,
        })
    }

    pub(super) fn identity(&self) -> &LegacyGuiIdentity {
        &self.identity
    }

    pub(super) fn stop(&mut self) -> Result<(), String> {
        self.require_current_identity()?;
        signal(self.identity.pid, libc::SIGSTOP, "stop legacy GUI")?;
        self.stopped = true;
        wait_for_state(&self.identity, |state| state.starts_with('T'))?;
        Ok(())
    }

    pub(super) fn seal_legacy_retired(&mut self) {
        self.resume_on_drop = false;
    }

    pub(super) fn terminate_after_replacement_active(&mut self) -> Result<(), String> {
        if !self.stopped || self.resume_on_drop {
            return Err(
                "legacy GUI termination requires a stopped identity and proven legacy retirement"
                    .into(),
            );
        }
        self.require_current_identity()?;
        signal(
            self.identity.pid,
            libc::SIGKILL,
            "terminate retired legacy GUI",
        )?;
        let deadline = Instant::now() + SIGNAL_CONFIRMATION_TIMEOUT;
        loop {
            if !identity_exists(&self.identity)? {
                self.stopped = false;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("retired legacy GUI did not terminate within two seconds".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn require_current_identity(&self) -> Result<(), String> {
        if identity_exists(&self.identity)? {
            Ok(())
        } else {
            Err("legacy GUI PID/start/executable identity changed; no signal was sent".into())
        }
    }

    pub(super) fn resume_persisted_if_stopped(identity: &LegacyGuiIdentity) -> Result<(), String> {
        if !identity_exists(identity)? {
            return Err("persisted legacy GUI identity no longer exists".into());
        }
        if !process_is_stopped(identity)? {
            return Ok(());
        }
        signal(identity.pid, libc::SIGCONT, "resume persisted legacy GUI")?;
        wait_for_state(identity, |state| !state.starts_with('T'))
    }

    pub(super) fn terminate_persisted_after_replacement_active(
        identity: &LegacyGuiIdentity,
    ) -> Result<(), String> {
        if !identity_exists(identity)? {
            return Ok(());
        }
        if !process_is_stopped(identity)? {
            return Err(
                "persisted legacy GUI is not stopped; refusing to signal an ambiguous process"
                    .into(),
            );
        }
        signal(
            identity.pid,
            libc::SIGKILL,
            "terminate persisted retired legacy GUI",
        )?;
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
        if self.stopped && self.resume_on_drop && self.require_current_identity().is_ok() {
            unsafe {
                libc::kill(self.identity.pid as libc::pid_t, libc::SIGCONT);
            }
        }
    }
}

fn legacy_gui_processes() -> Result<Vec<LegacyGuiIdentity>, String> {
    let output = Command::new("/bin/ps")
        .args(["-axo", "uid=,pid=,lstart=,command="])
        .output()
        .map_err(|error| format!("failed to inspect legacy GUI processes: {error}"))?;
    if !output.status.success() || output.stdout.len() > 1024 * 1024 {
        return Err("legacy GUI process observation failed or exceeded its bound".into());
    }
    let current_uid = unsafe { libc::geteuid() };
    let self_pid = std::process::id();
    let parsed = String::from_utf8(output.stdout)
        .map_err(|_| "legacy GUI process observation is not UTF-8".to_owned())?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_process)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(parsed
        .into_iter()
        .flatten()
        .filter(|process| process.uid == current_uid && process.pid != self_pid)
        .collect())
}

fn parse_process(line: &str) -> Result<Option<LegacyGuiIdentity>, String> {
    let mut fields = line.split_ascii_whitespace();
    let uid = fields
        .next()
        .ok_or_else(|| "legacy GUI process record is missing uid".to_owned())?
        .parse::<u32>()
        .map_err(|error| format!("legacy GUI uid is invalid: {error}"))?;
    let pid = fields
        .next()
        .ok_or_else(|| "legacy GUI process record is missing pid".to_owned())?
        .parse::<u32>()
        .map_err(|error| format!("legacy GUI pid is invalid: {error}"))?;
    let start_identity = (0..5)
        .map(|_| {
            fields
                .next()
                .ok_or_else(|| "legacy GUI start identity is incomplete".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    let command = fields.collect::<Vec<_>>().join(" ");
    if command != LEGACY_GUI_EXECUTABLE {
        return Ok(None);
    }
    Ok(Some(LegacyGuiIdentity {
        uid,
        pid,
        start_identity,
        executable: PathBuf::from(LEGACY_GUI_EXECUTABLE),
    }))
}

fn identity_exists(expected: &LegacyGuiIdentity) -> Result<bool, String> {
    Ok(legacy_gui_processes()?
        .iter()
        .any(|actual| actual == expected))
}

fn signal(pid: u32, signal: libc::c_int, operation: &str) -> Result<(), String> {
    if unsafe { libc::kill(pid as libc::pid_t, signal) } == -1 {
        Err(format!(
            "failed to {operation}: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

fn wait_for_state(
    identity: &LegacyGuiIdentity,
    accepted: impl Fn(&str) -> bool,
) -> Result<(), String> {
    let deadline = Instant::now() + SIGNAL_CONFIRMATION_TIMEOUT;
    loop {
        if !identity_exists(identity)? {
            return Err("legacy GUI exited while confirming its signal state".into());
        }
        let output = Command::new("/bin/ps")
            .args(["-o", "state=", "-p", &identity.pid.to_string()])
            .output()
            .map_err(|error| format!("failed to confirm legacy GUI state: {error}"))?;
        let state = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if output.status.success() && accepted(&state) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("legacy GUI signal state was not confirmed within two seconds".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn process_is_stopped(identity: &LegacyGuiIdentity) -> Result<bool, String> {
    let output = Command::new("/bin/ps")
        .args(["-o", "state=", "-p", &identity.pid.to_string()])
        .output()
        .map_err(|error| format!("failed to inspect legacy GUI state: {error}"))?;
    if !output.status.success() || output.stdout.len() > 1024 {
        return Err("legacy GUI state observation failed or exceeded its bound".into());
    }
    Ok(String::from_utf8(output.stdout)
        .map_err(|_| "legacy GUI state observation is not UTF-8".to_owned())?
        .trim()
        .starts_with('T'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_matches_only_the_exact_fixed_legacy_gui_executable() {
        let line = "501 42 Tue Jul 21 21:30:57 2026 /Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac";
        let parsed = parse_process(line).expect("parse").expect("identity");
        assert_eq!(parsed.pid, 42);
        assert_eq!(parsed.start_identity, "Tue Jul 21 21:30:57 2026");
        assert!(
            parse_process(&format!("{line} --extra"))
                .expect("parse extra")
                .is_none()
        );
        assert!(
            parse_process("501 42 Tue Jul 21 21:30:57 2026 /tmp/clash-for-mac")
                .expect("parse other")
                .is_none()
        );
    }
}

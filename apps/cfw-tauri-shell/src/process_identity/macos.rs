//! Darwin process observations shared by migration and update installation.
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

const MAX_PROCESS_LIST_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessStartIdentity {
    pub(crate) seconds: u64,
    pub(crate) microseconds: u32,
}

impl ProcessStartIdentity {
    pub(crate) fn is_valid(self) -> bool {
        self.seconds > 0 && self.microseconds < 1_000_000
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessIdentity {
    pub(crate) uid: u32,
    pub(crate) pid: u32,
    pub(crate) start_identity: ProcessStartIdentity,
    pub(crate) executable: PathBuf,
}

impl ProcessIdentity {
    /// Whether the identity names the calling process, whatever path its
    /// executable has by now.
    pub(crate) fn is_this_process(&self) -> bool {
        self.pid == std::process::id()
    }
}

pub(crate) fn current_process_identity(executable: &Path) -> Result<ProcessIdentity, String> {
    observe_exact_process(std::process::id(), executable)?
        .ok_or_else(|| "this process is not running the expected executable".to_owned())
}

pub(crate) fn exact_processes(executable: &Path) -> Result<Vec<ProcessIdentity>, String> {
    let mut matches = process_ids()?
        .into_iter()
        .filter_map(|pid| observe_exact_process(pid, executable).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    if matches.len() > 8 {
        return Err("more than eight exact GUI process identities were observed".into());
    }
    matches.sort_by_key(|identity| identity.pid);
    Ok(matches)
}

pub(crate) fn process_identity_exists(expected: &ProcessIdentity) -> Result<bool, String> {
    Ok(observe_exact_process(expected.pid, &expected.executable)?.as_ref() == Some(expected))
}

pub(crate) fn observe_exact_process(
    pid: u32,
    executable: &Path,
) -> Result<Option<ProcessIdentity>, String> {
    observe_kernel_process(pid, executable)
}

fn observe_kernel_process(
    pid: u32,
    expected_executable: &Path,
) -> Result<Option<ProcessIdentity>, String> {
    let Ok(pid_signed) = libc::pid_t::try_from(pid) else {
        return Err("process PID is outside Darwin's signed PID range".into());
    };
    if pid_signed <= 0 {
        return Ok(None);
    }
    // The kernel refuses the full identity of another user's process. Such a
    // process is never the one sought, and its owner is readable by anyone.
    if process_owner(pid_signed)? != Some(unsafe { libc::geteuid() }) {
        return Ok(None);
    }
    let Some(before) = process_bsd_info(pid_signed)? else {
        return Ok(None);
    };
    if before.pbi_uid != unsafe { libc::geteuid() } || before.pbi_pid != pid {
        return Ok(None);
    }
    let mut path = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let path_length = unsafe {
        libc::proc_pidpath(
            pid_signed,
            path.as_mut_ptr().cast(),
            u32::try_from(path.len()).expect("Darwin process path bound fits u32"),
        )
    };
    if path_length <= 0 {
        let error = std::io::Error::last_os_error();
        // ESRCH: the process is gone. ENOENT: its executable no longer has a
        // path, as after an application was replaced while running; it is
        // then not the file at the expected path.
        if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) {
            return Ok(None);
        }
        return Err(format!(
            "failed to resolve kernel executable identity for process {pid}: {error}"
        ));
    }
    if path_length as usize >= path.len() {
        return Err("kernel process executable path reached its truncation bound".into());
    }
    path.truncate(path_length as usize);
    if path.last() == Some(&0) {
        path.pop();
    }
    let executable = PathBuf::from(OsString::from_vec(path));
    if executable != expected_executable {
        return Ok(None);
    }
    let Some(after) = process_bsd_info(pid_signed)? else {
        return Ok(None);
    };
    if !same_process_incarnation(&before, &after) {
        return Err("process identity changed during kernel observation".into());
    }
    Ok(Some(ProcessIdentity {
        uid: after.pbi_uid,
        pid: after.pbi_pid,
        start_identity: ProcessStartIdentity {
            seconds: after.pbi_start_tvsec,
            microseconds: u32::try_from(after.pbi_start_tvusec)
                .map_err(|_| "kernel process start microseconds overflowed".to_owned())?,
        },
        executable,
    }))
}

/// The effective user of a live process, from the short identity every user
/// may read. An absent process has no owner.
fn process_owner(pid: libc::pid_t) -> Result<Option<libc::uid_t>, String> {
    classify_process_owner(pid, read_process_short_info(pid))
}

fn read_process_short_info(pid: libc::pid_t) -> std::io::Result<libc::proc_bsdshortinfo> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdshortinfo>::zeroed();
    let expected = std::mem::size_of::<libc::proc_bsdshortinfo>();
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDT_SHORTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(expected).expect("proc_bsdshortinfo size fits i32"),
        )
    };
    if result <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    if result as usize != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("kernel process owner had unexpected size {result}"),
        ));
    }
    Ok(unsafe { info.assume_init() })
}

fn classify_process_owner(
    pid: libc::pid_t,
    observation: std::io::Result<libc::proc_bsdshortinfo>,
) -> Result<Option<libc::uid_t>, String> {
    match observation {
        Ok(info) => Ok(Some(info.pbsi_uid)),
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(None),
        Err(error) => Err(format!(
            "failed to read kernel process owner for PID {pid}: {error}"
        )),
    }
}

fn process_bsd_info(pid: libc::pid_t) -> Result<Option<libc::proc_bsdinfo>, String> {
    classify_process_bsd_info(pid, read_process_bsd_info(pid))
}

fn read_process_bsd_info(pid: libc::pid_t) -> std::io::Result<libc::proc_bsdinfo> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected = std::mem::size_of::<libc::proc_bsdinfo>();
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(expected).expect("proc_bsdinfo size fits i32"),
        )
    };
    if result <= 0 {
        // errno belongs to this query. A second syscall can overwrite it;
        // kill(pid, 0) also continues to succeed for an unreaped exited parent.
        return Err(std::io::Error::last_os_error());
    }
    if result as usize != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("kernel process identity had unexpected size {result}"),
        ));
    }
    Ok(unsafe { info.assume_init() })
}

fn classify_process_bsd_info(
    pid: libc::pid_t,
    observation: std::io::Result<libc::proc_bsdinfo>,
) -> Result<Option<libc::proc_bsdinfo>, String> {
    match observation {
        // Darwin defines SZOMB as exited and awaiting collection by its
        // parent. It cannot keep the handoff's live-parent boundary occupied.
        Ok(info) if info.pbi_status == libc::SZOMB => Ok(None),
        Ok(info) => Ok(Some(info)),
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(None),
        Err(error) => Err(format!(
            "failed to read kernel process identity for PID {pid}: {error}"
        )),
    }
}

fn same_process_incarnation(left: &libc::proc_bsdinfo, right: &libc::proc_bsdinfo) -> bool {
    left.pbi_pid == right.pbi_pid
        && left.pbi_uid == right.pbi_uid
        && left.pbi_start_tvsec == right.pbi_start_tvsec
        && left.pbi_start_tvusec == right.pbi_start_tvusec
}

/// The processes of this user: the only ones an exact identity is sought
/// among, and the only ones whose full identity the kernel reveals.
fn process_ids() -> Result<Vec<u32>, String> {
    const PROC_UID_ONLY: u32 = 4;
    let mut pids = vec![0_i32; MAX_PROCESS_LIST_BYTES / std::mem::size_of::<i32>()];
    let bytes = unsafe {
        libc::proc_listpids(
            PROC_UID_ONLY,
            libc::geteuid(),
            pids.as_mut_ptr().cast(),
            i32::try_from(MAX_PROCESS_LIST_BYTES).expect("process list bound fits i32"),
        )
    };
    if bytes < 0 {
        return Err(format!(
            "failed to enumerate kernel process identities: {}",
            std::io::Error::last_os_error()
        ));
    }
    if bytes as usize >= MAX_PROCESS_LIST_BYTES
        || !(bytes as usize).is_multiple_of(std::mem::size_of::<i32>())
    {
        return Err("kernel process enumeration exceeded its bound or was malformed".into());
    }
    pids.truncate(bytes as usize / std::mem::size_of::<i32>());
    Ok(pids
        .into_iter()
        .filter_map(|pid| u32::try_from(pid).ok().filter(|pid| *pid > 0))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn fixture_identity(pid: u32, executable: &Path) -> ProcessIdentity {
        ProcessIdentity {
            uid: unsafe { libc::geteuid() },
            pid,
            start_identity: ProcessStartIdentity {
                seconds: 1_721_599_857,
                microseconds: 123_456,
            },
            executable: executable.to_path_buf(),
        }
    }

    #[test]
    fn kernel_process_identity_binds_pid_uid_path_and_microsecond_start() {
        let executable = std::env::current_exe().expect("current executable");
        let parsed = observe_exact_process(std::process::id(), &executable)
            .expect("observe")
            .expect("identity");
        assert_eq!(parsed.pid, std::process::id());
        assert_eq!(parsed.uid, unsafe { libc::geteuid() });
        assert_eq!(parsed.executable, executable);
        assert!(parsed.start_identity.is_valid());
        assert!(process_identity_exists(&parsed).expect("identity still exists"));
    }

    #[test]
    fn the_real_process_table_is_enumerated_to_exactly_this_users_matches() {
        // The table holds processes of other users, whose full identity the
        // kernel refuses to an unprivileged caller.
        let executable = std::env::current_exe().expect("current executable");
        let own = observe_exact_process(std::process::id(), &executable)
            .expect("observe")
            .expect("identity");
        let listed = exact_processes(&executable).expect("the process table is observable");
        assert!(listed.contains(&own), "{listed:?}");
        assert!(
            listed
                .iter()
                .all(|identity| identity.uid == own.uid && identity.executable == executable),
            "{listed:?}"
        );
        assert_eq!(
            exact_processes(Path::new("/nonexistent/executable")).expect("observable"),
            []
        );
    }

    #[test]
    fn a_process_whose_executable_was_removed_is_not_the_exact_executable() {
        // Any application replaced while it runs is such a process, and it
        // must not make the whole table unobservable.
        let scratch = tempfile::tempdir().expect("scratch");
        let executable = std::fs::canonicalize(scratch.path())
            .expect("canonical scratch")
            .join("removed-while-running");
        std::fs::copy("/bin/sleep", &executable).expect("copy a system tool");
        let mut child = std::process::Command::new(&executable)
            .arg("30")
            .spawn()
            .expect("run the copy");
        std::fs::remove_file(&executable).expect("remove the running executable");

        let observed = observe_exact_process(child.id(), &executable);
        let listed = exact_processes(&executable);
        child.kill().expect("stop the copy");
        child.wait().expect("reap the copy");

        assert_eq!(observed.expect("observable"), None);
        assert_eq!(listed.expect("the process table is observable"), []);
    }

    #[test]
    fn a_process_of_another_user_is_not_this_users_and_not_an_error() {
        // launchd always runs, as root.
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "the tests do not run as root"
        );
        assert_eq!(
            observe_exact_process(1, Path::new("/sbin/launchd")).expect("observable"),
            None
        );
        let recorded_then_reused = fixture_identity(1, Path::new("/sbin/launchd"));
        assert!(!process_identity_exists(&recorded_then_reused).expect("observable"));
    }

    #[test]
    fn missing_pid_is_a_proven_absence_not_an_observation_failure() {
        let missing = fixture_identity(
            i32::MAX as u32,
            Path::new("/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac"),
        );
        assert!(!process_identity_exists(&missing).expect("missing process is observable"));
    }

    #[test]
    fn kernel_process_query_esrch_is_absence_without_a_second_probe() {
        let observed =
            classify_process_bsd_info(42, Err(std::io::Error::from_raw_os_error(libc::ESRCH)))
                .expect("kernel-reported process absence");
        assert!(observed.is_none());
    }

    #[test]
    fn kernel_process_query_permission_and_io_errors_remain_failures() {
        for errno in [libc::EPERM, libc::EACCES, libc::EIO] {
            let expected = std::io::Error::from_raw_os_error(errno).to_string();
            let error =
                classify_process_bsd_info(42, Err(std::io::Error::from_raw_os_error(errno)))
                    .expect_err("non-absence errors must remain visible");
            assert_eq!(
                error,
                format!("failed to read kernel process identity for PID 42: {expected}")
            );
        }
    }

    #[test]
    fn an_unreadable_process_owner_is_an_error_and_an_absent_process_has_none() {
        assert_eq!(
            classify_process_owner(42, Err(std::io::Error::from_raw_os_error(libc::ESRCH))),
            Ok(None)
        );
        for errno in [libc::EPERM, libc::EIO] {
            let expected = std::io::Error::from_raw_os_error(errno).to_string();
            assert_eq!(
                classify_process_owner(42, Err(std::io::Error::from_raw_os_error(errno))),
                Err(format!(
                    "failed to read kernel process owner for PID 42: {expected}"
                ))
            );
        }
        assert_eq!(process_owner(1).expect("launchd owner"), Some(0));
        assert_eq!(
            process_owner(libc::pid_t::try_from(std::process::id()).expect("pid"))
                .expect("own owner"),
            Some(unsafe { libc::geteuid() })
        );
    }

    #[test]
    fn malformed_kernel_process_observation_remains_an_error() {
        let error = classify_process_bsd_info(
            42,
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "kernel process identity had unexpected size 1",
            )),
        )
        .expect_err("a short kernel record cannot prove absence");
        assert_eq!(
            error,
            "failed to read kernel process identity for PID 42: kernel process identity had unexpected size 1"
        );
    }

    #[test]
    fn exited_kernel_record_is_absent_but_live_and_stopped_records_remain() {
        for status in [libc::SRUN, libc::SSLEEP, libc::SSTOP, libc::SZOMB] {
            let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
            info.pbi_status = status;
            info.pbi_pid = 42;
            info.pbi_uid = unsafe { libc::geteuid() };
            info.pbi_start_tvsec = 1_000;
            info.pbi_start_tvusec = 123_456;
            let observed = classify_process_bsd_info(42, Ok(info)).expect("kernel record");
            if status == libc::SZOMB {
                assert!(observed.is_none());
            } else {
                let observed = observed.expect("live or stopped process is still present");
                assert_eq!(observed.pbi_status, status);
                assert_eq!(observed.pbi_pid, 42);
                assert_eq!(observed.pbi_uid, unsafe { libc::geteuid() });
                assert_eq!(observed.pbi_start_tvsec, 1_000);
                assert_eq!(observed.pbi_start_tvusec, 123_456);
            }
        }
    }

    #[test]
    fn exited_unreaped_process_is_absent_at_the_handoff_boundary() {
        let executable = Path::new("/bin/cat");
        let mut child = Command::new(executable)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn owned process waiting for EOF");
        let pid = child.id();
        let identity = observe_exact_process(pid, executable);
        drop(child.stdin.take());

        let observation = (|| -> Result<bool, String> {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let mut status = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
                // WNOWAIT proves exit while retaining the kernel's unreaped
                // process record, as the handoff child can observe its parent.
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid,
                        status.as_mut_ptr(),
                        libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                    )
                };
                if result != 0 {
                    return Err(format!(
                        "owned process exit observation failed: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                let status = unsafe { status.assume_init() };
                if status.si_pid == libc::pid_t::try_from(pid).expect("owned child PID") {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("owned process did not exit after EOF within five seconds".into());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            let identity = identity
                .as_ref()
                .map_err(Clone::clone)?
                .as_ref()
                .ok_or_else(|| "owned process was not observed alive before EOF".to_owned())?;
            process_identity_exists(identity)
        })();

        // Reap our process even when the production observation reports an
        // error; the assertion below must not leave a test-owned zombie.
        assert!(child.wait().expect("reap owned process").success());
        assert!(identity.expect("live kernel observation").is_some());
        assert!(!observation.expect("exited process is observable as absent"));
    }
}

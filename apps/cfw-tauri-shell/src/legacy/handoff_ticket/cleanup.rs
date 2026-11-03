//! The fail-closed cleanup of a pending hand-off: the armed boundary that
//! owns the launched instance, its exact termination, and the removal of the
//! hand-off's documents.

use super::*;

#[derive(Clone)]
pub(super) struct HandoffCleanup {
    pub(super) root: PathBuf,
    pub(super) token: String,
}

pub(super) trait CleanupBoundary {
    fn cleanup(&mut self) -> Result<(), String>;
}

/// Owns one fail-closed cleanup boundary. It is armed before the blocking task
/// is spawned, so dropping an unstarted closure, unwinding a worker, or aborting
/// its async caller all execute the same bounded cleanup. Only the successful
/// parent shutdown path may call `disarm`.
pub(super) struct ArmedCleanup<T: CleanupBoundary> {
    resource: Option<T>,
}

impl<T: CleanupBoundary> ArmedCleanup<T> {
    pub(super) fn new(resource: T) -> Self {
        Self {
            resource: Some(resource),
        }
    }

    fn resource_mut(&mut self) -> &mut T {
        self.resource
            .as_mut()
            .expect("armed handoff cleanup resource")
    }

    fn cleanup_now(&mut self) -> Result<(), String> {
        let Some(resource) = self.resource.as_mut() else {
            return Ok(());
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| resource.cleanup()));
        self.resource = None;
        match outcome {
            Ok(result) => result,
            Err(_) => Err("migration handoff cleanup panicked".into()),
        }
    }

    pub(super) fn disarm(&mut self) {
        self.resource = None;
    }
}

impl<T: CleanupBoundary> Drop for ArmedCleanup<T> {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup_now() {
            eprintln!("migration handoff cleanup after task termination failed: {error}");
        }
    }
}

struct PendingHandoffResources {
    pending: PendingHandoff,
    child: Option<Child>,
}

impl CleanupBoundary for PendingHandoffResources {
    fn cleanup(&mut self) -> Result<(), String> {
        let executable = self.pending.ticket.child_executable.clone();
        let documents = self.pending.cleanup_handle();
        cleanup_handoff_resources(
            self.child
                .as_mut()
                .map(|child| child as &mut dyn ChildProcess),
            &executable,
            &SystemProcessOperations,
            || documents.cleanup(),
        )
    }
}

pub(in crate::legacy) struct PendingHandoffChild {
    cleanup: ArmedCleanup<PendingHandoffResources>,
}

impl PendingHandoffChild {
    pub(super) fn new(pending: PendingHandoff) -> Self {
        Self {
            cleanup: ArmedCleanup::new(PendingHandoffResources {
                pending,
                child: None,
            }),
        }
    }

    pub(in crate::legacy) fn launch_until_ready(mut self) -> Result<Self, String> {
        let launch = self.cleanup.resource_mut().pending.spawn();
        match launch {
            Ok(child) => self.cleanup.resource_mut().child = Some(child),
            Err(error) => return self.fail(error),
        }
        let readiness = {
            let resources = self.cleanup.resource_mut();
            resources.pending.wait_until_ready(
                resources
                    .child
                    .as_mut()
                    .expect("launched migration handoff child"),
            )
        };
        match readiness {
            Ok(()) => Ok(self),
            Err(error) => self.fail(error),
        }
    }

    pub(in crate::legacy) fn fail<T>(mut self, operation: String) -> Result<T, String> {
        match self.cleanup.cleanup_now() {
            Ok(()) => Err(operation),
            Err(cleanup) => Err(format!(
                "{operation}; migration handoff cleanup also failed: {cleanup}"
            )),
        }
    }

    pub(in crate::legacy) fn disarm(mut self) {
        self.cleanup.disarm();
    }
}

impl HandoffCleanup {
    fn cleanup(&self) -> Result<(), String> {
        let directory = PrivateDirectory::open_or_create(&self.root)?;
        let mut failures = Vec::new();
        for (kind, name) in [
            ("startup ticket", ticket_filename(&self.token)),
            ("readiness acknowledgement", ready_filename(&self.token)),
        ] {
            if let Err(error) = directory.unlink_optional(&name) {
                failures.push(format!("{kind}: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

pub(super) trait ChildProcess {
    fn process_id(&self) -> u32;
    fn has_exited(&mut self) -> Result<bool, String>;
    fn reap(&mut self) -> Result<(), String>;
}

impl ChildProcess for Child {
    fn process_id(&self) -> u32 {
        self.id()
    }

    fn has_exited(&mut self) -> Result<bool, String> {
        self.try_wait()
            .map(|status| status.is_some())
            .map_err(|error| format!("failed to observe migration child exit: {error}"))
    }

    fn reap(&mut self) -> Result<(), String> {
        self.wait()
            .map(|_| ())
            .map_err(|error| format!("failed to reap migration child: {error}"))
    }
}

pub(super) trait ProcessOperations {
    fn observe(&self, pid: u32, executable: &Path) -> Result<Option<ProcessIdentity>, String>;
    fn signal(&self, pid: u32, signal: libc::c_int) -> Result<(), String>;
    fn wait_bounded(&self, child: &mut dyn ChildProcess, timeout: Duration)
    -> Result<bool, String>;
}

struct SystemProcessOperations;

impl ProcessOperations for SystemProcessOperations {
    fn observe(&self, pid: u32, executable: &Path) -> Result<Option<ProcessIdentity>, String> {
        observe_exact_process(pid, executable)
    }

    fn signal(&self, pid: u32, signal: libc::c_int) -> Result<(), String> {
        if unsafe { libc::kill(pid as libc::pid_t, signal) } == -1 {
            Err(format!(
                "failed to signal migration child: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }

    fn wait_bounded(
        &self,
        child: &mut dyn ChildProcess,
        timeout: Duration,
    ) -> Result<bool, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if child.has_exited()? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

pub(super) fn cleanup_handoff_resources<F>(
    child: Option<&mut dyn ChildProcess>,
    executable: &Path,
    operations: &dyn ProcessOperations,
    cleanup_documents: F,
) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    let termination = child
        .map(|child| terminate_exact_process_with(child, executable, operations))
        .unwrap_or(Ok(()));
    let documents = cleanup_documents();
    match (termination, documents) {
        (Ok(()), Ok(())) => Ok(()),
        (termination, documents) => Err(format!(
            "termination={termination:?}, documents={documents:?}"
        )),
    }
}

pub(super) fn terminate_exact_process_with(
    child: &mut dyn ChildProcess,
    executable: &Path,
    operations: &dyn ProcessOperations,
) -> Result<(), String> {
    if child.has_exited()? {
        return child.reap();
    }
    // This PID belongs to our Child and remains unreaped throughout each
    // signal boundary, so Darwin cannot recycle it. Kernel incarnation checks
    // are still repeated before SIGTERM and SIGKILL to bind the ticket path.
    let pid = child.process_id();
    let identity = operations
        .observe(pid, executable)?
        .ok_or_else(|| "migration child identity changed; no signal was sent".to_owned())?;
    if operations.observe(pid, executable)?.as_ref() != Some(&identity) {
        return Err("migration child identity changed at the graceful signal boundary".into());
    }
    operations.signal(identity.pid, libc::SIGTERM)?;
    if operations.wait_bounded(child, TERMINATION_TIMEOUT)? {
        return child.reap();
    }
    if operations.observe(pid, executable)?.as_ref() != Some(&identity) {
        return Err("migration child identity changed before forced termination".into());
    }
    operations.signal(pid, libc::SIGKILL)?;
    child.reap()
}

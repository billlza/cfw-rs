//! One read-only request in a verified, suspended-then-admitted native worker.
//! The existing explicit handle list and atomic cleanup Job are shared with
//! engine launch. A result requires observed process exits, drained I/O and an
//! empty Job whose lifetime process population is completely accounted for.
use super::*;
use std::io::Write;

mod retirement;
use retirement::RetirementWitnesses;

const MAX_REQUEST: usize = 16 * 1024;
pub(crate) const MAX_REPLY: usize = 4096;
const TICK: Duration = Duration::from_millis(10);
const CLEANUP: Duration = Duration::from_secs(5);

pub(crate) struct Reply {
    pub bytes: Vec<u8>,
    pub process_id: u32,
    pub exit_code: i32,
}

pub(crate) fn run(
    executable: VerifiedExecutable,
    directory: &Path,
    request: Vec<u8>,
    timeout: Duration,
    cancelled: impl Fn() -> bool,
) -> Result<Reply, Error> {
    let deadline = deadline(timeout)?;
    if request.is_empty() || request.len() > MAX_REQUEST {
        return Err(Error::Protocol("inspection request size is invalid"));
    }
    if cancelled() {
        return Err(Error::Cancelled);
    }
    let assets = spawn_assets_for(
        executable,
        directory,
        None,
        child::Program::PackageInspection,
        None,
    )?;
    let mut process = OneShot {
        assets,
        io: None,
        assigned: false,
        closed: false,
        witnesses: None,
    };
    let result = process.exchange(request, deadline, &cancelled);
    let cleaned = process.retire(result.is_err());
    match (result, cleaned) {
        (Ok(reply), Ok(())) => Ok(reply),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(Error::CleanupFailed {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}

struct OneShot {
    assets: SpawnAssets,
    io: Option<JoinHandle<Result<Vec<u8>, Error>>>,
    assigned: bool,
    closed: bool,
    witnesses: Option<RetirementWitnesses>,
}

impl OneShot {
    fn exchange(
        &mut self,
        request: Vec<u8>,
        deadline: Instant,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Reply, Error> {
        let mut member = 0;
        // SAFETY: both handles are retained and the output is a valid BOOL.
        if unsafe {
            IsProcessInJob(
                self.assets.child.as_raw_handle(),
                self.assets.job.as_raw_handle(),
                &mut member,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if member == 0 {
            return Err(Error::Protocol("inspection worker has no cleanup job"));
        }
        self.assigned = true;
        self.assets.child.verify(&self.assets.executable)?;
        // Capture creation-time members while the root is still suspended.
        // Retain them across normal exit as well as cancellation.
        self.witnesses = Some(RetirementWitnesses::capture(&self.assets)?);
        remaining(deadline)?;
        if cancelled() {
            return Err(Error::Cancelled);
        }
        let mut input = self
            .assets
            .child
            .stdin
            .take()
            .ok_or(Error::Protocol("worker stdin missing"))?;
        let output = self
            .assets
            .child
            .stdout
            .take()
            .ok_or(Error::Protocol("worker stdout missing"))?;
        self.io = Some(
            thread::Builder::new()
                .name("cfw-update-inspection".into())
                .spawn(move || {
                    input.write_all(&request)?;
                    drop(input); // EOF closes the single request; no further input is accepted.
                    let mut reply = Vec::new();
                    output
                        .take((MAX_REPLY + 1) as u64)
                        .read_to_end(&mut reply)?;
                    Ok(reply)
                })?,
        );
        self.assets.child.resume()?;
        loop {
            self.observe_members()?;
            if cancelled() {
                return Err(Error::Cancelled);
            }
            remaining(deadline)?;
            if self.io.as_ref().is_some_and(JoinHandle::is_finished) {
                break;
            }
            thread::sleep(TICK);
        }
        let bytes = self
            .io
            .take()
            .ok_or(Error::Cleanup)?
            .join()
            .map_err(|_| Error::Cleanup)??;
        if bytes.is_empty() || bytes.len() > MAX_REPLY {
            return Err(Error::Protocol("inspection reply size is invalid"));
        }
        let exit_code = loop {
            self.observe_members()?;
            if cancelled() {
                return Err(Error::Cancelled);
            }
            remaining(deadline)?;
            if let Some(status) = self.assets.child.try_wait()? {
                let code = status
                    .code()
                    .ok_or(Error::Protocol("inspection worker exit unavailable"))?;
                if !matches!(code, 0 | 2) {
                    return Err(Error::Protocol("inspection worker failed"));
                }
                break code;
            }
            thread::sleep(TICK);
        };
        Ok(Reply {
            bytes,
            process_id: self.assets.child.id(),
            exit_code,
        })
    }

    fn retire(&mut self, abort: bool) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        let end = Instant::now() + CLEANUP;
        // Capture exact members before termination can remove them from Job
        // accounting. Capture failure must not prevent the owned Job/pipe
        // cleanup below, but it must prevent a successful cleanup result.
        let captured = self.observe_members();
        if abort {
            if self.assigned {
                // SAFETY: only this worker and its descendants belong to this
                // unnamed Job. It never contains the caller or runtime services.
                if unsafe { TerminateJobObject(self.assets.job.as_raw_handle(), 2) } == 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            } else if self.assets.child.try_wait()?.is_none() {
                self.assets.child.kill()?;
            }
        }
        wait_process(&self.assets.child, end)?;
        while active_processes(&self.assets.job)? != 0 {
            remaining(end)?;
            thread::sleep(TICK);
        }
        if let Some(io) = self.io.as_ref() {
            while !io.is_finished() {
                remaining(end)?;
                thread::sleep(TICK);
            }
        }
        if let Some(io) = self.io.take() {
            // The original operation accounts for pipe failure after an abort;
            // joining still must prove that its I/O thread actually retired.
            match io.join().map_err(|_| Error::Cleanup)? {
                Ok(_) => {}
                Err(Error::Io(error))
                    if abort && matches!(error.raw_os_error(), Some(109 | 232 | 233 | 995)) =>
                {
                    // Closing this exact owned process/Job interrupts its pipes.
                    // No unrelated I/O, protocol or identity failure is hidden.
                }
                Err(error) => return Err(error),
            }
        }
        captured?;
        self.witnesses
            .as_ref()
            .ok_or(Error::Cleanup)?
            .wait(&self.assets.job, end)?;
        self.closed = true;
        Ok(())
    }

    fn observe_members(&mut self) -> Result<(), Error> {
        match &mut self.witnesses {
            Some(witnesses) => witnesses.observe(&self.assets),
            None => {
                self.witnesses = Some(RetirementWitnesses::capture(&self.assets)?);
                Ok(())
            }
        }
    }
}

impl Drop for OneShot {
    fn drop(&mut self) {
        if !self.closed
            && let Err(error) = self.retire(true)
        {
            eprintln!("update inspection worker cleanup failed: {error}");
        }
    }
}

#[cfg(all(test, feature = "native-package-validation"))]
mod tests;

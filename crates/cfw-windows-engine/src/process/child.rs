//! Explicit native creation: three selected stdio handles and an atomic local
//! Job assignment. The owner retains failures before the suspended thread runs.
use super::{Error, VerifiedExecutable};
use crate::{NativePeerIdentity, NativePeerProcess, process_handles::ProcessHandleList};
use std::{
    fs::File,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle, RawHandle},
        process::ExitStatusExt,
    },
    path::Path,
    process::ExitStatus,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::{
        Pipes::CreatePipe,
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess,
            PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
            TerminateProcess, WaitForSingleObject,
        },
    },
};

fn native(operation: &'static str) -> Error {
    Error::Operation {
        operation,
        source: io::Error::last_os_error(),
    }
}
fn peer_error(source: crate::PeerIdentityError) -> Error {
    Error::Operation {
        operation: "observe worker process identity",
        source: io::Error::other(source),
    }
}

pub(super) struct NativeChild {
    process: OwnedHandle,
    thread: Option<OwnedHandle>,
    id: u32,
    creator: NativePeerIdentity,
    pub(super) stdin: Option<File>,
    pub(super) stdout: Option<File>,
}
impl AsRawHandle for NativeChild {
    fn as_raw_handle(&self) -> RawHandle {
        self.process.as_raw_handle()
    }
}
impl NativeChild {
    pub(super) fn spawn(
        executable: &VerifiedExecutable,
        directory: &Path,
        job: BorrowedHandle<'_>,
    ) -> Result<Self, Error> {
        let parent = NativePeerProcess::open(std::process::id()).map_err(peer_error)?;
        let (input_read, input_write) = pipe()?;
        let (output_read, output_write) = pipe()?;
        let input = inherit(input_read.as_handle())?;
        let output = inherit(output_write.as_handle())?;
        // Keep unstructured engine diagnostics out of files and logs; the
        // existing framed protocol provides bounded, stable error codes.
        let null_output = File::options().write(true).open(r"\\.\NUL")?;
        let error = inherit(null_output.as_handle())?;
        let mut attributes = ProcessHandleList::with_job(
            &[input.as_handle(), output.as_handle(), error.as_handle()],
            job,
        )?;
        let application = terminated_path(executable.path())?;
        let current_directory = terminated_path(directory)?;
        let mut command = Vec::with_capacity(application.len() + 2);
        command.push(u16::from(b'"'));
        command.extend_from_slice(&application[..application.len() - 1]);
        command.extend([u16::from(b'"'), 0]);
        if command.len() > 32767 {
            return Err(Error::ExecutableIdentity);
        }
        let startup = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: size_of::<STARTUPINFOEXW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: input.as_raw_handle(),
                hStdOutput: output.as_raw_handle(),
                hStdError: error.as_raw_handle(),
                ..Default::default()
            },
            lpAttributeList: attributes.pointer(),
        };
        parent.revalidate().map_err(peer_error)?;
        let creator = parent.identity().clone();
        let mut info = PROCESS_INFORMATION::default();
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_NO_WINDOW
                    | CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                null(),
                current_directory.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err(native("create suspended verified worker"));
        }
        // No fallible operation follows successful creation before returning
        // ownership. Admission, resume and cleanup belong to EngineProcess.
        Ok(Self {
            process: unsafe { OwnedHandle::from_raw_handle(info.hProcess) },
            thread: Some(unsafe { OwnedHandle::from_raw_handle(info.hThread) }),
            id: info.dwProcessId,
            creator,
            stdin: Some(File::from(input_write)),
            stdout: Some(File::from(output_read)),
        })
    }
    pub(super) fn id(&self) -> u32 {
        self.id
    }
    pub(super) fn verify(&self, executable: &VerifiedExecutable) -> Result<(), Error> {
        if self.try_wait()?.is_some() {
            return Err(Error::Exited);
        }
        executable.verify_process_image(&self.process)?;
        let actual = NativePeerProcess::open(self.id).map_err(peer_error)?;
        let actual = actual.identity();
        if actual.user_session() != self.creator.user_session()
            || actual.integrity_rid() != self.creator.integrity_rid()
            || actual.is_app_container() != self.creator.is_app_container()
            || actual.is_restricted() != self.creator.is_restricted()
        {
            return Err(Error::ExecutableIdentity);
        }
        if self.try_wait()?.is_some() {
            return Err(Error::Exited);
        }
        Ok(())
    }
    pub(super) fn resume(&mut self) -> Result<(), Error> {
        let thread = self
            .thread
            .as_ref()
            .ok_or(Error::Protocol("worker already resumed"))?;
        let count = unsafe { ResumeThread(thread.as_raw_handle()) };
        if count == u32::MAX {
            return Err(native("resume admitted worker"));
        }
        if count != 1 {
            return Err(Error::Protocol(
                "worker suspension changed before admission",
            ));
        }
        self.thread.take();
        Ok(())
    }
    pub(super) fn try_wait(&self) -> Result<Option<ExitStatus>, Error> {
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                    return Err(native("observe worker exit code"));
                }
                // The signaled handle, not the magic STILL_ACTIVE exit value,
                // proves retirement. A process may actually exit with code 259.
                Ok(Some(ExitStatus::from_raw(code)))
            }
            WAIT_FAILED => Err(native("observe worker exit")),
            _ => Err(Error::Protocol("invalid worker process wait result")),
        }
    }
    pub(super) fn exit_status(&self) -> Result<ExitStatus, Error> {
        self.try_wait()?
            .ok_or(Error::Protocol("worker has not exited"))
    }
    pub(super) fn kill(&self) -> Result<(), Error> {
        if unsafe { TerminateProcess(self.process.as_raw_handle(), 2) } != 0 {
            return Ok(());
        }
        let failure = native("terminate unadmitted worker");
        match self.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(failure),
            Err(observation) => Err(Error::CleanupFailed {
                operation: Box::new(failure),
                cleanup: Box::new(observation),
            }),
        }
    }
}
fn terminated_path(path: &Path) -> Result<Vec<u16>, Error> {
    let units: Vec<_> = path.as_os_str().encode_wide().collect();
    if !path.is_absolute()
        || units.is_empty()
        || units.len() >= 32767
        || units.contains(&0)
        || units.contains(&u16::from(b'"'))
    {
        return Err(Error::ExecutableIdentity);
    }
    Ok(units.into_iter().chain([0]).collect())
}
fn pipe() -> Result<(OwnedHandle, OwnedHandle), Error> {
    let (mut read, mut write) = (null_mut(), null_mut());
    if unsafe { CreatePipe(&mut read, &mut write, null(), 0) } == 0 {
        return Err(native("create worker control pipe"));
    }
    Ok((unsafe { OwnedHandle::from_raw_handle(read) }, unsafe {
        OwnedHandle::from_raw_handle(write)
    }))
}
fn inherit(handle: BorrowedHandle<'_>) -> Result<OwnedHandle, Error> {
    let mut duplicate = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle.as_raw_handle(),
            GetCurrentProcess(),
            &mut duplicate,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(native("duplicate selected worker handle"));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate) })
}

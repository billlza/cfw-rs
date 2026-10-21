//! ActiveProcesses can reach zero before a member's process object is signaled.
//! Retain the observed members and require their actual exit, then compare the
//! complete lifetime count so concurrent or already departed members cannot be
//! silently omitted. An incomplete census is an explicit cleanup failure.
use super::*;
use windows_sys::Win32::System::{
    JobObjects::JobObjectBasicProcessIdList,
    Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE},
};

const MAX_MEMBERS: usize = 64;

// JOBOBJECT_BASIC_PROCESS_ID_LIST with storage for a bounded variable-length
// ProcessIdList. repr(C) preserves the documented DWORD/DWORD/ULONG_PTR layout.
#[repr(C)]
struct ProcessIds {
    assigned: u32,
    returned: u32,
    ids: [usize; MAX_MEMBERS],
}

pub(super) struct RetirementWitnesses {
    descendants: Vec<OwnedHandle>,
}

impl RetirementWitnesses {
    pub(super) fn capture(assets: &SpawnAssets) -> Result<Self, Error> {
        let mut list = ProcessIds {
            assigned: 0,
            returned: 0,
            ids: [0; MAX_MEMBERS],
        };
        // SAFETY: the retained Job and aligned, writable C-layout buffer stay
        // valid for the call. Counts are checked before accessing returned IDs.
        if unsafe {
            QueryInformationJobObject(
                assets.job.as_raw_handle(),
                JobObjectBasicProcessIdList,
                (&mut list as *mut ProcessIds).cast(),
                size_of::<ProcessIds>() as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if list.assigned != list.returned || list.returned as usize > MAX_MEMBERS {
            return Err(Error::Protocol(
                "inspection Job process census is incomplete",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut descendants = Vec::new();
        for id in &list.ids[..list.returned as usize] {
            let id = u32::try_from(*id)
                .map_err(|_| Error::Protocol("inspection Job process id is invalid"))?;
            if id == 0 || !seen.insert(id) {
                return Err(Error::Protocol("inspection Job process id is invalid"));
            }
            if id == assets.child.id() {
                // NativeChild already retains this exact process until after
                // wait_process observes its exit. Do not reopen it by PID.
                continue;
            }
            // Query/synchronize rights only. Cancellation remains scoped to
            // the owned Job; these handles never terminate arbitrary PIDs.
            let raw = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    id,
                )
            };
            if raw.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: OpenProcess returned a new owned handle.
            let process = unsafe { OwnedHandle::from_raw_handle(raw) };
            let mut member = 0;
            if unsafe {
                IsProcessInJob(
                    process.as_raw_handle(),
                    assets.job.as_raw_handle(),
                    &mut member,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if member == 0 {
                return Err(Error::Protocol("inspection process left its owned Job"));
            }
            descendants.push(process);
        }
        Ok(Self { descendants })
    }

    pub(super) fn wait(self, job: &OwnedHandle, deadline: Instant) -> Result<(), Error> {
        for process in &self.descendants {
            match wait_until(process, deadline)? {
                WaitOutcome::Signaled => {}
                WaitOutcome::TimedOut => return Err(Error::Timeout),
                WaitOutcome::Abandoned => {
                    return Err(Error::Protocol("process wait reported abandonment"));
                }
            }
        }
        // No process can be added by an external Job owner: it is unnamed and
        // non-inheritable. A child created during the census still increments
        // TotalProcesses. Reject that gap, including children that already
        // departed, instead of mistaking an empty current list for full exit.
        let accounting = job_accounting(job)?;
        if accounting.ActiveProcesses != 0
            || accounting.TotalProcesses as usize != 1 + self.descendants.len()
        {
            return Err(Error::Protocol(
                "inspection Job retirement population is incomplete",
            ));
        }
        Ok(())
    }
}

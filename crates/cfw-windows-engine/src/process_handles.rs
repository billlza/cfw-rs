//! Explicit inherited-handle list shared by the launcher and native fixture.
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, BorrowedHandle},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT},
    System::Threading::{
        DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_JOB_LIST, UpdateProcThreadAttribute,
    },
};

pub struct ProcessHandleList<'a> {
    words: Vec<usize>,
    handles: Vec<HANDLE>,
    _borrowed: Vec<BorrowedHandle<'a>>,
    jobs: Vec<HANDLE>,
    _job: Option<BorrowedHandle<'a>>,
}
impl<'a> ProcessHandleList<'a> {
    pub fn new(handles: &[BorrowedHandle<'a>]) -> io::Result<Self> {
        Self::build(handles, None)
    }
    /// Assign the local cleanup Job during CreateProcess, before the child can
    /// execute. The Job handle is borrowed as an attribute, never inherited.
    pub(crate) fn with_job(
        handles: &[BorrowedHandle<'a>],
        job: BorrowedHandle<'a>,
    ) -> io::Result<Self> {
        Self::build(handles, Some(job))
    }
    fn build(handles: &[BorrowedHandle<'a>], job: Option<BorrowedHandle<'a>>) -> io::Result<Self> {
        if handles.is_empty() || handles.len() > 16 {
            return Err(io::Error::other("invalid inherited handle count"));
        }
        for handle in handles {
            let mut flags = 0;
            if unsafe { GetHandleInformation(handle.as_raw_handle(), &mut flags) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if flags & HANDLE_FLAG_INHERIT == 0 {
                return Err(io::Error::other("selected handle is not inheritable"));
            }
        }
        let mut size = 0;
        let count = 1 + u32::from(job.is_some());
        let first = unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        if first != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || size == 0
            || size > 65536
        {
            return Err(io::Error::other("invalid process attribute size"));
        }
        let mut words = vec![0usize; size.div_ceil(size_of::<usize>())];
        if unsafe {
            InitializeProcThreadAttributeList(words.as_mut_ptr().cast(), count, 0, &mut size)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut result = Self {
            words,
            handles: handles.iter().map(AsRawHandle::as_raw_handle).collect(),
            _borrowed: handles.to_vec(),
            jobs: job.iter().map(AsRawHandle::as_raw_handle).collect(),
            _job: job,
        };
        if unsafe {
            UpdateProcThreadAttribute(
                result.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                result.handles.as_ptr().cast(),
                std::mem::size_of_val(result.handles.as_slice()),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if !result.jobs.is_empty()
            && unsafe {
                UpdateProcThreadAttribute(
                    result.pointer(),
                    0,
                    PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                    result.jobs.as_ptr().cast(),
                    std::mem::size_of_val(result.jobs.as_slice()),
                    null_mut(),
                    null(),
                )
            } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(result)
    }
    pub fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.words.as_mut_ptr().cast()
    }
}
impl Drop for ProcessHandleList<'_> {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.pointer()) };
    }
}

use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::null_mut;

use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

use crate::SettingsStoreError;

pub(crate) fn local_app_data() -> Result<PathBuf, SettingsStoreError> {
    let mut pointer = null_mut();
    // SAFETY: the API returns a CoTaskMem-allocated, NUL-terminated UTF-16 path.
    let result = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_LocalAppData,
            KF_FLAG_DEFAULT as u32,
            null_mut(),
            &mut pointer,
        )
    };
    if result < 0 {
        // The API requires releasing this allocation on failure as well.
        unsafe { CoTaskMemFree(pointer.cast()) };
        return Err(SettingsStoreError::UserDataDirectoryUnavailable(result));
    }
    if pointer.is_null() {
        return Err(SettingsStoreError::InvalidPath);
    }
    let mut length = 0;
    while length < 32768 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    let path = if length == 0 || length == 32768 {
        Err(SettingsStoreError::InvalidPath)
    } else {
        let value =
            std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(pointer, length) });
        let path = PathBuf::from(value);
        if path.is_absolute() {
            Ok(path)
        } else {
            Err(SettingsStoreError::InvalidPath)
        }
    };
    unsafe { CoTaskMemFree(pointer.cast()) };
    path
}

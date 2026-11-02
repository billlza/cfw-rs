//! The versioned C ABI of the signed Host Bridge framework: its entry points,
//! where they are resolved from, and how long the framework stays loaded.

use std::{
    ffi::{CStr, CString, c_void},
    path::PathBuf,
};

const EXECUTE_SYMBOL: &CStr = c"cfw_native_bridge_execute_v1";
const CANCEL_SYMBOL: &CStr = c"cfw_native_bridge_cancel_v1";

pub(crate) type Completion = unsafe extern "C" fn(*mut c_void, *const u8, isize);
type Execute = unsafe extern "C" fn(*const u8, isize, Option<Completion>, *mut c_void) -> i32;
pub(crate) type Cancel = unsafe extern "C" fn(*const u8, isize) -> i32;

pub(crate) struct LoadedABI {
    pub(super) execute: Execute,
    pub(super) cancel: Cancel,
    pub(super) library_handle: Option<*mut c_void>,
}

// The dlopen handle and resolved C function are immutable after construction.
// Native requests copy their input and never retain a Rust reference to this
// object; the enclosing Arc keeps the framework loaded for the backend life.
unsafe impl Send for LoadedABI {}
unsafe impl Sync for LoadedABI {}

impl Drop for LoadedABI {
    fn drop(&mut self) {
        if let Some(handle) = self.library_handle {
            // SAFETY: handle was returned by a successful dlopen in `load` and
            // is closed exactly once when the final Arc is released.
            unsafe {
                libc::dlclose(handle);
            }
        }
    }
}

impl LoadedABI {
    pub(super) fn load() -> Result<Self, String> {
        // SAFETY: RTLD_DEFAULT is a process-global pseudo-handle valid for
        // dlsym. The symbol is copied into a typed function pointer below.
        let default_execute = unsafe { libc::dlsym(libc::RTLD_DEFAULT, EXECUTE_SYMBOL.as_ptr()) };
        // SAFETY: RTLD_DEFAULT is valid for both symbols in the same image.
        let default_cancel = unsafe { libc::dlsym(libc::RTLD_DEFAULT, CANCEL_SYMBOL.as_ptr()) };
        if !default_execute.is_null() || !default_cancel.is_null() {
            if default_execute.is_null() || default_cancel.is_null() {
                return Err(
                    "linked native bridge exports only part of the required ABI v1 pair".to_owned(),
                );
            }
            return Ok(Self {
                // SAFETY: the versioned symbol's C header fixes this signature.
                execute: unsafe { std::mem::transmute::<*mut c_void, Execute>(default_execute) },
                // SAFETY: the versioned cancel symbol's C header fixes this signature.
                cancel: unsafe { std::mem::transmute::<*mut c_void, Cancel>(default_cancel) },
                library_handle: None,
            });
        }

        let framework = fixed_framework_binary()?;
        let framework_c = CString::new(framework.as_os_str().as_encoded_bytes())
            .map_err(|_| "native bridge framework path contains an embedded NUL".to_owned())?;
        // SAFETY: framework_c is NUL terminated and the fixed bundle path is
        // not influenced by configuration, environment, or user input.
        let handle =
            unsafe { libc::dlopen(framework_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(format!(
                "signed native bridge framework could not be loaded: {}",
                dl_error()
            ));
        }
        // SAFETY: handle is a live dlopen handle and symbol is NUL terminated.
        let execute_symbol = unsafe { libc::dlsym(handle, EXECUTE_SYMBOL.as_ptr()) };
        // SAFETY: handle remains live and the cancel symbol is NUL terminated.
        let cancel_symbol = unsafe { libc::dlsym(handle, CANCEL_SYMBOL.as_ptr()) };
        if execute_symbol.is_null() || cancel_symbol.is_null() {
            let message = format!(
                "signed native bridge framework does not export the complete ABI v1 pair: {}",
                dl_error()
            );
            // SAFETY: no symbol call can be in flight before construction.
            unsafe {
                libc::dlclose(handle);
            }
            return Err(message);
        }
        Ok(Self {
            // SAFETY: the exported v1 C header fixes this exact signature.
            execute: unsafe { std::mem::transmute::<*mut c_void, Execute>(execute_symbol) },
            // SAFETY: the exported cancel v1 C header fixes this exact signature.
            cancel: unsafe { std::mem::transmute::<*mut c_void, Cancel>(cancel_symbol) },
            library_handle: Some(handle),
        })
    }
}

fn fixed_framework_binary() -> Result<PathBuf, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve current executable for native bridge: {error}"))?;
    let macos_directory = executable
        .parent()
        .ok_or_else(|| "current executable has no parent directory".to_owned())?;
    let contents_directory = macos_directory
        .parent()
        .ok_or_else(|| "current executable is outside a macOS application bundle".to_owned())?;
    Ok(contents_directory
        .join("Frameworks")
        .join("CFWNativeBridge.framework")
        .join("CFWNativeBridge"))
}

fn dl_error() -> String {
    // SAFETY: dlerror returns either null or a process-owned NUL-terminated
    // string valid until the next dynamic-loader call on this thread.
    let pointer = unsafe { libc::dlerror() };
    if pointer.is_null() {
        "dynamic loader returned no diagnostic".to_owned()
    } else {
        // SAFETY: non-null dlerror results are valid C strings.
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }
}

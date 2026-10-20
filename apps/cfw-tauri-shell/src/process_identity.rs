//! Process observations used by desktop lifecycle and update installation.
//! A serialized identity is a claim to re-observe, never a native authority.
#[cfg(target_os = "macos")]
#[path = "process_identity/macos.rs"]
mod native;
#[cfg(windows)]
#[path = "process_identity/windows.rs"]
mod native;

#[cfg(all(target_os = "macos", test))]
pub(crate) use native::ProcessStartIdentity;
#[cfg(target_os = "macos")]
pub(crate) use native::observe_exact_process;
pub(crate) use native::{
    ProcessIdentity, current_process_identity, exact_processes, process_identity_exists,
};

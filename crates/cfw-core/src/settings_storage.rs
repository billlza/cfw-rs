#[cfg(target_os = "macos")]
#[path = "settings_storage/macos.rs"]
mod platform;
#[cfg(windows)]
#[path = "settings_storage/windows.rs"]
mod platform;

#[cfg(not(any(target_os = "macos", windows)))]
compile_error!("application storage supports macOS and Windows");

pub(crate) use platform::{FileIdentity, FilePolicy, SecureDirectory};

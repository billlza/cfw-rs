//! Current-user sign-in registration for the protected installed desktop.
//!
//! A Run entry proves registration, not Windows Startup approval or a future
//! launch. The undocumented StartupApproved values are neither read nor changed.
//! Registration is changed only by an explicit preference transaction.
use crate::{VerifiedExecutable, runtime_host::InstalledRuntime};
use cfw_windows_storage::PrivateUserMutex;
use std::{
    io,
    os::windows::ffi::OsStrExt,
    path::{Component, Path, Prefix},
    ptr::{null, null_mut},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS},
    System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY,
        REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteValueW,
        RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    },
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "Clash for Windows";
// Microsoft's Run contract limits the complete command line to 260 characters.
const MAX_COMMAND_UNITS: usize = 260;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsStartupStatus {
    NotRegistered,
    Registered,
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("Windows startup installation: {0}")]
    Installation(#[from] crate::runtime_host::HostError),
    #[error("Windows startup user identity: {0}")]
    Identity(#[from] crate::user_agent::launcher::LaunchError),
    #[error("Windows startup serialization: {0}")]
    Storage(#[from] cfw_windows_storage::Error),
    #[error("Windows startup {operation}: {source}")]
    Native {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("the installed desktop path cannot be represented as a bounded startup command")]
    InvalidCommand,
    #[error(
        "the Windows startup entry contains another command or invalid data; it was not replaced"
    )]
    ForeignRegistration,
    #[error("the Windows startup entry changed during the preference transaction")]
    RegistrationChanged,
    #[error("the Windows startup preference could not be saved: {0}")]
    Preference(String),
    #[error(
        "Windows startup failed ({operation}); restoration or lock release also failed ({cleanup})"
    )]
    Cleanup {
        operation: Box<Self>,
        cleanup: Box<Self>,
    },
}

type Result<T> = std::result::Result<T, StartupError>;

/// Read-only native observation. Missing values are distinct from malformed
/// values and access failures. No key is created while inspecting registration.
pub fn observe_windows_startup() -> Result<WindowsStartupStatus> {
    with_registration(Registration::observe)
}

/// Keep the per-user lease through native readback and preference persistence.
/// On persistence failure, restore the observed registration, without replacing
/// a foreign command that appeared meanwhile. A crash is exposed as an intent /
/// registration mismatch on the next read; no cross-store atomicity is claimed.
pub fn set_windows_startup<T>(
    enabled: bool,
    persist: impl FnOnce() -> std::result::Result<T, String>,
) -> Result<(T, WindowsStartupStatus)> {
    with_registration(|registration| {
        let original = registration.observe()?;
        let requested = if enabled {
            WindowsStartupStatus::Registered
        } else {
            WindowsStartupStatus::NotRegistered
        };
        if let Err(operation) = registration.change(original, requested) {
            return restore_after_failure(registration, original, operation);
        }
        match persist() {
            Ok(value) => Ok((value, requested)),
            Err(error) => {
                restore_after_failure(registration, original, StartupError::Preference(error))
            }
        }
    })
}

fn restore_after_failure<T>(
    registration: &Registration,
    original: WindowsStartupStatus,
    operation: StartupError,
) -> Result<T> {
    let restored = registration
        .observe()
        .and_then(|current| registration.change(current, original));
    match restored {
        Ok(()) => Err(operation),
        Err(cleanup) => Err(StartupError::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}

struct Registration {
    command: Vec<u16>,
    // Hold the admitted image and protected manifest while using their path.
    _desktop: VerifiedExecutable,
    _installation: InstalledRuntime,
}

fn with_registration<T>(operation: impl FnOnce(&Registration) -> Result<T>) -> Result<T> {
    crate::user_agent::launcher::medium_process()?;
    let installation = InstalledRuntime::open()?;
    installation.require_desktop_process()?;
    let desktop = installation.desktop()?;
    let command = command_line(desktop.path())?;
    let registration = Registration {
        command,
        _desktop: desktop,
        _installation: installation,
    };
    let lock = PrivateUserMutex::acquire("startup-registration-v1", Duration::from_secs(3))?;
    // An abandoned lease is never a success receipt. Every operation reloads
    // the actual value, including after a predecessor exited during a change.
    let result = operation(&registration);
    let released = lock.release().map_err(StartupError::from);
    match (result, released) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(StartupError::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}

impl Registration {
    fn observe(&self) -> Result<WindowsStartupStatus> {
        match Key::open(false, false)? {
            Some(key) => key.observe(&self.command),
            None => Ok(WindowsStartupStatus::NotRegistered),
        }
    }

    fn change(
        &self,
        expected: WindowsStartupStatus,
        requested: WindowsStartupStatus,
    ) -> Result<()> {
        // Opening with write access is reserved for a real requested change.
        if expected == requested {
            return if self.observe()? == expected {
                Ok(())
            } else {
                Err(StartupError::RegistrationChanged)
            };
        }
        let key = Key::open(true, requested == WindowsStartupStatus::Registered)?;
        let Some(key) = key else {
            return Err(StartupError::RegistrationChanged);
        };
        if key.observe(&self.command)? != expected {
            return Err(StartupError::RegistrationChanged);
        }
        let name = wide(VALUE_NAME);
        let status = if requested == WindowsStartupStatus::Registered {
            unsafe {
                RegSetValueExW(
                    key.0,
                    name.as_ptr(),
                    0,
                    REG_SZ,
                    self.command.as_ptr().cast(),
                    (self.command.len() * 2) as u32,
                )
            }
        } else {
            unsafe { RegDeleteValueW(key.0, name.as_ptr()) }
        };
        native("write registration", status)?;
        if key.observe(&self.command)? != requested {
            return Err(StartupError::RegistrationChanged);
        }
        Ok(())
    }
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}
impl Key {
    fn open(write: bool, create: bool) -> Result<Option<Self>> {
        let path = wide(RUN_KEY);
        let access = KEY_QUERY_VALUE | KEY_WOW64_64KEY | if write { KEY_SET_VALUE } else { 0 };
        let mut key = null_mut();
        let status = if create {
            unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    null(),
                    REG_OPTION_NON_VOLATILE,
                    access,
                    null(),
                    &mut key,
                    null_mut(),
                )
            }
        } else {
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, access, &mut key) }
        };
        if !create && status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        native("open current-user registration", status)?;
        Ok(Some(Self(key)))
    }

    fn observe(&self, expected: &[u16]) -> Result<WindowsStartupStatus> {
        let mut units = [0u16; MAX_COMMAND_UNITS + 1];
        let mut bytes = (units.len() * 2) as u32;
        let mut kind = 0;
        let name = wide(VALUE_NAME);
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                null(),
                &mut kind,
                units.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        match status {
            ERROR_FILE_NOT_FOUND => Ok(WindowsStartupStatus::NotRegistered),
            ERROR_MORE_DATA => Err(StartupError::ForeignRegistration),
            ERROR_SUCCESS => classify_value(kind, bytes as usize, &units, expected),
            _ => Err(native_error("read registration", status)),
        }
    }
}

fn classify_value(
    kind: u32,
    bytes: usize,
    units: &[u16],
    expected: &[u16],
) -> Result<WindowsStartupStatus> {
    if kind != REG_SZ
        || bytes != expected.len() * 2
        || bytes > units.len() * 2
        || &units[..bytes / 2] != expected
    {
        return Err(StartupError::ForeignRegistration);
    }
    Ok(WindowsStartupStatus::Registered)
}

fn command_line(path: &Path) -> Result<Vec<u16>> {
    if !path.is_absolute()
        || !matches!(path.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_)))
        || path.components().any(|component| matches!(component, Component::ParentDir)
            || matches!(component, Component::Normal(name) if name.encode_wide().any(|unit| unit == u16::from(b':'))))
    {
        return Err(StartupError::InvalidCommand);
    }
    let path: Vec<_> = path.as_os_str().encode_wide().collect();
    if path.len() + 2 > MAX_COMMAND_UNITS
        || path
            .iter()
            .any(|unit| *unit < 32 || *unit == u16::from(b'"'))
    {
        return Err(StartupError::InvalidCommand);
    }
    Ok([vec![u16::from(b'"')], path, vec![u16::from(b'"'), 0]].concat())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
fn native(operation: &'static str, status: u32) -> Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(native_error(operation, status))
    }
}
fn native_error(operation: &'static str, status: u32) -> StartupError {
    StartupError::Native {
        operation,
        source: io::Error::from_raw_os_error(status as i32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_command_quotes_the_whole_unicode_path_without_arguments() {
        let path = Path::new(r"C:\Program Files\配置 (a)&b\Clash for Windows.exe");
        assert_eq!(
            command_line(path).unwrap(),
            wide(&format!("\"{}\"", path.display()))
        );
    }

    #[test]
    fn startup_command_rejects_unbounded_and_nonlocal_targets() {
        for path in [
            "app.exe",
            "C:app.exe",
            r"\\server\share\app.exe",
            r"\\?\C:\app.exe",
            r"C:\parent\..\app.exe",
            r"C:\app.exe:payload",
            "C:\\app\".exe",
            "C:\\app\0.exe",
        ] {
            assert!(command_line(Path::new(path)).is_err(), "{path}");
        }
        let exact = format!("C:\\{}", "a".repeat(MAX_COMMAND_UNITS - 5));
        assert_eq!(
            command_line(Path::new(&exact)).unwrap().len(),
            MAX_COMMAND_UNITS + 1
        );
        assert!(command_line(Path::new(&(exact + "a"))).is_err());
    }

    #[test]
    fn startup_value_never_confuses_registration_with_os_approval() {
        let expected = wide(r#""C:\Program Files\Clash for Windows\Clash for Windows.exe""#);
        assert_eq!(
            classify_value(REG_SZ, expected.len() * 2, &expected, &expected).unwrap(),
            WindowsStartupStatus::Registered
        );
        for (kind, bytes) in [
            (REG_SZ + 1, expected.len() * 2),
            (REG_SZ, 0),
            (REG_SZ, 1),
            (REG_SZ, expected.len() * 2 - 2),
            (REG_SZ, expected.len() * 2 + 2),
        ] {
            assert!(classify_value(kind, bytes, &expected, &expected).is_err());
        }
        let mut other = expected.clone();
        other[2] = u16::from(b'D');
        assert!(classify_value(REG_SZ, other.len() * 2, &other, &expected).is_err());
    }
}

//! Real current-user Run registration under the installed ordinary-user host.
//! No sign-out, sign-in or automatic application launch is claimed by this test.
use super::*;
use cfw_windows_engine::{
    StartupError, WindowsStartupStatus, observe_windows_startup, set_windows_startup,
};
use windows_sys::Win32::System::Registry::*;

const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const NAME: &str = "Clash for Windows";
const FOREIGN: &str = r#""C:\cfw-missing-startup-fixture.exe""#;

pub(super) fn exercise() -> Result<serde_json::Value> {
    if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
        return Err("startup registration requires disposable CI opt-in".into());
    }
    let expected = wide(&format!(
        "\"{}\"",
        InstalledRuntime::desktop_path()
            .map_err(|e| e.to_string())?
            .display()
    ));
    if read()?.is_some()
        || observe_windows_startup().map_err(|e| e.to_string())?
            != WindowsStartupStatus::NotRegistered
    {
        return Err("startup fixture refuses a preexisting registration".into());
    }
    let exercised = (|| -> Result<serde_json::Value> {
        let fail_enable = set_windows_startup(true, || {
            Err::<(), _>("fixture preference write failed".into())
        });
        if !matches!(fail_enable, Err(StartupError::Preference(_))) || read()?.is_some() {
            return Err("failed startup preference did not restore the absent registration".into());
        }
        let ((), status) =
            set_windows_startup(true, || require_value(&expected)).map_err(|e| e.to_string())?;
        if status != WindowsStartupStatus::Registered {
            return Err("registration was misreported as Windows startup approval".into());
        }
        require_value(&expected)?;
        set_windows_startup(true, || require_value(&expected)).map_err(|e| e.to_string())?;
        let fail_disable = set_windows_startup(false, || {
            if read()?.is_some() {
                return Err("registration was not removed before persistence".into());
            }
            Err::<(), _>("fixture preference write failed".into())
        });
        if !matches!(fail_disable, Err(StartupError::Preference(_))) {
            return Err("failed disable did not report its preference failure".into());
        }
        require_value(&expected)?;
        let ((), status) = set_windows_startup(false, || {
            if read()?.is_some() {
                return Err("disabled registration remains present".into());
            }
            Ok(())
        })
        .map_err(|e| e.to_string())?;
        if status != WindowsStartupStatus::NotRegistered || read()?.is_some() {
            return Err("startup disable did not remove the exact registration".into());
        }
        let foreign = wide(FOREIGN);
        let changed_during_persistence = set_windows_startup(true, || {
            write(Some(&foreign))?;
            Err::<(), _>("fixture preference write failed after external change".into())
        });
        if !matches!(
            changed_during_persistence,
            Err(StartupError::Cleanup { .. })
        ) {
            return Err("startup rollback did not report the changed registration".into());
        }
        require_value(&foreign)?;
        if !matches!(
            observe_windows_startup(),
            Err(StartupError::ForeignRegistration)
        ) {
            return Err("foreign startup entry was accepted".into());
        }
        for enabled in [false, true] {
            let mut persisted = false;
            let result = set_windows_startup(enabled, || {
                persisted = true;
                Ok(())
            });
            if !matches!(result, Err(StartupError::ForeignRegistration)) || persisted {
                return Err("foreign startup registration reached preference persistence".into());
            }
            require_value(&foreign)?;
        }
        Ok(serde_json::json!({
            "document":"cfw-windows-startup-registration-v1",
            "source":std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e| e.to_string())?,
            "registered_and_removed":true,"idempotent_registration":true,
            "failed_enable_restored":true,"failed_disable_restored":true,
            "foreign_command_preserved":true,"preference_callback_guarded":true,
            "changed_registration_preserved":true,
            "os_startup_approval_verified":false,"sign_in_launch_verified":false,
        }))
    })();
    // Cleanup is explicit and verified on failure too. Never remove a value
    // other than the exact command installed by this disposable fixture.
    let cleanup = (|| -> Result<()> {
        match read()? {
            None => Ok(()),
            Some(value) if value == expected || value == wide(FOREIGN) => {
                write(None)?;
                if read()?.is_some() {
                    return Err("startup fixture registration remains after cleanup".into());
                }
                Ok(())
            }
            Some(_) => Err("startup fixture cleanup refused a changed value".into()),
        }
    })();
    match (exercised, cleanup) {
        (Ok(mut value), Ok(())) => {
            value["registration_removed"] = true.into();
            Ok(value)
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; startup fixture cleanup: {cleanup}")),
    }
}

fn require_value(expected: &[u16]) -> Result<()> {
    if read()?.as_deref() == Some(expected) {
        Ok(())
    } else {
        Err("native Run value differs from the exact quoted desktop command".into())
    }
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}
fn key() -> Result<Option<Key>> {
    let mut key = null_mut();
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            wide(KEY).as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if result != ERROR_SUCCESS {
        return Err(format!("open fixture Run key: {result}"));
    }
    Ok(Some(Key(key)))
}
fn read() -> Result<Option<Vec<u16>>> {
    let Some(key) = key()? else {
        return Ok(None);
    };
    let mut units = [0u16; 261];
    let mut size = (units.len() * 2) as u32;
    let mut kind = 0;
    let result = unsafe {
        RegQueryValueExW(
            key.0,
            wide(NAME).as_ptr(),
            null(),
            &mut kind,
            units.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if result != ERROR_SUCCESS
        || kind != REG_SZ
        || !size.is_multiple_of(2)
        || size as usize > units.len() * 2
    {
        return Err(format!("read fixture Run value: {result}/{kind}/{size}"));
    }
    Ok(Some(units[..size as usize / 2].to_vec()))
}
fn write(value: Option<&[u16]>) -> Result<()> {
    let key = key()?.ok_or("fixture Run key disappeared")?;
    let result = match value {
        Some(value) => unsafe {
            RegSetValueExW(
                key.0,
                wide(NAME).as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                (value.len() * 2) as u32,
            )
        },
        None => unsafe { RegDeleteValueW(key.0, wide(NAME).as_ptr()) },
    };
    if result != ERROR_SUCCESS {
        return Err(format!("write fixture Run value: {result}"));
    }
    Ok(())
}

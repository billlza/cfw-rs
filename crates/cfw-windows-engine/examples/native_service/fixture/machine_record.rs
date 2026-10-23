//! Opted-in native fixture only. These small synthetic records are not an
//! Authority journal, a runtime lease or evidence of global Off.
use super::*;
use cfw_windows_storage::{Error as StorageError, MachineRecordError, PrivateMachineRecord};
use windows_sys::Win32::{
    Storage::FileSystem::{DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER},
    System::Registry::*,
};

const FIRST: &[u8] = b"fixture-anchor-revision-1";
const SECOND: &[u8] = b"fixture-anchor-revision-2";

fn scope(name: &str) -> Result<String> {
    let prefix = name
        .strip_suffix("-a")
        .or_else(|| name.strip_suffix("-b"))
        .ok_or("invalid machine-record service suffix")?;
    let id = prefix
        .strip_prefix("CFW-scm-fixture-")
        .ok_or("invalid machine-record scope")?;
    if uuid::Uuid::parse_str(id)
        .map_err(|e| e.to_string())?
        .to_string()
        != id
    {
        return Err("noncanonical machine-record fixture identity".into());
    }
    Ok(prefix.to_owned())
}

fn record(name: &str) -> Result<PrivateMachineRecord> {
    PrivateMachineRecord::new(&scope(name)?).map_err(|e| e.to_string())
}

pub(super) fn request(name: &str, image: &Path, digest: [u8; 32], command: &[u8]) -> Result<()> {
    let mut channel =
        ServiceChannel::connect(name, ServiceClientRole::Desktop, verified(image, digest)?)
            .map_err(|e| e.to_string())?;
    if channel
        .request(command, Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"record-ok"
    {
        return Err("machine-record service response mismatch".into());
    }
    Ok(())
}

pub(super) fn exercise(name: &str, command: &[u8]) -> Result<()> {
    let record = record(name)?;
    let guard = record.lock(LIMIT).map_err(|e| e.to_string())?;
    if guard.was_abandoned() {
        return Err("unexpected abandoned fixture anchor".into());
    }
    match command {
        b"machine-record-seed" if name.ends_with("-a") => {
            assert_eq!(guard.read().map_err(|e| e.to_string())?, None);
            guard
                .compare_exchange(None, FIRST)
                .map_err(|e| e.to_string())?;
            assert_eq!(
                guard.read().map_err(|e| e.to_string())?.as_deref(),
                Some(FIRST)
            );
            assert!(matches!(
                guard.compare_exchange(None, SECOND),
                Err(MachineRecordError::Conflict)
            ));
            assert!(matches!(
                guard.compare_exchange(Some(SECOND), FIRST),
                Err(MachineRecordError::Conflict)
            ));
            assert!(matches!(
                guard.remove(SECOND),
                Err(MachineRecordError::Conflict)
            ));
            for invalid in [Vec::new(), vec![1; 2049]] {
                assert!(matches!(
                    guard.compare_exchange(Some(FIRST), &invalid),
                    Err(MachineRecordError::InvalidValue)
                ));
            }
            // Registry names are case-insensitive; another thread using uppercase
            // must contend on the same native mutex before accessing the record.
            let contender_scope = scope(name)?.to_uppercase();
            thread::spawn(move || -> Result<()> {
                let contender =
                    PrivateMachineRecord::new(&contender_scope).map_err(|e| e.to_string())?;
                assert!(matches!(
                    contender.lock(Duration::from_millis(50)),
                    Err(MachineRecordError::Storage(StorageError::MutexBusy))
                ));
                Ok(())
            })
            .join()
            .map_err(|_| "machine-record contender panicked")??;
            invalid_native_values(name, &guard)?;
        }
        b"machine-record-observe" if name.ends_with("-b") => {
            // The first SYSTEM process has exited and its handles are gone.
            // A separate service must read and advance the original record.
            assert_eq!(
                guard.read().map_err(|e| e.to_string())?.as_deref(),
                Some(FIRST)
            );
            guard
                .compare_exchange(Some(FIRST), SECOND)
                .map_err(|e| e.to_string())?;
            assert_eq!(
                guard.read().map_err(|e| e.to_string())?.as_deref(),
                Some(SECOND)
            );
        }
        _ => return Err("unexpected machine-record fixture operation".into()),
    }
    guard.release().map_err(|e| e.to_string())
}

pub(super) fn cleanup(name: &str) -> Result<()> {
    let record = record(name)?;
    let guard = record.lock(LIMIT).map_err(|e| e.to_string())?;
    if let Some(value) = guard.read().map_err(|e| e.to_string())? {
        if value != FIRST && value != SECOND {
            return Err("refusing to remove unknown fixture record".into());
        }
        guard.remove(&value).map_err(|e| e.to_string())?;
    }
    if guard.read().map_err(|e| e.to_string())?.is_some() {
        return Err("fixture record deletion was not observed".into());
    }
    guard.release().map_err(|e| e.to_string())
}

fn key_path(name: &str) -> Result<String> {
    Ok(format!(
        "SOFTWARE\\ClashForWindowsAuthority\\{}",
        scope(name)?
    ))
}

pub(super) fn require_user_denied(name: &str) -> Result<()> {
    assert!(matches!(
        PrivateMachineRecord::new(&scope(name)?),
        Err(MachineRecordError::RequiresSystem)
    ));
    let path = wide(&key_path(name)?);
    // This runs in the actual medium-integrity, non-administrator child.
    // Bypass the product's early identity check to prove the native ACL too.
    for access in [
        KEY_QUERY_VALUE,
        KEY_SET_VALUE,
        KEY_CREATE_SUB_KEY,
        READ_CONTROL,
        WRITE_DAC,
        WRITE_OWNER,
        DELETE,
    ] {
        let mut raw = null_mut();
        let code = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                REG_OPTION_OPEN_LINK,
                access | KEY_WOW64_64KEY,
                &mut raw,
            )
        };
        if !raw.is_null() {
            unsafe { RegCloseKey(raw) };
        }
        if code != ERROR_ACCESS_DENIED {
            return Err(format!(
                "ordinary client registry access {access:#x} returned {code}"
            ));
        }
    }
    Ok(())
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}
fn check(code: u32, operation: &str) -> Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "fixture registry {operation}: {}",
            io::Error::from_raw_os_error(code as i32)
        ))
    }
}
fn write(key: &Key, kind: u32, bytes: &[u8]) -> Result<()> {
    check(
        unsafe {
            RegSetValueExW(
                key.0,
                wide("record").as_ptr(),
                0,
                kind,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        },
        "write malformed test value",
    )
}
fn dacl(key: &Key, sddl: &str) -> Result<()> {
    let descriptor = Descriptor::new(sddl)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }
        == 0
    {
        return Err(error("read fixture registry DACL"));
    }
    if present == 0 || defaulted != 0 || acl.is_null() {
        return Err("invalid fixture registry DACL".into());
    }
    check(
        unsafe {
            SetSecurityInfo(
                key.0,
                SE_REGISTRY_KEY,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null_mut(),
            )
        },
        "set test DACL",
    )
}

fn invalid_native_values(
    name: &str,
    guard: &cfw_windows_storage::MachineRecordGuard<'_>,
) -> Result<()> {
    let mut raw = null_mut();
    check(
        unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(&key_path(name)?).as_ptr(),
                REG_OPTION_OPEN_LINK,
                KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC | KEY_WOW64_64KEY,
                &mut raw,
            )
        },
        "open corruption fixture",
    )?;
    if raw.is_null() {
        return Err("null corruption fixture key".into());
    }
    let key = Key(raw);
    let exercised = (|| {
        for (kind, bytes) in [
            (REG_SZ, vec![b'x', 0]),
            (REG_BINARY, Vec::new()),
            (REG_BINARY, vec![1; 2049]),
        ] {
            write(&key, kind, &bytes)?;
            if !matches!(guard.read(), Err(MachineRecordError::InvalidValue)) {
                return Err("malformed native registry value was not rejected".into());
            }
        }
        write(&key, REG_BINARY, FIRST)?;
        dacl(&key, "D:P(A;CI;KA;;;SY)(A;CI;KR;;;AU)")?;
        if !matches!(guard.read(), Err(MachineRecordError::UnsafeKey)) {
            return Err("foreign registry DACL was not rejected".into());
        }
        Ok(())
    })();
    // Restore through the retained handle even if a malformed-data check fails.
    // The guard remains held, so cooperating SYSTEM readers cannot see fixtures.
    let restore = (|| {
        dacl(&key, "D:P(A;CI;KA;;;SY)")?;
        write(&key, REG_BINARY, FIRST)?;
        check(unsafe { RegFlushKey(key.0) }, "flush restored fixture")
    })();
    match (exercised, restore) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Err(e), Err(cleanup)) => Err(format!("{e}; fixture restoration: {cleanup}")),
    }
}

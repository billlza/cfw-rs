//! Independent SYSTEM-only durable records in the 64-bit local-machine hive.
//! The payload is bounded application metadata, not a generic secret store.
use crate::{
    Error, PrivateUserMutex,
    security::{Security, is_system_process},
};
use sha2::{Digest, Sha256};
use std::{
    io,
    mem::size_of,
    ptr::{null, null_mut},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::READ_CONTROL,
    System::Registry::*,
};

const NAMESPACE: &str = "ClashForWindowsAuthority";
const VALUE: &str = "record";
const MAXIMUM: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum MachineRecordError {
    #[error("machine record requires an unimpersonated SYSTEM identity")]
    RequiresSystem,
    #[error("machine record scope is invalid")]
    InvalidScope,
    #[error("machine record value is empty, oversized or has the wrong native type")]
    InvalidValue,
    #[error("machine record registry key is redirected or has unsafe ownership/access")]
    UnsafeKey,
    #[error("machine record changed before compare-and-swap")]
    Conflict,
    #[error("machine record readback differs from its publication")]
    ReadbackMismatch,
    #[error("machine record native {operation}: {source}")]
    Native {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("machine record locking/identity: {0}")]
    Storage(#[from] Error),
    #[error("machine record publication may have changed durable state: {0}")]
    OutcomeUnknown(Box<Self>),
}

fn native(operation: &'static str, code: u32) -> MachineRecordError {
    MachineRecordError::Native {
        operation,
        source: io::Error::from_raw_os_error(code as i32),
    }
}
fn system() -> Result<(), MachineRecordError> {
    if !is_system_process()? {
        return Err(MachineRecordError::RequiresSystem);
    }
    Ok(())
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

/// No caller-selected hive/path or identity. A scope comes from the trusted
/// service installation. Case folding agrees with registry key equivalence.
pub struct PrivateMachineRecord {
    scope: String,
    security: Security,
}
pub struct MachineRecordGuard<'a> {
    record: &'a PrivateMachineRecord,
    mutex: PrivateUserMutex,
}

impl PrivateMachineRecord {
    pub fn new(scope: &str) -> Result<Self, MachineRecordError> {
        if scope.is_empty()
            || scope.len() > 80
            || !scope
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(MachineRecordError::InvalidScope);
        }
        system()?;
        Ok(Self {
            scope: scope.to_ascii_lowercase(),
            security: Security::for_registry()?,
        })
    }

    /// Hold this guard across a complete journal/anchor transaction, not only
    /// individual registry writes. An abandoned predecessor requires recovery.
    pub fn lock(&self, timeout: Duration) -> Result<MachineRecordGuard<'_>, MachineRecordError> {
        system()?;
        let digest = crate::digest_hex(Sha256::digest(self.scope.as_bytes()).into());
        let purpose = format!("machine-record-{digest}");
        Ok(MachineRecordGuard {
            record: self,
            mutex: PrivateUserMutex::acquire(&purpose, timeout)?,
        })
    }

    fn namespace(&self, create: bool) -> Result<Option<Key>, MachineRecordError> {
        let access = KEY_QUERY_VALUE
            | READ_CONTROL
            | KEY_WOW64_64KEY
            | if create { KEY_CREATE_SUB_KEY } else { 0 };
        let software =
            open(HKEY_LOCAL_MACHINE, "SOFTWARE", access)?.ok_or(MachineRecordError::UnsafeKey)?;
        no_link(&software)?;
        let key = self.child(&software, NAMESPACE, create, access)?;
        Ok(key)
    }

    fn child(
        &self,
        parent: &Key,
        name: &str,
        create: bool,
        access: u32,
    ) -> Result<Option<Key>, MachineRecordError> {
        let key = match open(parent.0, name, access)? {
            Some(key) => key,
            None if !create => return Ok(None),
            None => {
                let mut raw = null_mut();
                let mut disposition = 0;
                let attributes = SECURITY_ATTRIBUTES {
                    nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: self.security.descriptor().cast_mut().cast(),
                    bInheritHandle: 0,
                };
                let status = unsafe {
                    RegCreateKeyExW(
                        parent.0,
                        wide(name).as_ptr(),
                        0,
                        null(),
                        REG_OPTION_NON_VOLATILE,
                        access,
                        &attributes,
                        &mut raw,
                        &mut disposition,
                    )
                };
                if status != ERROR_SUCCESS {
                    return Err(native("create key", status));
                }
                if raw.is_null() {
                    return Err(MachineRecordError::UnsafeKey);
                }
                let created = Key(raw);
                match disposition {
                    REG_CREATED_NEW_KEY => created,
                    REG_OPENED_EXISTING_KEY => {
                        // A racing creator might have installed a symbolic link.
                        // Reopen the key itself before any value access.
                        drop(created);
                        open(parent.0, name, access)?.ok_or(MachineRecordError::UnsafeKey)?
                    }
                    _ => return Err(MachineRecordError::UnsafeKey),
                }
            }
        };
        no_link(&key)?;
        self.security.verify_registry(key.0).map_err(|e| match e {
            Error::UnsafeDirectory | Error::UnsafeFile => MachineRecordError::UnsafeKey,
            other => other.into(),
        })?;
        Ok(Some(key))
    }

    fn key(&self, create: bool) -> Result<Option<Key>, MachineRecordError> {
        let Some(namespace) = self.namespace(create)? else {
            return Ok(None);
        };
        self.child(
            &namespace,
            &self.scope,
            create,
            KEY_QUERY_VALUE
                | READ_CONTROL
                | KEY_WOW64_64KEY
                | if create { KEY_SET_VALUE } else { 0 },
        )
    }
}

impl MachineRecordGuard<'_> {
    pub fn was_abandoned(&self) -> bool {
        self.mutex.was_abandoned()
    }
    pub fn release(self) -> Result<(), MachineRecordError> {
        self.mutex.release().map_err(Into::into)
    }

    pub fn read(&self) -> Result<Option<Vec<u8>>, MachineRecordError> {
        system()?;
        let Some(key) = self.record.key(false)? else {
            return Ok(None);
        };
        let mut kind = 0;
        let mut length = 0;
        let name = wide(VALUE);
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null(),
                &mut kind,
                null_mut(),
                &mut length,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(native("measure value", status));
        }
        if kind != REG_BINARY || length == 0 || length as usize > MAXIMUM {
            return Err(MachineRecordError::InvalidValue);
        }
        let mut bytes = vec![0; length as usize];
        let capacity = length;
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null(),
                &mut kind,
                bytes.as_mut_ptr(),
                &mut length,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(native("read value", status));
        }
        if kind != REG_BINARY || length != capacity {
            return Err(MachineRecordError::InvalidValue);
        }
        Ok(Some(bytes))
    }

    pub fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<(), MachineRecordError> {
        system()?;
        if replacement.is_empty() || replacement.len() > MAXIMUM {
            return Err(MachineRecordError::InvalidValue);
        }
        if self.read()?.as_deref() != expected {
            return Err(MachineRecordError::Conflict);
        }
        let outcome = (|| {
            // Key creation is also a mutation, including when later security
            // verification fails. Do not report it as a known no-op.
            let key = self
                .record
                .key(true)?
                .ok_or(MachineRecordError::UnsafeKey)?;
            let status = unsafe {
                RegSetValueExW(
                    key.0,
                    wide(VALUE).as_ptr(),
                    0,
                    REG_BINARY,
                    replacement.as_ptr(),
                    replacement.len() as u32,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(native("write value", status));
            }
            let status = unsafe { RegFlushKey(key.0) };
            if status != ERROR_SUCCESS {
                return Err(native("flush value", status));
            }
            drop(key);
            if self.read()?.as_deref() != Some(replacement) {
                return Err(MachineRecordError::ReadbackMismatch);
            }
            Ok(())
        })();
        outcome.map_err(|error| MachineRecordError::OutcomeUnknown(Box::new(error)))
    }

    /// Removes only this exact, owned leaf record. Lifecycle owners must prove
    /// their own uninstall/retirement preconditions before calling this storage API.
    pub fn remove(&self, expected: &[u8]) -> Result<(), MachineRecordError> {
        system()?;
        if self.read()?.as_deref() != Some(expected) {
            return Err(MachineRecordError::Conflict);
        }
        let parent = self
            .record
            .namespace(false)?
            .ok_or(MachineRecordError::UnsafeKey)?;
        let outcome = (|| {
            let status = unsafe {
                RegDeleteKeyExW(
                    parent.0,
                    wide(&self.record.scope).as_ptr(),
                    KEY_WOW64_64KEY,
                    0,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(native("delete record", status));
            }
            let status = unsafe { RegFlushKey(parent.0) };
            if status != ERROR_SUCCESS {
                return Err(native("flush deletion", status));
            }
            if self.read()?.is_some() {
                return Err(MachineRecordError::ReadbackMismatch);
            }
            Ok(())
        })();
        outcome.map_err(|error| MachineRecordError::OutcomeUnknown(Box::new(error)))
    }
}

fn open(parent: HKEY, name: &str, access: u32) -> Result<Option<Key>, MachineRecordError> {
    let mut raw = null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            parent,
            wide(name).as_ptr(),
            REG_OPTION_OPEN_LINK,
            access,
            &mut raw,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(native("open key", status));
    }
    if raw.is_null() {
        return Err(MachineRecordError::UnsafeKey);
    }
    Ok(Some(Key(raw)))
}

fn no_link(key: &Key) -> Result<(), MachineRecordError> {
    let mut size = 0;
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            wide("SymbolicLinkValue").as_ptr(),
            null(),
            null_mut(),
            null_mut(),
            &mut size,
        )
    };
    match status {
        ERROR_FILE_NOT_FOUND => Ok(()),
        ERROR_SUCCESS | ERROR_MORE_DATA => Err(MachineRecordError::UnsafeKey),
        code => Err(native("inspect registry link", code)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_process_cannot_open_machine_records_and_scope_is_closed() {
        assert!(!is_system_process().unwrap());
        assert!(matches!(
            PrivateMachineRecord::new("test-authority"),
            Err(MachineRecordError::RequiresSystem)
        ));
        for scope in ["", "..", "a\\b", "a/b", "a\0b", "a b"] {
            assert!(matches!(
                PrivateMachineRecord::new(scope),
                Err(MachineRecordError::InvalidScope)
            ));
        }
    }
}

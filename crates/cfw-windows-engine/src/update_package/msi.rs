use super::{
    MsiIdentity, PRODUCT_IDENTIFIER, PackageError, PackageExpectation, Result, UPGRADE_CODE,
    canonical_version, combine, wide_path, windows_version,
};
use std::{path::Path, ptr::null};
use windows_sys::Win32::{
    Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FILETIME},
    System::ApplicationInstallationAndServicing::*,
};

const MAX_PROPERTY_CHARS: usize = 256;

pub(super) fn inspect(path: &Path, expectation: &PackageExpectation) -> Result<MsiIdentity> {
    let path = wide_path(path)?;
    let mut raw = 0;
    // SAFETY: terminated path and writable output; READONLY forbids mutation.
    check("open MSI database", unsafe {
        MsiOpenDatabaseW(path.as_ptr(), MSIDBOPEN_READONLY, &mut raw)
    })?;
    let database = Handle::new(raw)?;
    let result = identity(&database, expectation);
    database.finish(result)
}

fn identity(database: &Handle, expectation: &PackageExpectation) -> Result<MsiIdentity> {
    for (name, expected) in [
        ("CFW_PRODUCT_ID", PRODUCT_IDENTIFIER),
        ("ProductName", "Clash for Windows"),
        ("UpgradeCode", UPGRADE_CODE),
        ("ALLUSERS", "1"),
        ("MSIRESTARTMANAGERCONTROL", "DisableShutdown"),
    ] {
        if property(database, name)? != expected {
            return Err(PackageError::Invalid("MSI product or installation policy"));
        }
    }
    let version_text = property(database, "CFW_RELEASE_VERSION")?;
    let version = canonical_version(&version_text)?;
    if version != expectation.version {
        return Err(PackageError::Requirement("requested release version"));
    }
    if property(database, "ProductVersion")?
        != format!("{}.{}.{}", version.major, version.minor, version.patch)
    {
        return Err(PackageError::Invalid("MSI product version"));
    }
    let build_text = property(database, "CFW_BUILD_NUMBER")?;
    let build: u64 = build_text
        .parse()
        .map_err(|_| PackageError::Invalid("build number"))?;
    if build == 0 || build.to_string() != build_text {
        return Err(PackageError::Invalid("build number"));
    }
    if build <= expectation.minimum_exclusive_build {
        return Err(PackageError::Requirement("newer build number"));
    }
    let minimum_windows_version = property(database, "CFW_MINIMUM_WINDOWS_VERSION")?;
    if windows_version(&minimum_windows_version)? > expectation.system_version {
        return Err(PackageError::Requirement("minimum Windows version"));
    }
    let product_code = canonical_guid(&property(database, "ProductCode")?)?;
    let mut raw = 0;
    // SAFETY: live database, no alternate path, zero updates requests read-only.
    check("open MSI summary", unsafe {
        MsiGetSummaryInformationW(database.raw, null(), 0, &mut raw)
    })?;
    let summary = Handle::new(raw)?;
    let result = (|| {
        let template = summary_property(&summary, PID_TEMPLATE)?;
        let Some(("x64", languages)) = template.split_once(';') else {
            return Err(PackageError::Invalid("MSI architecture"));
        };
        // CFW packages are x64 and carry at least one canonical Windows LANGID.
        let mut seen = std::collections::BTreeSet::new();
        for text in languages.split(',') {
            let language: u16 = text
                .parse()
                .map_err(|_| PackageError::Invalid("MSI language"))?;
            if language == 0 || language.to_string() != text || !seen.insert(language) {
                return Err(PackageError::Invalid("MSI language"));
            }
        }
        let package_code = canonical_guid(&summary_property(&summary, PID_REVNUMBER)?)?;
        if package_code == product_code
            || product_code == UPGRADE_CODE
            || package_code == UPGRADE_CODE
        {
            return Err(PackageError::Invalid("distinct MSI package identities"));
        }
        Ok(MsiIdentity {
            version: version_text,
            build,
            product_code,
            package_code,
            architecture: "x64",
            minimum_windows_version,
        })
    })();
    summary.finish(result)
}

fn canonical_guid(value: &str) -> Result<String> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| PackageError::Invalid("MSI GUID"))?;
    let canonical = format!("{{{}}}", parsed.hyphenated()).to_ascii_uppercase();
    if parsed.is_nil() || value != canonical {
        return Err(PackageError::Invalid("MSI GUID"));
    }
    Ok(canonical)
}

fn property(database: &Handle, name: &str) -> Result<String> {
    let query: Vec<u16> = "SELECT `Value` FROM `Property` WHERE `Property` = ?\0"
        .encode_utf16()
        .collect();
    let mut raw = 0;
    // SAFETY: fixed SQL, live database and writable view handle.
    check("open MSI property query", unsafe {
        MsiDatabaseOpenViewW(database.raw, query.as_ptr(), &mut raw)
    })?;
    let mut view = Handle::new(raw)?;
    let result = (|| {
        // SAFETY: create a single-field parameter record; zero means failure.
        let parameter = Handle::new(unsafe { MsiCreateRecord(1) })?;
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let result = (|| {
            // SAFETY: record has one field and name is terminated.
            check("bind MSI property name", unsafe {
                MsiRecordSetStringW(parameter.raw, 1, name.as_ptr())
            })?;
            // SAFETY: the view expects one bound string field.
            check("execute MSI property query", unsafe {
                MsiViewExecute(view.raw, parameter.raw)
            })?;
            view.executed = true;
            Ok(())
        })();
        parameter.finish(result)?;
        let mut raw = 0;
        // SAFETY: executed view and writable record output.
        check("fetch MSI property", unsafe {
            MsiViewFetch(view.raw, &mut raw)
        })?;
        let record = Handle::new(raw)?;
        let result = string(|buffer, size| {
            // SAFETY: string supplies a bounded, live UTF-16 buffer and size.
            unsafe { MsiRecordGetStringW(record.raw, 1, buffer, size) }
        });
        let value = record.finish(result)?;
        let mut duplicate = 0;
        // SAFETY: the same view is valid until finish; no unbounded iteration.
        let next = unsafe { MsiViewFetch(view.raw, &mut duplicate) };
        if next == ERROR_SUCCESS {
            return Handle::new(duplicate)?
                .finish(Err(PackageError::Invalid("duplicate MSI property")));
        }
        if next != ERROR_NO_MORE_ITEMS {
            check("finish MSI property query", next)?;
        }
        Ok(value)
    })();
    view.finish(result)
}

fn summary_property(summary: &Handle, property: u32) -> Result<String> {
    let mut kind = 0;
    let mut integer = 0;
    let mut time = FILETIME::default();
    let value = string(|buffer, size| {
        // SAFETY: live summary, valid scalar outputs and bounded string output.
        unsafe {
            MsiSummaryInfoGetPropertyW(
                summary.raw,
                property,
                &mut kind,
                &mut integer,
                &mut time,
                buffer,
                size,
            )
        }
    })?;
    // Summary string properties use VT_LPSTR even with the Unicode API.
    if kind != 30 {
        return Err(PackageError::Invalid("MSI summary property type"));
    }
    Ok(value)
}

fn string(mut read: impl FnMut(*mut u16, *mut u32) -> u32) -> Result<String> {
    // All required properties fit in this fixed bound. There is no allocation
    // or retry driven by untrusted database lengths.
    let mut buffer = [0u16; MAX_PROPERTY_CHARS + 1];
    let mut size = buffer.len() as u32;
    let status = read(buffer.as_mut_ptr(), &mut size);
    if status == ERROR_MORE_DATA {
        return Err(PackageError::Invalid("oversized MSI property"));
    }
    check("read MSI string", status)?;
    let size = size as usize;
    if size == 0 || size > MAX_PROPERTY_CHARS || buffer[size] != 0 || buffer[..size].contains(&0) {
        return Err(PackageError::Invalid("MSI string length"));
    }
    String::from_utf16(&buffer[..size]).map_err(|_| PackageError::Invalid("MSI Unicode string"))
}

fn check(operation: &'static str, code: u32) -> Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(PackageError::Native { operation, code })
    }
}

struct Handle {
    raw: MSIHANDLE,
    executed: bool,
}
impl Handle {
    fn new(raw: MSIHANDLE) -> Result<Self> {
        if raw == 0 {
            return Err(PackageError::Invalid("MSI handle"));
        }
        Ok(Self {
            raw,
            executed: false,
        })
    }
    fn close(&mut self) -> Result<()> {
        let view = if self.executed {
            self.executed = false;
            // SAFETY: this live view has been successfully executed.
            check("close MSI query", unsafe { MsiViewClose(self.raw) })
        } else {
            Ok(())
        };
        let raw = std::mem::take(&mut self.raw);
        // SAFETY: the nonzero owned handle is closed exactly once.
        let handle = check("close MSI handle", unsafe { MsiCloseHandle(raw) });
        combine(view, handle)
    }
    fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        combine(result, self.close())
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        if self.raw != 0
            && let Err(error) = self.close()
        {
            eprintln!("Windows package inspection cleanup failed: {error}");
        }
    }
}

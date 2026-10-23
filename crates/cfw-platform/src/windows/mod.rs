//! Windows observations use native OS APIs, without executing Mac tools or
//! changing registration, network, language or machine-wide timer settings.
use anyhow::{Context, bail};
pub(super) mod diagnostics;
pub(super) mod network;
pub(super) mod shell;
use windows_sys::{
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, RtlNtStatusToDosError},
        Globalization::{GetUserPreferredUILanguages, MUI_LANGUAGE_NAME},
        System::{Diagnostics::Debug::VER_PLATFORM_WIN32_NT, SystemInformation::OSVERSIONINFOW},
    },
};

pub(super) fn operating_system_version() -> anyhow::Result<String> {
    let mut value = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
        ..OSVERSIONINFOW::default()
    };
    // The pinned windows-sys binding calls ntdll's running-kernel query; this
    // observation is not a proxy for availability of an optional Windows API.
    let status = unsafe { RtlGetVersion(&mut value) };
    if status < 0 {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ))
        .context("read Windows kernel version");
    }
    if status != 0
        || value.dwPlatformId != VER_PLATFORM_WIN32_NT
        || value.dwMajorVersion == 0
        || value.dwBuildNumber == 0
    {
        bail!("Windows returned an invalid kernel version");
    }
    Ok(format!(
        "{}.{}.{}",
        value.dwMajorVersion, value.dwMinorVersion, value.dwBuildNumber
    ))
}

pub(super) fn preferred_languages() -> anyhow::Result<Vec<String>> {
    // The user can change preferences between sizing and reading. Only the
    // documented buffer-growth race permits a second complete observation.
    for _ in 0..2 {
        let (mut count, mut size) = (0, 0);
        if unsafe {
            GetUserPreferredUILanguages(
                MUI_LANGUAGE_NAME,
                &mut count,
                std::ptr::null_mut(),
                &mut size,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error()).context("measure Windows UI languages");
        }
        if count > 128 || !(2..=16_384).contains(&size) {
            bail!("Windows UI language list exceeds its observation bounds");
        }
        let mut buffer = vec![0; size as usize];
        if unsafe {
            GetUserPreferredUILanguages(
                MUI_LANGUAGE_NAME,
                &mut count,
                buffer.as_mut_ptr(),
                &mut size,
            )
        } == 0
        {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                continue;
            }
            return Err(error).context("read Windows UI languages");
        }
        let written = buffer
            .get(..size as usize)
            .context("Windows UI language size changed unexpectedly")?;
        return decode_languages(written, count);
    }
    bail!("Windows UI language preferences changed during both bounded reads")
}

fn decode_languages(buffer: &[u16], count: u32) -> anyhow::Result<Vec<String>> {
    if count > 128 || buffer.len() > 16_384 || !buffer.ends_with(&[0, 0]) {
        bail!("Windows UI language list is malformed");
    }
    if count == 0 {
        if buffer != [0, 0] {
            bail!("empty UI language count has unexpected data");
        }
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let mut remaining = buffer;
    for _ in 0..count {
        let length = remaining
            .iter()
            .position(|unit| *unit == 0)
            .filter(|length| (1..=84).contains(length))
            .context("Windows UI language entry is empty or unbounded")?;
        let value = String::from_utf16(&remaining[..length])
            .context("Windows UI language is not valid UTF-16")?;
        if result.contains(&value) {
            bail!("Windows UI language list contains duplicates");
        }
        result.push(value);
        remaining = &remaining[length + 1..];
    }
    if remaining != [0] {
        bail!("Windows UI language count and buffer disagree");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_version_and_languages_are_observed_from_windows() {
        let version = operating_system_version().unwrap();
        let components: Vec<u32> = version
            .split('.')
            .map(|part| part.parse().unwrap())
            .collect();
        assert_eq!(components.len(), 3);
        assert!(components[0] >= 10 && components[2] > 0);
        let languages = preferred_languages().unwrap();
        assert!(
            !languages.is_empty(),
            "the Windows CI image must have an installed UI language"
        );
        assert!(languages.iter().all(|name| !name.contains('\0')));
    }

    #[test]
    fn ordered_multi_strings_preserve_supported_language_names() {
        let input: Vec<u16> = "ja-JP\0zh-Hant\0en-US\0\0".encode_utf16().collect();
        assert_eq!(
            decode_languages(&input, 3).unwrap(),
            ["ja-JP", "zh-Hant", "en-US"]
        );
        assert!(decode_languages(&[0, 0], 0).unwrap().is_empty());
    }

    #[test]
    fn malformed_or_ambiguous_language_buffers_never_become_defaults() {
        for (input, count) in [
            (vec![], 0),
            (vec![0], 0),
            (vec![0, 0], 1),
            (vec![0xd800, 0, 0], 1),
            (vec![b'e' as u16, 0, 0], 0),
            ("en\0en\0\0".encode_utf16().collect(), 2),
            ("en\0ja\0\0".encode_utf16().collect(), 1),
            ("en\0\0".encode_utf16().collect(), 2),
        ] {
            assert!(decode_languages(&input, count).is_err());
        }
    }
}

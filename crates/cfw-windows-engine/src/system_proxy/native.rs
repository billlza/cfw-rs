//! Current-user WinINet LAN settings. Never execute in the privileged service.
use std::{
    io,
    mem::size_of,
    ptr::{null, null_mut},
};

use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GlobalFree, HGLOBAL},
    Networking::WinInet::*,
    System::{
        Memory::GlobalSize,
        Registry::{
            HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_SUBKEY_WOW6464KEY,
            RegGetValueW,
        },
    },
};

use super::{MAX_STRING_UNITS, ProxyError, ProxySettings};

fn error(operation: &'static str) -> ProxyError {
    ProxyError::Native {
        operation,
        source: io::Error::last_os_error(),
    }
}

fn policy(root: HKEY, key: &str, name: &str) -> Result<Option<u32>, ProxyError> {
    let key: Vec<u16> = key.encode_utf16().chain([0]).collect();
    let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut value = 0_u32;
    let mut size = size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            root,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
            null_mut(),
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    match status {
        0 if size == size_of::<u32>() as u32 => Ok(Some(value)),
        0 => Err(ProxyError::InvalidObservation),
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
        _ => Err(ProxyError::Native {
            operation: "read proxy policy",
            source: io::Error::from_raw_os_error(status as i32),
        }),
    }
}

pub(super) fn require_user_policy() -> Result<(), ProxyError> {
    let per_user = policy(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxySettingsPerUser",
    )?;
    if !matches!(per_user, None | Some(1)) {
        return Err(ProxyError::PolicyDenied);
    }
    for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        let restricted = policy(
            root,
            r"SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel",
            "Proxy",
        )?;
        if !matches!(restricted, None | Some(0)) {
            return Err(ProxyError::PolicyDenied);
        }
    }
    Ok(())
}

// WinINet owns the output allocation until it returns; afterwards GlobalFree
// is required even when decoding another option fails. No output string is logged.
struct Strings([HGLOBAL; 3]);
impl Strings {
    fn decode(&self, index: usize) -> Result<Vec<u16>, ProxyError> {
        let allocation = self.0[index];
        if allocation.is_null() {
            // An absent string is the documented empty option value.
            return Ok(Vec::new());
        }
        let size = unsafe { GlobalSize(allocation) };
        if !(2..=64 * 1024).contains(&size) || !size.is_multiple_of(2) {
            return Err(ProxyError::InvalidObservation);
        }
        let units = unsafe {
            std::slice::from_raw_parts(
                allocation.cast::<u16>(),
                (size / 2).min(MAX_STRING_UNITS + 1),
            )
        };
        let end = units
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(ProxyError::InvalidObservation)?;
        if end > MAX_STRING_UNITS {
            return Err(ProxyError::InvalidObservation);
        }
        Ok(units[..end].to_vec())
    }

    fn release(mut self) -> Result<(), ProxyError> {
        let mut failed = None;
        for allocation in &mut self.0 {
            if !allocation.is_null() {
                if unsafe { GlobalFree(*allocation) }.is_null() {
                    *allocation = null_mut();
                } else if failed.is_none() {
                    failed = Some(error("free proxy observation"));
                }
            }
        }
        match failed {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
impl Drop for Strings {
    fn drop(&mut self) {
        for allocation in &self.0 {
            if !allocation.is_null() {
                unsafe { GlobalFree(*allocation) };
            }
        }
    }
}

fn observe_once() -> Result<ProxySettings, ProxyError> {
    let mut options = [
        INTERNET_PER_CONN_FLAGS_UI,
        INTERNET_PER_CONN_PROXY_SERVER,
        INTERNET_PER_CONN_PROXY_BYPASS,
        INTERNET_PER_CONN_AUTOCONFIG_URL,
    ]
    .map(|dw_option| INTERNET_PER_CONN_OPTIONW {
        dwOption: dw_option,
        ..Default::default()
    });
    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    let mut length = list.dwSize;
    let ok = unsafe {
        InternetQueryOptionW(
            null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast(),
            &mut length,
        )
    };
    let failure = (ok == 0).then(|| error("query user LAN proxy settings"));
    let strings = Strings([
        unsafe { options[1].Value.pszValue.cast() },
        unsafe { options[2].Value.pszValue.cast() },
        unsafe { options[3].Value.pszValue.cast() },
    ]);
    let result = (|| {
        if let Some(failure) = failure {
            return Err(failure);
        }
        if length != size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32 {
            return Err(ProxyError::InvalidObservation);
        }
        let settings = ProxySettings {
            flags: unsafe { options[0].Value.dwValue },
            server: strings.decode(0)?,
            bypass: strings.decode(1)?,
            pac_url: strings.decode(2)?,
        };
        settings.validate()?;
        Ok(settings)
    })();
    super::with_cleanup(result, strings.release())
}

pub(super) fn observe() -> Result<ProxySettings, ProxyError> {
    require_user_policy()?;
    let first = observe_once()?;
    if observe_once()? != first {
        return Err(ProxyError::SettingsChanged);
    }
    Ok(first)
}

pub(super) fn apply(settings: &ProxySettings) -> Result<(), ProxyError> {
    require_user_policy()?;
    settings.validate()?;
    let mut server = settings.server.clone();
    server.push(0);
    let mut bypass = settings.bypass.clone();
    bypass.push(0);
    let mut pac = settings.pac_url.clone();
    pac.push(0);
    let mut options = [
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_FLAGS,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                dwValue: settings.flags,
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_SERVER,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: server.as_mut_ptr(),
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: bypass.as_mut_ptr(),
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: pac.as_mut_ptr(),
            },
        },
    ];
    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    if unsafe {
        InternetSetOptionW(
            null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast(),
            list.dwSize,
        )
    } == 0
    {
        // Native failure does not promise that none of the options changed.
        return Err(error("write user LAN proxy settings"));
    }
    notify()
}

pub(super) fn notify() -> Result<(), ProxyError> {
    for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        if unsafe { InternetSetOptionW(null(), option, null(), 0) } == 0 {
            return Err(error("notify proxy settings change"));
        }
    }
    Ok(())
}

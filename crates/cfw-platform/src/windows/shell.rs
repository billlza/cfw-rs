//! Native shell dispatch on one bounded STA worker. Inputs are data, never a
//! command line, shell script, executable override or process arguments.
use anyhow::{Context, bail};
use std::{
    os::windows::ffi::OsStrExt,
    path::{Component, Path, Prefix},
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};
use windows_sys::Win32::{
    System::Com::{
        COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoTaskMemFree,
        CoUninitialize,
    },
    UI::{
        Shell::{
            Common::ITEMIDLIST, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW,
            SHOpenFolderAndSelectItems, SHParseDisplayName, ShellExecuteExW,
        },
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};

// Native shell extensions cannot be forcibly cancelled safely. Keep the slot
// until the worker actually returns, even after a caller stops waiting.
static ACTIVE: AtomicBool = AtomicBool::new(false);
const TIMEOUT: Duration = Duration::from_secs(8);

enum Operation {
    Open(Vec<u16>),
    Reveal(Vec<u16>),
}

pub fn open_windows_external_url(value: &str) -> anyhow::Result<()> {
    if value.len() > 2048
        || value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"')
    {
        bail!("only a bounded plain absolute http(s) URL can be opened");
    }
    let parsed = url::Url::parse(value).context("external URL is invalid")?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none_or(str::is_empty)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.as_str() != value
    {
        bail!("only a plain absolute http(s) URL can be opened");
    }
    dispatch(Operation::Open(value.encode_utf16().chain([0]).collect()))
}

pub fn open_windows_path(path: &Path, reveal: bool) -> anyhow::Result<()> {
    let target = path_target(path)?;
    // Missing paths are errors before any shell association is activated.
    let _metadata = std::fs::metadata(path).context("application-owned path is unavailable")?;
    dispatch(if reveal {
        Operation::Reveal(target)
    } else {
        Operation::Open(target)
    })
}

pub fn open_windows_startup_settings() -> anyhow::Result<()> {
    dispatch(Operation::Open(
        "ms-settings:startupapps\0".encode_utf16().collect(),
    ))
}

pub(super) fn open_location_settings() -> anyhow::Result<()> {
    dispatch(Operation::Open(
        "ms-settings:privacy-location\0".encode_utf16().collect(),
    ))
}

fn path_target(path: &Path) -> anyhow::Result<Vec<u16>> {
    if !path.is_absolute()
        || !matches!(path.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        || path.components().any(|part| matches!(part, Component::ParentDir)
            || matches!(part, Component::Normal(name) if name.encode_wide().any(|unit| unit == u16::from(b':')))) {
        bail!("only an absolute local application-owned path can be opened");
    }
    let mut target: Vec<u16> = path.as_os_str().encode_wide().collect();
    if target.is_empty()
        || target.len() > 32766
        || target.iter().any(|unit| *unit < 32 || *unit == 34)
    {
        bail!("application-owned path is invalid or too long");
    }
    target.push(0);
    Ok(target)
}

fn dispatch(operation: Operation) -> anyhow::Result<()> {
    ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| anyhow::anyhow!("a Windows shell operation is still in progress"))?;
    struct Active;
    impl Drop for Active {
        fn drop(&mut self) {
            ACTIVE.store(false, Ordering::Release);
        }
    }
    let active = Active;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("cfw-windows-shell".into())
        .spawn(move || {
            let _active = active;
            let result = execute(operation);
            if let Err(unreceived) = sender.send(result)
                && let Err(error) = unreceived.0
            {
                eprintln!(
                    "Windows shell dispatch failed after its caller stopped waiting: {error}"
                );
            }
        })
        .context("start Windows shell worker")?;
    match receiver.recv_timeout(TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => bail!(
            "Windows shell dispatch timed out; acceptance is unknown and its worker remains reserved"
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            bail!("Windows shell worker ended without a result")
        }
    }
}

fn execute(operation: Operation) -> anyhow::Result<()> {
    let status = unsafe {
        CoInitializeEx(
            null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    if status < 0 {
        bail!("initialize Windows shell apartment: {status:#x}");
    }
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }
    let _apartment = Apartment;
    match operation {
        Operation::Open(target) => {
            let verb: Vec<u16> = "open\0".encode_utf16().collect();
            let mut information = SHELLEXECUTEINFOW {
                cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
                fMask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
                lpVerb: verb.as_ptr(),
                lpFile: target.as_ptr(),
                nShow: SW_SHOWNORMAL,
                ..Default::default()
            };
            // SAFETY: strings remain live, no parameter vector or executable
            // override is supplied, and COM is initialized on this STA worker.
            if unsafe { ShellExecuteExW(&mut information) } == 0 {
                return Err(std::io::Error::last_os_error()).context("Windows shell dispatch");
            }
            Ok(())
        }
        Operation::Reveal(target) => {
            let mut item = null_mut();
            let status = unsafe {
                SHParseDisplayName(target.as_ptr(), null_mut(), &mut item, 0, null_mut())
            };
            struct Item(*mut ITEMIDLIST);
            impl Drop for Item {
                fn drop(&mut self) {
                    unsafe { CoTaskMemFree(self.0.cast()) };
                }
            }
            let item = Item(item);
            if status < 0 || item.0.is_null() {
                bail!("parse Windows shell item: {status:#x}");
            }
            // With zero children, this selects the exact item in its parent.
            let status = unsafe { SHOpenFolderAndSelectItems(item.0, 0, null(), 0) };
            if status < 0 {
                bail!("reveal Windows shell item: {status:#x}");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_paths_cannot_be_relative_network_device_or_parent_traversal() {
        for path in [
            r"file.json",
            r"C:file.json",
            r"\\server\share\file.json",
            r"\\.\pipe\cfw",
            r"C:\data\..\file.json",
            "C:\\data\\bad\0.json",
        ] {
            assert!(path_target(Path::new(path)).is_err(), "{path:?}");
        }
        for path in [
            r"C:\配置 文件\a,b.profile.json",
            r"\\?\C:\配置 文件\a.profile.json",
        ] {
            let target = path_target(Path::new(path)).unwrap();
            assert_eq!(target.last(), Some(&0));
        }
    }

    #[test]
    fn unsafe_url_inputs_never_reach_the_native_dispatcher() {
        for url in [
            "file:///C:/file",
            "ms-settings:startupapps",
            "javascript:alert(1)",
            "https://user:pass@example.com/",
            "https://example.com/a b",
            "https://example.com/\n",
            "https://example.com/\"",
            " https://example.com/",
        ] {
            assert!(open_windows_external_url(url).is_err());
        }
    }
}

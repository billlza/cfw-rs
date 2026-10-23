#![cfg(windows)]
use anyhow::{Context, bail};
use std::{
    io::Read,
    path::Path,
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_CREATED_NEW_KEY, REG_OPTION_NON_VOLATILE, REG_SZ,
        RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW,
    },
    UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify},
};

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn create(key: &str) -> anyhow::Result<Key> {
    let mut handle = null_mut();
    let mut disposition = 0;
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            wide(key).as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            null(),
            &mut handle,
            &mut disposition,
        )
    };
    if status != ERROR_SUCCESS {
        bail!("create fixture association: Win32 {status}");
    }
    let key = Key(handle);
    if disposition != REG_CREATED_NEW_KEY {
        bail!("fixture association already existed");
    }
    Ok(key)
}

fn value(key: &Key, text: &str) -> anyhow::Result<()> {
    let text = wide(text);
    let status = unsafe {
        RegSetValueExW(
            key.0,
            null(),
            0,
            REG_SZ,
            text.as_ptr().cast(),
            (text.len() * 2) as u32,
        )
    };
    if status != ERROR_SUCCESS {
        bail!("write fixture association: Win32 {status}");
    }
    Ok(())
}

#[derive(Default)]
struct Associations {
    roots: Vec<String>,
}
impl Associations {
    fn root(&mut self, path: &str) -> anyhow::Result<Key> {
        let key = create(path)?;
        self.roots.push(path.into());
        Ok(key)
    }
    fn remove(&mut self) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        self.roots.retain(|path| {
            let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, wide(path).as_ptr()) };
            if status == ERROR_SUCCESS {
                false
            } else {
                errors.push(format!("{path}: Win32 {status}"));
                true
            }
        });
        unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED as i32, SHCNF_IDLIST, null(), null()) };
        if !errors.is_empty() {
            bail!("fixture association cleanup: {}", errors.join("; "));
        }
        Ok(())
    }
}
impl Drop for Associations {
    fn drop(&mut self) {
        if !self.roots.is_empty()
            && let Err(error) = self.remove()
        {
            eprintln!("native shell fixture cleanup failed: {error}");
        }
    }
}

fn receipt(directory: &Path) -> anyhow::Result<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match std::fs::File::open(directory.join("receipt.json")) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(8193).read_to_end(&mut bytes)?;
                if bytes.len() > 8192 {
                    bail!("recipient receipt exceeds its bound");
                }
                return serde_json::from_slice(&bytes).context("decode native recipient receipt");
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                return Err(error).context("native recipient did not report the opened file");
            }
        }
    }
}

#[test]
fn shell_dispatches_one_unicode_document_to_its_actual_registered_handler() -> anyhow::Result<()> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("CFW_NATIVE_SHELL_TESTS").as_deref() != Ok("1")
    {
        bail!("native shell test requires opted-in disposable GitHub CI");
    }
    let root = std::path::PathBuf::from(
        std::env::var_os("RUNNER_TEMP").context("missing temporary root")?,
    );
    let directory = root.join(format!("cfw-native-shell-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let mut associations = Associations::default();
    let operation = (|| -> anyhow::Result<serde_json::Value> {
        let extension = format!("cfw-native-shell-{}", std::process::id());
        let class = format!("CFW.NativeShell.{}", std::process::id());
        let fixture = std::env::var("CFW_NATIVE_SHELL_FIXTURE").context("missing fixture image")?;
        if fixture.contains('"')
            || !Path::new(&fixture).is_absolute()
            || !Path::new(&fixture).is_file()
        {
            bail!("invalid fixture executable");
        }
        let class_path = format!(r"Software\Classes\{class}");
        let class_key = associations.root(&class_path)?;
        value(&class_key, "CFW disposable native shell fixture")?;
        drop(class_key);
        let command = create(&format!(r"{class_path}\shell\open\command"))?;
        value(&command, &format!("\"{fixture}\" \"%1\""))?;
        drop(command);
        let extension_key = associations.root(&format!(r"Software\Classes\.{extension}"))?;
        value(&extension_key, &class)?;
        drop(extension_key);
        unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED as i32, SHCNF_IDLIST, null(), null()) };
        let target = directory.join(format!("配置 空格 (a)&b.{extension}"));
        std::fs::write(&target, b"native shell dispatch fixture")?;
        cfw_platform::open_windows_path(&target, false)?;
        let observed = receipt(&directory)?;
        if observed["path"] != target.to_str().context("Unicode fixture path")?
            || observed["arguments"] != 1
            || observed["pid"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid == u64::from(std::process::id()))
            || observed["source"] != std::env::var("CFW_NATIVE_SHELL_SOURCE")?
        {
            bail!("native handler did not receive the exact single document argument");
        }
        Ok(observed)
    })();
    let registry_cleanup = associations.remove();
    let file_cleanup = std::fs::remove_dir_all(&directory);
    match (operation, registry_cleanup, file_cleanup) {
        (Ok(observed), Ok(()), Ok(())) => {
            println!(
                "{}",
                serde_json::json!({"native_shell_recipient":observed,
                "associations_removed":true,"fixture_directory_removed":true,
                "explorer_selection_verified":false,"browser_launch_verified":false,"release_accepted":false})
            );
            Ok(())
        }
        (operation, registry, files) => bail!(
            "native shell operation: {operation:?}; registry cleanup: {registry:?}; file cleanup: {files:?}"
        ),
    }
}

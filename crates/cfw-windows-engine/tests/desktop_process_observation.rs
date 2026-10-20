#![cfg(windows)]

#[path = "../../../apps/cfw-tauri-shell/src/process_identity/windows.rs"]
mod desktop;

use cfw_windows_engine::{NativePeerProcess, PeerIdentityError};
use desktop::{
    ProcessIdentity, current_process_identity, exact_processes, process_identity_exists,
};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct OwnedChild(Child);

impl OwnedChild {
    fn start(path: &Path) -> Self {
        Self(
            Command::new(path)
                .args(["/D", "/Q", "/C", "set /p CFW_PROCESS_INPUT="])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("start owned waiting process"),
        )
    }

    fn finish(&mut self) {
        self.0.stdin.take().unwrap().write_all(b"done\r\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "{status}");
                return;
            }
            assert!(Instant::now() < deadline, "owned process did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = self.0.kill() {
                    eprintln!("owned process cleanup failed: {error}");
                    return;
                }
                if let Err(error) = self.0.wait() {
                    eprintln!("owned process collection failed: {error}");
                }
            }
            Err(error) => eprintln!("owned process exit observation failed: {error}"),
        }
    }
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let executable = temporary.path().join("进程 观察.exe");
    let permissions = fs::File::create(&executable)
        .unwrap()
        .metadata()
        .unwrap()
        .permissions();
    let system =
        std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/cmd.exe");
    fs::copy(system, &executable).unwrap();
    fs::set_permissions(&executable, permissions).unwrap();
    (temporary, executable)
}

#[test]
fn desktop_identity_preserves_full_native_scope_and_filetime_without_unix_fields() {
    let executable = std::env::current_exe().unwrap();
    let identity = current_process_identity(&executable).unwrap();
    let native = NativePeerProcess::open(std::process::id()).unwrap();
    assert!(identity.is_this_process());
    assert!(process_identity_exists(&identity).unwrap());
    let wire = serde_json::to_value(&identity).unwrap();
    assert_eq!(wire["logon"]["sid"], native.identity().user_sid());
    assert_eq!(
        wire["logon"]["authentication_id"],
        native.identity().authentication_id()
    );
    assert_eq!(wire["logon"]["session_id"], native.identity().session_id());
    assert_eq!(
        wire["creation_filetime"],
        native.identity().process_creation_time()
    );
    assert!(wire.get("uid").is_none());
    assert!(wire.get("start_identity").is_none());
    let restored: ProcessIdentity = serde_json::from_value(wire).unwrap();
    assert_eq!(identity, restored);
    assert!(process_identity_exists(&restored).unwrap());
    assert!(exact_processes(&executable).unwrap().contains(&identity));
}

#[test]
fn recorded_incarnations_and_foreign_logons_do_not_become_native_process_authority() {
    let identity = current_process_identity(&std::env::current_exe().unwrap()).unwrap();
    let value = serde_json::to_value(&identity).unwrap();
    let mut changed = value.clone();
    changed["creation_filetime"] = (value["creation_filetime"].as_u64().unwrap() + 1).into();
    let changed: ProcessIdentity = serde_json::from_value(changed).unwrap();
    assert!(!process_identity_exists(&changed).unwrap());
    for field in ["sid", "authentication_id", "session_id"] {
        let mut changed = value.clone();
        changed["logon"][field] = match field {
            "sid" => "S-1-5-18".into(),
            _ => (value["logon"][field].as_u64().unwrap() + 1).into(),
        };
        let changed: ProcessIdentity = serde_json::from_value(changed).unwrap();
        assert!(process_identity_exists(&changed).is_err(), "{field}");
    }
    for field in ["integrity_rid", "app_container", "restricted"] {
        let mut changed = value.clone();
        changed[field] = if field == "integrity_rid" {
            (value[field].as_u64().unwrap() + 1).into()
        } else {
            (!value[field].as_bool().unwrap()).into()
        };
        let changed: ProcessIdentity = serde_json::from_value(changed).unwrap();
        assert!(process_identity_exists(&changed).is_err(), "{field}");
    }
    assert!(NativePeerProcess::open_if_running(0).is_err());
    assert!(
        NativePeerProcess::open_if_running(u32::MAX)
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_real_unicode_path_child_is_observed_until_the_retained_process_object_signals_exit() {
    let (_temporary, executable) = fixture();
    let mut child = OwnedChild::start(&executable);
    let retained = NativePeerProcess::open(child.0.id()).unwrap();
    assert!(matches!(
        retained.processes_using_file(&executable),
        Err(PeerIdentityError::WrongProcess)
    ));
    let listed = exact_processes(&executable).unwrap();
    assert_eq!(listed.len(), 1);
    let identity = &listed[0];
    assert_eq!(identity.pid, child.0.id());
    assert!(!identity.is_this_process());
    assert!(process_identity_exists(identity).unwrap());
    assert!(current_process_identity(&executable).is_err());
    child.finish();
    assert!(matches!(
        retained.observed_image_path(),
        Err(PeerIdentityError::Exited)
    ));
    assert!(!process_identity_exists(identity).unwrap());
    assert!(exact_processes(&executable).unwrap().is_empty());
}

#[test]
fn process_enumeration_refuses_to_truncate_more_than_eight_owned_matches() {
    let (_temporary, executable) = fixture();
    let mut children: Vec<_> = (0..9).map(|_| OwnedChild::start(&executable)).collect();
    assert!(
        exact_processes(&executable)
            .unwrap_err()
            .contains("more than eight")
    );
    for child in &mut children {
        child.finish();
    }
    assert!(exact_processes(&executable).unwrap().is_empty());
}

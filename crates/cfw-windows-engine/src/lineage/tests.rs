use super::*;
use std::{
    process::{Command, Stdio},
    thread,
    time::Instant,
};
use windows_sys::Win32::Security::{
    Credentials::CredDeleteW, ImpersonateSelf, RevertToSelf, SecurityImpersonation,
};

const CHILD_TARGET: &str = "CFW_WINDOWS_LINEAGE_TEST_TARGET";

struct Fixture(WindowsEngineGenerationStore);

impl Fixture {
    fn new() -> Self {
        Self(WindowsEngineGenerationStore::for_target(format!(
            "{TARGET}.test.{}",
            Uuid::new_v4()
        )))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let target = self.0.target_wide();
        let result = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if result == 0 && io::Error::last_os_error().raw_os_error() != Some(ERROR_NOT_FOUND as i32)
        {
            // Report cleanup errors even during a failed test without double panic.
            eprintln!(
                "test lineage cleanup failed for isolated target: {}",
                io::Error::last_os_error()
            );
            if !thread::panicking() {
                panic!("test lineage cleanup failed");
            }
        }
    }
}

fn raw_bytes(store: &WindowsEngineGenerationStore) -> Vec<u8> {
    let target = store.target_wide();
    let mut pointer = null_mut();
    assert_ne!(
        unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pointer) },
        0
    );
    assert!(!pointer.is_null());
    let record = unsafe { &*pointer };
    assert!(!record.CredentialBlob.is_null() && record.CredentialBlobSize > 0);
    assert!(record.CredentialBlobSize <= CRED_MAX_CREDENTIAL_BLOB_SIZE);
    let bytes = unsafe {
        std::slice::from_raw_parts(record.CredentialBlob, record.CredentialBlobSize as usize)
    }
    .to_vec();
    unsafe { CredFree(pointer.cast()) };
    bytes
}

#[test]
fn real_credential_manager_persists_exact_lineage_and_compare_exchange() {
    let fixture = Fixture::new();
    let first = fixture.0.load_lineage().unwrap();
    assert_eq!(first.generation, 0);
    assert_eq!(first.session.config_epoch, 1);
    assert!(
        !Uuid::parse_str(&first.session.installation_id)
            .unwrap()
            .is_nil()
    );
    assert_eq!(fixture.0.reserve_generation(0).unwrap(), 1);
    let reopened = fixture.0.clone();
    let second = reopened.load_lineage().unwrap();
    assert_eq!(first.session, second.session);
    assert_eq!(second.generation, 1);
    assert!(matches!(
        reopened.reserve_generation(0),
        Err(LineageError::Conflict {
            expected: 0,
            actual: 1
        })
    ));
    assert_eq!(reopened.reserve_generation(1).unwrap(), 2);
    assert_eq!(fixture.0.load_lineage().unwrap().generation, 2);
}

#[test]
fn invalid_native_document_is_never_overwritten_or_treated_as_absent() {
    let fixture = Fixture::new();
    let baseline = fixture.0.load_or_initialize().unwrap();
    let good = baseline.encode().unwrap();
    let mut unknown: serde_json::Value = serde_json::from_slice(&good).unwrap();
    unknown["unexpected"] = serde_json::json!(true);
    let mut zero_epoch = baseline.clone();
    zero_epoch.config_epoch = 0;
    let mut nil_id = baseline.clone();
    nil_id.installation_id = Uuid::nil();
    for mut bytes in [
        b"not-json".to_vec(),
        [good.as_slice(), b"\n"].concat(),
        serde_json::to_vec(&unknown).unwrap(),
        serde_json::to_vec(&zero_epoch).unwrap(),
        serde_json::to_vec(&nil_id).unwrap(),
        b"{\"schema_version\":1,\"schema_version\":1}".to_vec(),
    ] {
        fixture.0.write(&mut bytes).unwrap();
        assert!(matches!(
            fixture.0.load_lineage(),
            Err(LineageError::InvalidDocument)
        ));
        assert!(matches!(
            fixture.0.reserve_generation(0),
            Err(LineageError::InvalidDocument)
        ));
        assert_eq!(raw_bytes(&fixture.0), bytes);
    }
}

#[test]
fn generation_exhaustion_does_not_wrap_or_replace_identity() {
    let fixture = Fixture::new();
    let mut document = fixture.0.load_or_initialize().unwrap();
    document.generation = u64::MAX;
    fixture.0.publish(&document).unwrap();
    assert!(matches!(
        fixture.0.reserve_generation(u64::MAX),
        Err(LineageError::Exhausted)
    ));
    assert_eq!(fixture.0.load_lineage().unwrap(), document.lineage());
}

#[test]
fn explicit_credential_removal_never_reuses_the_old_installation_identity() {
    let fixture = Fixture::new();
    let first = fixture.0.load_lineage().unwrap();
    fixture.0.reserve_generation(0).unwrap();
    let target = fixture.0.target_wide();
    assert_ne!(
        unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) },
        0
    );
    assert!(matches!(
        fixture.0.load_lineage(),
        Err(LineageError::AuthorityMissing)
    ));
    assert!(matches!(
        fixture.0.reserve_generation(1),
        Err(LineageError::AuthorityMissing)
    ));
    let recreated = WindowsEngineGenerationStore::for_target(fixture.0.target.clone())
        .load_lineage()
        .unwrap();
    assert_ne!(
        first.session.installation_id,
        recreated.session.installation_id
    );
    assert_eq!(recreated.generation, 0);
    assert!(matches!(
        fixture.0.load_lineage(),
        Err(LineageError::IdentityChanged)
    ));
}

#[test]
fn same_generation_cannot_hide_replacement_of_the_bound_installation() {
    let fixture = Fixture::new();
    let first = fixture.0.load_lineage().unwrap();
    let replacement = Document {
        schema_version: 1,
        installation_id: Uuid::new_v4(),
        config_epoch: first.session.config_epoch,
        generation: first.generation,
    };
    fixture.0.publish(&replacement).unwrap();
    assert!(matches!(
        fixture.0.reserve_generation(first.generation),
        Err(LineageError::IdentityChanged)
    ));
    assert_eq!(raw_bytes(&fixture.0), replacement.encode().unwrap());
}

#[test]
fn impersonating_thread_cannot_read_or_reserve_process_lineage() {
    let fixture = Fixture::new();
    let initial = fixture.0.load_lineage().unwrap();
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            assert_ne!(unsafe { RevertToSelf() }, 0);
        }
    }
    assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
    let revert = Revert;
    let read = fixture.0.load_lineage();
    let write = fixture.0.reserve_generation(0);
    drop(revert);
    assert!(matches!(
        read,
        Err(LineageError::Storage(
            cfw_windows_storage::Error::ImpersonatedIdentity
        ))
    ));
    assert!(matches!(
        write,
        Err(LineageError::Storage(
            cfw_windows_storage::Error::ImpersonatedIdentity
        ))
    ));
    assert_eq!(fixture.0.load_lineage().unwrap(), initial);
}

#[test]
fn processes_reserve_unique_monotonic_generations() {
    if let Some(target) = std::env::var_os(CHILD_TARGET) {
        let target = target.to_str().unwrap().to_owned();
        let suffix = target.strip_prefix(&format!("{TARGET}.test.")).unwrap();
        assert_eq!(Uuid::parse_str(suffix).unwrap().to_string(), suffix);
        let store = WindowsEngineGenerationStore::for_target(target);
        for _ in 0..8 {
            let mut reserved = false;
            for _ in 0..64 {
                let previous = store.load_lineage().unwrap();
                match store.reserve_generation(previous.generation) {
                    Ok(next) => {
                        assert_eq!(next, previous.generation + 1);
                        reserved = true;
                        break;
                    }
                    Err(LineageError::Conflict { .. }) => {}
                    Err(error) => panic!("reservation failed: {error}"),
                }
            }
            assert!(reserved, "bounded CAS contention budget exhausted");
        }
        return;
    }
    let fixture = Fixture::new();
    let original = fixture.0.load_lineage().unwrap();
    let mut children = Vec::new();
    for _ in 0..4 {
        children.push(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "lineage::tests::processes_reserve_unique_monotonic_generations",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_TARGET, &fixture.0.target)
                .env("RUST_BACKTRACE", "0")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut timeout = false;
    while children
        .iter_mut()
        .any(|child| child.try_wait().unwrap().is_none())
    {
        if Instant::now() >= deadline {
            timeout = true;
            for child in &mut children {
                if child.try_wait().unwrap().is_none() {
                    child.kill().unwrap();
                }
            }
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "lineage child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(!timeout, "child processes exceeded admission budget");
    let final_state = fixture.0.load_lineage().unwrap();
    assert_eq!(final_state.session, original.session);
    assert_eq!(final_state.generation, 32);
}

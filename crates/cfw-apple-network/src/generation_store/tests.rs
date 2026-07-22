use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cfw_engine_api::EngineGenerationStore;

use super::*;

#[derive(Default)]
struct MemoryAuthority {
    state: Mutex<MemoryAuthorityState>,
}

#[derive(Default)]
struct MemoryAuthorityState {
    record: Option<AuthorityRecord>,
    fail_load: bool,
    fail_create: bool,
    fail_save: bool,
    commit_then_fail_save: bool,
}

impl MemoryAuthority {
    fn set_fail_load(&self, value: bool) {
        self.state.lock().expect("authority lock").fail_load = value;
    }

    fn set_fail_save(&self, value: bool) {
        self.state.lock().expect("authority lock").fail_save = value;
    }

    fn set_commit_then_fail_save(&self, value: bool) {
        self.state
            .lock()
            .expect("authority lock")
            .commit_then_fail_save = value;
    }

    fn replace_record(&self, record: AuthorityRecord) {
        self.state.lock().expect("authority lock").record = Some(record);
    }

    fn record(&self) -> Option<AuthorityRecord> {
        self.state.lock().expect("authority lock").record.clone()
    }
}

impl LineageAuthority for MemoryAuthority {
    fn load(&self) -> Result<Option<AuthorityRecord>, GenerationStoreError> {
        let state = self.state.lock().expect("authority lock");
        if state.fail_load {
            return Err(GenerationStoreError::AuthorityLoad(
                "injected load failure".into(),
            ));
        }
        Ok(state.record.clone())
    }

    fn create(&self, record: &AuthorityRecord) -> Result<CreateOutcome, GenerationStoreError> {
        let mut state = self.state.lock().expect("authority lock");
        if state.fail_create {
            return Err(GenerationStoreError::AuthorityCreate(
                "injected create failure".into(),
            ));
        }
        if state.record.is_some() {
            return Ok(CreateOutcome::AlreadyExists);
        }
        state.record = Some(record.clone());
        Ok(CreateOutcome::Created)
    }

    fn compare_exchange(
        &self,
        expected_revision: &str,
        replacement: &AuthorityRecord,
    ) -> Result<CompareExchangeOutcome, GenerationStoreError> {
        let mut state = self.state.lock().expect("authority lock");
        if state.fail_save {
            return Err(GenerationStoreError::AuthoritySave(
                "injected save failure".into(),
            ));
        }
        let Some(current) = state.record.as_ref() else {
            return Ok(CompareExchangeOutcome::Conflict);
        };
        if current.revision != expected_revision {
            return Ok(CompareExchangeOutcome::Conflict);
        }
        state.record = Some(replacement.clone());
        if state.commit_then_fail_save {
            return Err(GenerationStoreError::AuthoritySave(
                "injected post-commit save failure".into(),
            ));
        }
        Ok(CompareExchangeOutcome::Swapped)
    }
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "cfw-keychain-lineage-{name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        if self.0.exists() {
            fs::remove_dir_all(&self.0).expect("remove test lineage root");
        }
    }
}

fn store(root: &TestRoot, authority: Arc<MemoryAuthority>) -> KeychainEngineGenerationStore {
    KeychainEngineGenerationStore::with_authority(root.0.clone(), authority)
        .expect("generation store")
}

#[test]
fn keychain_generation_survives_store_restart() {
    let root = TestRoot::new("restart");
    let authority = Arc::new(MemoryAuthority::default());
    let first = store(&root, authority.clone());
    let initial = first.load().expect("initial lineage");
    assert_eq!(initial.generation, 0);
    assert_eq!(first.reserve_next(0).expect("generation one"), 1);

    let second = store(&root, authority);
    let reloaded = second.load().expect("reloaded lineage");
    assert_eq!(reloaded.session, initial.session);
    assert_eq!(reloaded.generation, 1);
}

#[test]
fn application_support_deletion_does_not_reset_keychain_authority() {
    let root = TestRoot::new("root-deletion");
    let authority = Arc::new(MemoryAuthority::default());
    let first = store(&root, authority.clone());
    let initial = first.load().expect("initial lineage");
    assert_eq!(first.reserve_next(0).expect("generation one"), 1);
    fs::remove_dir_all(&root.0).expect("delete Application Support engine root");

    let second = store(&root, authority);
    let restored = second.load().expect("lineage from retained Keychain");
    assert_eq!(restored.session, initial.session);
    assert_eq!(restored.generation, 1);
    assert!(cache_path(&root.0).is_file(), "cache must be recreated");
}

#[test]
fn deleted_or_tampered_cache_is_repaired_from_keychain() {
    let root = TestRoot::new("cache-repair");
    let authority = Arc::new(MemoryAuthority::default());
    let generation_store = store(&root, authority.clone());
    generation_store.load().expect("initialize");
    generation_store.reserve_next(0).expect("generation one");
    let canonical = authority.record().expect("authority record").bytes;

    fs::write(cache_path(&root.0), b"{\"generation\":0}").expect("tamper cache");
    assert_eq!(
        generation_store.load().expect("repair tamper").generation,
        1
    );
    assert_eq!(
        fs::read(cache_path(&root.0)).expect("read repaired cache"),
        canonical
    );

    fs::remove_file(cache_path(&root.0)).expect("delete cache");
    assert_eq!(
        generation_store.load().expect("repair deletion").generation,
        1
    );
    assert_eq!(
        fs::read(cache_path(&root.0)).expect("read recreated cache"),
        canonical
    );
}

#[test]
fn keychain_load_and_save_failures_never_reset_authority() {
    let root = TestRoot::new("authority-failure");
    let authority = Arc::new(MemoryAuthority::default());
    authority.set_fail_load(true);
    let generation_store = store(&root, authority.clone());
    assert!(generation_store.load().is_err());
    assert!(
        authority.record().is_none(),
        "load failure must not initialize"
    );

    authority.set_fail_load(false);
    let initial = generation_store.load().expect("initialize after recovery");
    authority.set_fail_save(true);
    assert!(generation_store.reserve_next(0).is_err());
    assert_eq!(
        authority
            .record()
            .expect("retained authority")
            .document()
            .expect("valid authority")
            .generation,
        0
    );

    authority.set_fail_save(false);
    let repaired = generation_store
        .load()
        .expect("repair cache after save failure");
    assert_eq!(repaired.session, initial.session);
    assert_eq!(repaired.generation, 0);
}

#[test]
fn committed_keychain_update_is_success_even_when_api_returns_an_error() {
    let root = TestRoot::new("commit-then-error");
    let authority = Arc::new(MemoryAuthority::default());
    let generation_store = store(&root, authority.clone());
    let initial = generation_store.load().expect("initial lineage");

    authority.set_commit_then_fail_save(true);
    assert_eq!(
        generation_store
            .reserve_next(0)
            .expect("authoritative reload confirms committed generation"),
        1
    );
    assert_eq!(
        authority
            .record()
            .expect("committed authority")
            .document()
            .expect("canonical authority")
            .generation,
        1
    );

    let restarted = store(&root, authority).load().expect("restart lineage");
    assert_eq!(restarted.session, initial.session);
    assert_eq!(restarted.generation, 1);
}

#[test]
fn stale_concurrent_writer_loses_keychain_compare_and_swap() {
    let first_root = TestRoot::new("writer-one");
    let second_root = TestRoot::new("writer-two");
    let authority = Arc::new(MemoryAuthority::default());
    let first = store(&first_root, authority.clone());
    let second = store(&second_root, authority);
    assert_eq!(first.load().expect("first load").generation, 0);
    assert_eq!(second.load().expect("second load").generation, 0);

    assert_eq!(first.reserve_next(0).expect("winning writer"), 1);
    let error = second.reserve_next(0).expect_err("stale writer must fail");
    assert!(
        error.contains("expected 0, found 1"),
        "unexpected conflict: {error}"
    );
    assert_eq!(second.load().expect("second cache repaired").generation, 1);
}

#[test]
fn corrupt_noncanonical_or_revision_mismatched_keychain_data_fails_closed() {
    let root = TestRoot::new("corrupt-authority");
    let authority = Arc::new(MemoryAuthority::default());
    let document = LineageDocument::new();
    let canonical = document.canonical_bytes().expect("canonical document");

    let noncanonical = [b" ".as_slice(), canonical.as_slice(), b"\n".as_slice()].concat();
    authority.replace_record(AuthorityRecord {
        revision: revision_for(&noncanonical),
        bytes: noncanonical,
    });
    assert!(store(&root, authority.clone()).load().is_err());

    let malformed = b"{not-json}".to_vec();
    authority.replace_record(AuthorityRecord {
        revision: revision_for(&malformed),
        bytes: malformed,
    });
    assert!(store(&root, authority.clone()).load().is_err());

    authority.replace_record(AuthorityRecord {
        bytes: canonical,
        revision: "0".repeat(64),
    });
    assert!(store(&root, authority).load().is_err());
}

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cfw_engine_api::EngineGenerationStore;

use super::*;

#[path = "recovery_tests.rs"]
mod recovery_tests;

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
    /// Another writer creates this record first; creation reports a duplicate.
    created_meanwhile: Option<AuthorityRecord>,
    /// Creation reports a duplicate that no read can find.
    duplicate_vanishes: bool,
    /// Another writer stores this record first; the swap reports a conflict.
    swapped_meanwhile: Option<AuthorityRecord>,
    /// A failed save also loses the stored record.
    failed_save_loses_record: bool,
    /// A failed save also puts a directory where this cache file was.
    failed_save_blocks_cache: Option<PathBuf>,
    /// Loading panics, as a broken Security.framework call might.
    panic_on_load: bool,
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

    fn edit(&self, change: impl FnOnce(&mut MemoryAuthorityState)) {
        change(&mut self.state.lock().expect("authority lock"));
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
        // Released before panicking, so only the store's lock is poisoned.
        let panic_on_load = self.state.lock().expect("authority lock").panic_on_load;
        assert!(!panic_on_load, "injected load panic");
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
        if let Some(other) = state.created_meanwhile.take() {
            state.record = Some(other);
            return Ok(CreateOutcome::AlreadyExists);
        }
        if state.duplicate_vanishes || state.record.is_some() {
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
        if let Some(other) = state.swapped_meanwhile.take() {
            state.record = Some(other);
            return Ok(CompareExchangeOutcome::Conflict);
        }
        if state.fail_save {
            if state.failed_save_loses_record {
                state.record = None;
            }
            if let Some(cache) = state.failed_save_blocks_cache.take() {
                fs::remove_file(&cache).expect("remove the cache");
                fs::create_dir(&cache).expect("block the cache path");
            }
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

/// An authority record holding `bytes`, whatever they are.
fn raw_record(bytes: &[u8]) -> AuthorityRecord {
    AuthorityRecord {
        bytes: bytes.to_vec(),
        revision: revision_for(bytes),
    }
}

/// The record of a fresh lineage at `generation`.
fn record_at(generation: u64) -> AuthorityRecord {
    AuthorityRecord::from_document(&LineageDocument {
        generation,
        ..LineageDocument::new()
    })
    .expect("lineage record")
}

fn store(root: &TestRoot, authority: Arc<MemoryAuthority>) -> KeychainEngineGenerationStore {
    KeychainEngineGenerationStore::with_authority(root.0.clone(), authority)
        .expect("generation store")
}

#[test]
fn startup_lineage_lock_contention_is_bounded_and_does_not_touch_keychain() {
    let root = TestRoot::new("startup-lock-contention");
    let authority = Arc::new(MemoryAuthority::default());
    let generation_store = store(&root, authority.clone());
    let guard = cache::exclusive_lock(&root.0).unwrap();
    let (reply, result) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        reply.send(generation_store.load()).unwrap();
    });
    let observed = result.recv_timeout(std::time::Duration::from_secs(5));
    drop(guard);
    reader.join().unwrap();
    assert!(observed.unwrap().unwrap_err().contains("remained locked"));
    assert!(authority.record().is_none());
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

#[test]
fn a_new_store_prepares_its_private_cache_root_without_the_keychain() {
    let root = TestRoot::new("new-store");
    KeychainEngineGenerationStore::new(root.0.clone()).expect("generation store");
    let metadata = fs::metadata(&root.0).expect("cache root");
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

#[test]
fn a_lineage_another_writer_created_first_is_adopted() {
    let root = TestRoot::new("created-meanwhile");
    let authority = Arc::new(MemoryAuthority::default());
    let other = record_at(5);
    authority.edit(|state| state.created_meanwhile = Some(other.clone()));
    let lineage = store(&root, authority).load().expect("adopted lineage");
    assert_eq!(lineage.generation, 5);
    assert_eq!(fs::read(cache_path(&root.0)).expect("cache"), other.bytes);
}

#[test]
fn a_duplicate_lineage_that_cannot_be_read_fails_closed() {
    let root = TestRoot::new("duplicate-vanishes");
    let authority = Arc::new(MemoryAuthority::default());
    authority.edit(|state| state.duplicate_vanishes = true);
    assert_eq!(
        store(&root, authority).load().expect_err("no lineage"),
        GenerationStoreError::AuthorityInconsistent(
            "item disappeared after duplicate creation".into()
        )
        .to_string()
    );
    assert!(!cache_path(&root.0).exists());
}

#[test]
fn a_lost_compare_and_swap_reports_and_caches_the_winning_generation() {
    let root = TestRoot::new("swapped-meanwhile");
    let authority = Arc::new(MemoryAuthority::default());
    let generation_store = store(&root, authority.clone());
    generation_store.load().expect("initialize");
    let winner = record_at(7);
    authority.edit(|state| state.swapped_meanwhile = Some(winner.clone()));
    assert_eq!(
        generation_store
            .reserve_next(0)
            .expect_err("another writer won"),
        GenerationStoreError::GenerationConflict {
            expected: 0,
            actual: 7
        }
        .to_string()
    );
    assert_eq!(fs::read(cache_path(&root.0)).expect("cache"), winner.bytes);
}

#[test]
fn a_failed_save_whose_record_then_vanished_reports_both_failures() {
    let root = TestRoot::new("save-then-vanish");
    let authority = Arc::new(MemoryAuthority::default());
    let generation_store = store(&root, authority.clone());
    generation_store.load().expect("initialize");
    authority.edit(|state| {
        state.fail_save = true;
        state.failed_save_loses_record = true;
    });
    assert_eq!(
        generation_store
            .reserve_next(0)
            .expect_err("save and recovery fail"),
        GenerationStoreError::AuthoritySaveAndRecoveryFailed {
            write_error: GenerationStoreError::AuthoritySave("injected save failure".into())
                .to_string(),
            recovery_error: GenerationStoreError::AuthorityInconsistent(
                "item disappeared while recovering a compare-and-swap".into()
            )
            .to_string(),
        }
        .to_string()
    );
}

#[test]
fn a_failed_save_whose_cache_repair_fails_reports_both_failures() {
    let root = TestRoot::new("save-then-cache");
    let authority = Arc::new(MemoryAuthority::default());
    let generation_store = store(&root, authority.clone());
    generation_store.load().expect("initialize");
    let cache = cache_path(&root.0);
    authority.edit(|state| {
        state.fail_save = true;
        state.failed_save_blocks_cache = Some(cache.clone());
    });
    let error = generation_store
        .reserve_next(0)
        .expect_err("save and cache repair fail");
    assert!(
        error.starts_with(
            "engine lineage Keychain save failed: engine lineage Keychain save failed: injected save failure; recovery failed: engine lineage I/O failed during replace-lineage-cache: "
        ),
        "{error}"
    );
    fs::remove_dir(&cache).expect("unblock the cache path");
}

#[test]
fn a_panic_inside_the_store_leaves_it_refusing_further_work() {
    let root = TestRoot::new("poisoned");
    let authority = Arc::new(MemoryAuthority::default());
    let generation_store = store(&root, authority.clone());
    authority.edit(|state| state.panic_on_load = true);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = generation_store.load();
    }));
    assert!(panicked.is_err());
    authority.edit(|state| state.panic_on_load = false);
    let error = generation_store
        .load()
        .expect_err("poisoned in-process lock");
    assert!(
        error.starts_with("engine lineage I/O failed during lock-in-process-lineage: "),
        "{error}"
    );
}

#[test]
fn a_lineage_document_must_be_bounded_current_and_complete() {
    let valid = LineageDocument::new();
    let mut other_schema = valid.clone();
    other_schema.schema_version = SCHEMA_VERSION + 1;
    let mut nil_installation = valid.clone();
    nil_installation.installation_id = Uuid::nil();
    let mut first_epoch = valid.clone();
    first_epoch.config_epoch = 0;
    let encoded = |document: &LineageDocument| serde_json::to_vec(document).expect("document");
    let cases = [
        (
            encoded(&other_schema),
            GenerationStoreError::UnsupportedSchema(SCHEMA_VERSION + 1).to_string(),
        ),
        (
            encoded(&nil_installation),
            GenerationStoreError::InvalidInstallationId(Uuid::nil().to_string()).to_string(),
        ),
        (
            encoded(&first_epoch),
            GenerationStoreError::InvalidEpoch.to_string(),
        ),
        (
            Vec::new(),
            GenerationStoreError::DocumentTooLarge(0).to_string(),
        ),
        (
            vec![b' '; MAX_LINEAGE_BYTES as usize + 1],
            GenerationStoreError::DocumentTooLarge(MAX_LINEAGE_BYTES + 1).to_string(),
        ),
    ];
    for (bytes, expected) in cases {
        let root = TestRoot::new("document-checks");
        let authority = Arc::new(MemoryAuthority::default());
        authority.replace_record(raw_record(&bytes));
        assert_eq!(
            store(&root, authority)
                .load()
                .expect_err("document refused"),
            expected
        );
    }
}

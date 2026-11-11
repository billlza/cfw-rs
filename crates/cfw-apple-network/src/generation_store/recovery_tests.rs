use super::*;

#[test]
fn lost_identity_rejoins_authority_above_its_epoch_and_survives_restart() {
    let root = TestRoot::new("recover-lost-identity");
    let authority = Arc::new(MemoryAuthority::default());
    let subject = store(&root, authority.clone());
    let baseline = subject.load().unwrap();
    let machine_id = Uuid::new_v4();
    let recovered = subject
        .recover_installation(&baseline, machine_id, 7)
        .unwrap();
    assert_eq!(recovered.session.installation_id, machine_id.to_string());
    assert_eq!(recovered.session.config_epoch, 8);
    assert_eq!(recovered.generation, 0);
    let restarted = store(&root, authority);
    assert_eq!(restarted.load().unwrap(), recovered);
    assert_eq!(restarted.reserve_next(0).unwrap(), 1);
}

#[test]
fn recovery_never_rolls_back_an_existing_local_epoch() {
    let root = TestRoot::new("recover-epoch");
    let authority = Arc::new(MemoryAuthority::default());
    let document = LineageDocument {
        config_epoch: 12,
        generation: u64::MAX,
        ..LineageDocument::new()
    };
    authority.replace_record(AuthorityRecord::from_document(&document).unwrap());
    let subject = store(&root, authority);
    let baseline = subject.load().unwrap();
    let recovered = subject
        .recover_installation(&baseline, document.installation_id, 9)
        .unwrap();
    assert_eq!(recovered.session.config_epoch, 13);
    assert_eq!(recovered.generation, 0);
}

#[test]
fn enrolled_but_never_started_identity_recovers_at_epoch_one() {
    let root = TestRoot::new("recover-genesis");
    let authority = Arc::new(MemoryAuthority::default());
    let subject = store(&root, authority);
    let baseline = subject.load().unwrap();
    assert_eq!(
        subject
            .recover_installation(&baseline, Uuid::new_v4(), 0)
            .unwrap()
            .session
            .config_epoch,
        1
    );
}

#[test]
fn invalid_or_exhausted_recovery_leaves_authority_unchanged() {
    for (id, floor) in [(Uuid::nil(), 0), (Uuid::new_v4(), u64::MAX)] {
        let root = TestRoot::new("recover-invalid");
        let authority = Arc::new(MemoryAuthority::default());
        let subject = store(&root, authority.clone());
        let baseline = subject.load().unwrap();
        let before = authority.record();
        assert!(subject.recover_installation(&baseline, id, floor).is_err());
        assert_eq!(authority.record(), before);
    }
}

#[test]
fn baseline_change_during_consent_cannot_replace_another_writer() {
    let root = TestRoot::new("recover-baseline");
    let authority = Arc::new(MemoryAuthority::default());
    let subject = store(&root, authority.clone());
    let baseline = subject.load().unwrap();
    subject.reserve_next(0).unwrap();
    let before = authority.record();
    assert!(matches!(
        subject.recover_installation(&baseline, Uuid::new_v4(), 1),
        Err(GenerationStoreError::RecoveryConflict)
    ));
    assert_eq!(authority.record(), before);
}

#[test]
fn concurrent_cas_is_a_conflict_even_when_the_other_writer_chose_the_same_identity() {
    let root = TestRoot::new("recover-cas-conflict");
    let authority = Arc::new(MemoryAuthority::default());
    let subject = store(&root, authority.clone());
    let baseline = subject.load().unwrap();
    let target = Uuid::new_v4();
    let competing = AuthorityRecord::from_document(&LineageDocument {
        schema_version: SCHEMA_VERSION,
        installation_id: target,
        config_epoch: 4,
        generation: 0,
    })
    .unwrap();
    authority.edit(|state| state.swapped_meanwhile = Some(competing.clone()));
    assert!(matches!(
        subject.recover_installation(&baseline, target, 3),
        Err(GenerationStoreError::RecoveryConflict)
    ));
    assert_eq!(fs::read(cache_path(&root.0)).unwrap(), competing.bytes);
}

#[test]
fn recovery_resolves_an_error_after_atomic_commit_only_by_exact_readback() {
    let root = TestRoot::new("recover-committed-error");
    let authority = Arc::new(MemoryAuthority::default());
    let subject = store(&root, authority.clone());
    let baseline = subject.load().unwrap();
    authority.set_commit_then_fail_save(true);
    let recovered = subject
        .recover_installation(&baseline, Uuid::new_v4(), 4)
        .unwrap();
    assert_eq!(subject.load().unwrap(), recovered);
}

#[test]
fn failed_recovery_repairs_cache_and_does_not_report_success() {
    let root = TestRoot::new("recover-failed-save");
    let authority = Arc::new(MemoryAuthority::default());
    let subject = store(&root, authority.clone());
    let baseline = subject.load().unwrap();
    let before = authority.record().unwrap();
    authority.set_fail_save(true);
    assert!(
        subject
            .recover_installation(&baseline, Uuid::new_v4(), 4)
            .is_err()
    );
    assert_eq!(authority.record().unwrap(), before);
    assert_eq!(fs::read(cache_path(&root.0)).unwrap(), before.bytes);
}

#[test]
fn missing_keychain_after_consent_is_not_silently_recreated() {
    let root = TestRoot::new("recover-disappeared");
    let authority = Arc::new(MemoryAuthority::default());
    let subject = store(&root, authority.clone());
    let baseline = subject.load().unwrap();
    authority.edit(|state| state.record = None);
    assert!(
        subject
            .recover_installation(&baseline, Uuid::new_v4(), 4)
            .is_err()
    );
    assert_eq!(authority.record(), None);
}

#[test]
fn a_crash_before_cas_leaves_only_a_cache_that_restart_repairs() {
    let root = TestRoot::new("recover-cache-only");
    let authority = Arc::new(MemoryAuthority::default());
    let subject = store(&root, authority.clone());
    let baseline = subject.load().unwrap();
    let ahead = AuthorityRecord::from_document(&LineageDocument {
        config_epoch: 15,
        ..LineageDocument::new()
    })
    .unwrap();
    subject.synchronize_cache(&ahead).unwrap();
    assert_eq!(store(&root, authority.clone()).load().unwrap(), baseline);
    assert_eq!(
        fs::read(cache_path(&root.0)).unwrap(),
        authority.record().unwrap().bytes
    );
}

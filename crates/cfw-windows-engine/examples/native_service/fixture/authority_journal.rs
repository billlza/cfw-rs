//! Native SYSTEM journal validation, isolated to disposable VM fixture roots.
use super::*;
use cfw_engine_api::authority_v1::{AuthorityMode, AuthorityState, RootContext};
use cfw_windows_engine::authority_journal::*;
use cfw_windows_storage::{PrivateDirectory, PrivateMachineRecord};
use std::io::Write;

pub(super) fn request(name: &str, image: &Path, digest: [u8; 32], command: &[u8]) -> Result<()> {
    let mut channel =
        ServiceChannel::connect(name, ServiceClientRole::Desktop, verified(image, digest)?)
            .map_err(|e| e.to_string())?;
    if channel
        .request(command, Instant::now() + Duration::from_secs(45))
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"journal-ok"
    {
        return Err("journal fixture response mismatch".into());
    }
    Ok(())
}
pub(super) fn root() -> Result<PathBuf> {
    std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .map(Path::to_owned)
        .ok_or_else(|| "missing journal fixture root".into())
}
fn shared(name: &str) -> Result<(PathBuf, String)> {
    let prefix = name
        .strip_suffix("-a")
        .or_else(|| name.strip_suffix("-b"))
        .ok_or("invalid journal fixture service")?;
    Ok((
        root()?.join("shared-authority-journal"),
        format!("{prefix}-journal"),
    ))
}
pub(super) fn cleanup(path: &Path, scope: &str) -> Result<()> {
    let record = PrivateMachineRecord::new(scope).map_err(|e| e.to_string())?;
    let guard = record.lock(LIMIT).map_err(|e| e.to_string())?;
    if let Some(bytes) = guard.read().map_err(|e| e.to_string())? {
        guard.remove(&bytes).map_err(|e| e.to_string())?;
    }
    guard.release().map_err(|e| e.to_string())?;
    if path.try_exists().map_err(|e| e.to_string())? {
        std::fs::remove_dir_all(path).map_err(|e| e.to_string())?;
    }
    if path.try_exists().map_err(|e| e.to_string())? {
        return Err("fixture journal directory remained after cleanup".into());
    }
    Ok(())
}
pub(super) fn cleanup_shared(name: &str) -> Result<()> {
    let (path, scope) = shared(name)?;
    cleanup(&path, &scope)
}

fn with_case(
    action: impl FnOnce(&WindowsAuthorityJournal, &Path, &str) -> Result<()>,
) -> Result<()> {
    let scope = format!("CFW-journal-{}", uuid::Uuid::new_v4());
    let path = root()?.join(&scope);
    let store =
        WindowsAuthorityJournal::open_with_record_capacity_for_validation(&path, &scope, 10)
            .map_err(|e| e.to_string())?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        action(&store, &path, &scope)
    }));
    drop(store);
    let operation = match result {
        Ok(value) => value,
        Err(value) => Err(value
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| value.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_else(|| "journal native assertion panicked".into())),
    };
    let removal = cleanup(&path, &scope);
    match (operation, removal) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Err(e), Err(cleanup)) => Err(format!("{e}; fixture cleanup: {cleanup}")),
    }
}
fn enroll(store: &WindowsAuthorityJournal) -> Result<AuthorityCommittedState> {
    let state = AuthorityCommittedState::enrollment(uuid::Uuid::new_v4());
    store.append(&state).map_err(|e| e.to_string())?;
    Ok(state)
}
fn reserve(
    store: &WindowsAuthorityJournal,
    previous: &AuthorityCommittedState,
) -> Result<AuthorityCommittedState> {
    let next = previous
        .reserve_next_generation()
        .map_err(|e| e.to_string())?;
    store.append(&next).map_err(|e| e.to_string())?;
    Ok(next)
}
fn prepare(
    genesis: &AuthorityCommittedState,
    owner: &NativeUserSession,
    generation: u64,
    revision: u64,
) -> Result<AuthorityCommittedState> {
    let claim = RecordedOwner::from_native(owner).map_err(|e| e.to_string())?;
    assert!(claim.matches_native(owner));
    let operation = JournalOperation::new(
        uuid::Uuid::new_v4(),
        AuthorityMode::SystemProxy,
        [7; 32],
        [8; 32],
        uuid::Uuid::new_v4(),
        claim,
    )
    .map_err(|e| e.to_string())?;
    AuthorityCommittedState::new(
        RootContext {
            installation_id: genesis.root().installation_id,
            epoch: 1,
            generation,
        },
        revision,
        JournalTransition::Prepare,
        AuthorityState::Preparing,
        Some(operation),
    )
    .map_err(|e| e.to_string())
}
fn transition(
    store: &WindowsAuthorityJournal,
    prior: &AuthorityCommittedState,
    transition: JournalTransition,
    state: AuthorityState,
) -> Result<AuthorityCommittedState> {
    let value = AuthorityCommittedState::new(
        prior.root().clone(),
        prior.revision() + 1,
        transition,
        state,
        if state == AuthorityState::Off {
            None
        } else {
            prior.operation().cloned()
        },
    )
    .map_err(|e| e.to_string())?;
    store.append(&value).map_err(|e| e.to_string())?;
    Ok(value)
}
fn cycle(
    store: &WindowsAuthorityJournal,
    owner: &NativeUserSession,
) -> Result<AuthorityCommittedState> {
    let genesis = enroll(store)?;
    let allocated = reserve(store, &genesis)?;
    let value = prepare(&allocated, owner, 1, 3)?;
    store.append(&value).map_err(|e| e.to_string())?;
    let value = transition(
        store,
        &value,
        JournalTransition::BindOwner,
        AuthorityState::Starting,
    )?;
    let value = transition(
        store,
        &value,
        JournalTransition::Ready,
        AuthorityState::Active,
    )?;
    let recovered = store.recover().map_err(|e| e.to_string())?;
    assert_eq!(recovered.action, RecoveryAction::ReattestOwner);
    assert!(
        recovered
            .committed
            .unwrap()
            .operation()
            .unwrap()
            .owner()
            .matches_native(owner)
    );
    let value = transition(
        store,
        &value,
        JournalTransition::BeginStop,
        AuthorityState::Stopping,
    )?;
    let value = transition(
        store,
        &value,
        JournalTransition::OwnerStopped,
        AuthorityState::Stopping,
    )?;
    transition(
        store,
        &value,
        JournalTransition::GlobalOff,
        AuthorityState::Off,
    )
}
fn bytes(path: &Path, name: &str) -> Result<Vec<u8>> {
    std::fs::read(path.join(name)).map_err(|e| e.to_string())
}
fn replace(path: &Path, name: &str, data: &[u8]) -> Result<()> {
    let directory = PrivateDirectory::open_existing(path)
        .map_err(|e| e.to_string())?
        .ok_or("missing fixture journal directory")?;
    let mut tx = directory.write().map_err(|e| e.to_string())?;
    tx.replace(name, data, MAX_JOURNAL_BYTES)
        .map_err(|e| e.to_string())
}
fn make_temporary(path: &Path, name: &str, data: &[u8]) -> Result<()> {
    // Use production private-file creation so the SYSTEM owner/DACL is exact,
    // then move only this synthetic staging file to the interrupted-write name.
    replace(path, "fixture-staging", data)?;
    std::fs::rename(path.join("fixture-staging"), path.join(name)).map_err(|e| e.to_string())
}
fn anchor(scope: &str) -> Result<JournalAnchor> {
    let record = PrivateMachineRecord::new(scope).map_err(|e| e.to_string())?;
    let guard = record.lock(LIMIT).map_err(|e| e.to_string())?;
    let bytes = guard
        .read()
        .map_err(|e| e.to_string())?
        .ok_or("missing fixture anchor")?;
    let anchor = JournalAnchor::decode(&bytes).map_err(|e| e.to_string())?;
    guard.release().map_err(|e| e.to_string())?;
    Ok(anchor)
}
fn interrupted(
    store: &WindowsAuthorityJournal,
    state: &AuthorityCommittedState,
    point: JournalFaultPoint,
) -> Result<()> {
    if !matches!(
        store.append_interrupted_for_validation(state, point),
        Err(JournalStoreError::InjectedFault)
    ) {
        return Err(format!("journal did not stop at {point:?}"));
    }
    Ok(())
}

pub(super) fn exercise(name: &str, command: &[u8], owner: &NativeUserSession) -> Result<()> {
    let (path, scope) = shared(name)?;
    match command {
        b"authority-journal" if name.ends_with("-a") => {
            existing_authority_admission()?;
            recorded_off_observation(owner)?;
            enrollment_faults()?;
            allocation_faults()?;
            allocation_checkpoint()?;
            prepare_faults(owner)?;
            compaction_faults(owner)?;
            temporary_recovery(owner)?;
            rollback_and_missing_identity(owner)?;
            let store = WindowsAuthorityJournal::open(&path, &scope).map_err(|e| e.to_string())?;
            let genesis = enroll(&store)?;
            let allocated = reserve(&store, &genesis)?;
            let prepared = prepare(&allocated, owner, 1, 3)?;
            store.append(&prepared).map_err(|e| e.to_string())?;
            let starting = transition(
                &store,
                &prepared,
                JournalTransition::BindOwner,
                AuthorityState::Starting,
            )?;
            transition(
                &store,
                &starting,
                JournalTransition::Ready,
                AuthorityState::Active,
            )?;
            write_report("a", &first_report())
        }
        b"authority-journal-observe" if name.ends_with("-b") => {
            let store =
                WindowsAuthorityJournal::open_existing(&path, &scope).map_err(|e| e.to_string())?;
            let recovered = store.recover().map_err(|e| e.to_string())?;
            assert_eq!(recovered.action, RecoveryAction::ReattestOwner);
            let state = recovered
                .committed
                .ok_or("missing cross-process journal state")?;
            assert_eq!(state.state(), AuthorityState::Active);
            assert_eq!(state.revision(), 5);
            assert!(state.operation().unwrap().owner().matches_native(owner));
            assert_eq!(state.operation().unwrap().config_sha256(), &[7; 32]);
            assert_eq!(state.operation().unwrap().identity_sha256(), &[8; 32]);
            write_report("b", &second_report())
        }
        _ => Err("unexpected journal fixture command".into()),
    }
}

fn existing_authority_admission() -> Result<()> {
    use cfw_windows_engine::authority::{AuthorityError, WindowsAuthority};
    with_case(|store, path, scope| {
        let missing = path.join("uncreated-journal");
        assert!(matches!(
            WindowsAuthority::reopen(&missing, scope),
            Err(AuthorityError::Journal(JournalStoreError::StoreIdentity))
        ));
        assert!(!missing.try_exists().map_err(|e| e.to_string())?);
        assert!(matches!(
            WindowsAuthority::reopen(path, scope),
            Err(AuthorityError::Journal(JournalStoreError::StoreIdentity))
        ));
        assert!(
            store
                .recover()
                .map_err(|e| e.to_string())?
                .committed
                .is_none()
        );
        let anchor = PrivateMachineRecord::new(scope).map_err(|e| e.to_string())?;
        let guard = anchor.lock(LIMIT).map_err(|e| e.to_string())?;
        assert!(guard.read().map_err(|e| e.to_string())?.is_none());
        guard.release().map_err(|e| e.to_string())?;

        let prior = enroll(store)?;
        let mut reopened = WindowsAuthority::reopen(path, scope).map_err(|e| e.to_string())?;
        assert_eq!(reopened.snapshot().state, AuthorityState::Recovering);
        assert_eq!(reopened.recovery_target(), Some(&prior));
        assert!(reopened.lease_owner().is_none());
        let admission = reopened.verify_recorded_off().map_err(|e| e.to_string())?;
        assert_eq!(admission.prior(), &prior);
        assert_eq!(admission.snapshot().revision, Some(prior.revision()));
        assert_eq!(admission.snapshot().state, AuthorityState::Off);
        assert_eq!(
            store.recover().map_err(|e| e.to_string())?.committed,
            Some(prior)
        );
        Ok(())
    })?;
    for point in [
        JournalFaultPoint::AnchorCreated,
        JournalFaultPoint::MarkerPublished,
        JournalFaultPoint::PendingAnchorPublished,
    ] {
        with_case(|store, path, scope| {
            let prior = AuthorityCommittedState::enrollment(uuid::Uuid::new_v4());
            interrupted(store, &prior, point)?;
            assert!(matches!(
                WindowsAuthority::reopen(path, scope),
                Err(AuthorityError::Journal(JournalStoreError::StoreIdentity))
            ));
            // Recovery of the interrupted publication may repair its anchor,
            // but cannot choose a new installation or commit an Off record.
            assert!(
                store
                    .recover()
                    .map_err(|e| e.to_string())?
                    .committed
                    .is_none()
            );
            Ok(())
        })?;
    }
    Ok(())
}

fn recorded_off_observation(owner: &NativeUserSession) -> Result<()> {
    use cfw_windows_engine::authority::WindowsAuthority;
    with_case(|store, path, scope| {
        let prior = cycle(store, owner)?;
        assert!(prior.root().epoch > 0);
        let mut controller = WindowsAuthority::reopen(path, scope).map_err(|e| e.to_string())?;
        for _ in 0..2 {
            let observed = controller
                .observe_recorded_off()
                .map_err(|e| e.to_string())?;
            assert_eq!(observed.record(), &prior);
            assert!(observed.processes().processes_retired());
            assert_eq!(controller.snapshot().state, AuthorityState::Recovering);
            assert!(controller.lease_owner().is_none());
            assert_eq!(
                store.recover().map_err(|e| e.to_string())?.committed,
                Some(prior.clone())
            );
        }
        // Startup admission is intentionally different: a previously used
        // runtime root publishes a new reconciliation revision.
        let admitted = controller
            .verify_recorded_off()
            .map_err(|e| e.to_string())?;
        assert_eq!(admitted.snapshot().revision, Some(prior.revision() + 1));
        assert_eq!(admitted.snapshot().state, AuthorityState::Off);
        Ok(())
    })
}

fn enrollment_faults() -> Result<()> {
    for point in [
        JournalFaultPoint::AnchorCreated,
        JournalFaultPoint::MarkerPublished,
        JournalFaultPoint::PendingAnchorPublished,
        JournalFaultPoint::JournalPublished,
        JournalFaultPoint::HeadPublished,
        JournalFaultPoint::CommittedAnchorPublished,
    ] {
        with_case(|store, _, _| {
            let genesis = AuthorityCommittedState::enrollment(uuid::Uuid::new_v4());
            interrupted(store, &genesis, point)?;
            let recovered = store.recover().map_err(|e| e.to_string())?;
            assert_eq!(recovered.action, RecoveryAction::VerifyOff);
            if matches!(
                point,
                JournalFaultPoint::AnchorCreated
                    | JournalFaultPoint::MarkerPublished
                    | JournalFaultPoint::PendingAnchorPublished
            ) {
                assert!(recovered.committed.is_none());
                store.append(&genesis).map_err(|e| e.to_string())?;
            } else {
                assert_eq!(recovered.committed, Some(genesis));
            }
            Ok(())
        })?;
    }
    Ok(())
}
fn allocation_faults() -> Result<()> {
    for point in [
        JournalFaultPoint::PendingAnchorPublished,
        JournalFaultPoint::JournalPublished,
        JournalFaultPoint::HeadPublished,
        JournalFaultPoint::CommittedAnchorPublished,
    ] {
        with_case(|store, _, _| {
            let initial = enroll(store)?;
            let allocated = initial
                .reserve_next_generation()
                .map_err(|e| e.to_string())?;
            interrupted(store, &allocated, point)?;
            let recovered = store.recover().map_err(|e| e.to_string())?;
            assert_eq!(recovered.action, RecoveryAction::VerifyOff);
            if point == JournalFaultPoint::PendingAnchorPublished {
                assert_eq!(recovered.committed, Some(initial));
                store.append(&allocated).map_err(|e| e.to_string())?;
            } else {
                assert_eq!(recovered.committed, Some(allocated.clone()));
                assert!(store.append(&allocated).is_err());
            }
            assert_eq!(
                store
                    .recover()
                    .map_err(|e| e.to_string())?
                    .committed
                    .unwrap()
                    .allocated_generation(),
                1
            );
            Ok(())
        })?;
    }
    Ok(())
}
fn allocation_checkpoint() -> Result<()> {
    with_case(|store, path, scope| {
        let mut allocated = enroll(store)?;
        let installation = allocated.root().installation_id;
        for generation in 1..=6 {
            allocated = reserve(store, &allocated)?;
            assert_eq!(allocated.allocated_generation(), generation);
            assert_eq!(allocated.root().generation, 0);
            assert!(allocated.operation().is_none());
        }
        let recovered = store.recover().map_err(|e| e.to_string())?;
        assert!(recovered.cursor.as_ref().unwrap().generation() > 1);
        assert_eq!(recovered.committed.as_ref(), Some(&allocated));
        assert_eq!(recovered.action, RecoveryAction::VerifyOff);
        // A second native store must read the same unused allocation from the
        // compacted file/registry transaction, without inventing a runtime root.
        let reopened = WindowsAuthorityJournal::open(path, scope).map_err(|e| e.to_string())?;
        let state = reopened
            .recover()
            .map_err(|e| e.to_string())?
            .committed
            .ok_or("compacted allocation missing")?;
        assert_eq!(state.root().installation_id, installation);
        assert_eq!(state.root().generation, 0);
        assert_eq!(state.allocated_generation(), 6);
        let next = reserve(&reopened, &state)?;
        assert_eq!(next.allocated_generation(), 7);
        assert_eq!(next.state(), AuthorityState::Off);
        assert!(next.operation().is_none());
        Ok(())
    })
}
fn prepare_faults(owner: &NativeUserSession) -> Result<()> {
    for point in [
        JournalFaultPoint::PendingAnchorPublished,
        JournalFaultPoint::JournalPublished,
        JournalFaultPoint::HeadPublished,
        JournalFaultPoint::CommittedAnchorPublished,
    ] {
        with_case(|store, _, _| {
            let genesis = enroll(store)?;
            let allocated = reserve(store, &genesis)?;
            let prepared = prepare(&allocated, owner, 1, 3)?;
            interrupted(store, &prepared, point)?;
            let recovered = store.recover().map_err(|e| e.to_string())?;
            if point == JournalFaultPoint::PendingAnchorPublished {
                assert_eq!(recovered.committed, Some(allocated));
                assert_eq!(recovered.action, RecoveryAction::VerifyOff);
                store.append(&prepared).map_err(|e| e.to_string())?;
            } else {
                assert_eq!(recovered.committed, Some(prepared.clone()));
                assert_eq!(recovered.action, RecoveryAction::StopOwner);
                assert!(store.append(&prepared).is_err());
            }
            Ok(())
        })?;
    }
    Ok(())
}
fn compaction_faults(owner: &NativeUserSession) -> Result<()> {
    for point in [
        JournalFaultPoint::PendingAnchorPublished,
        JournalFaultPoint::JournalPublished,
        JournalFaultPoint::HeadPublished,
        JournalFaultPoint::CommittedAnchorPublished,
        JournalFaultPoint::OldGenerationRemoved,
    ] {
        with_case(|store, path, _| {
            let off = cycle(store, owner)?;
            assert_eq!(off.revision(), 8);
            let allocated = off.reserve_next_generation().map_err(|e| e.to_string())?;
            interrupted(store, &allocated, point)?;
            let recovered = store.recover().map_err(|e| e.to_string())?;
            assert_eq!(recovered.action, RecoveryAction::VerifyOff);
            assert_eq!(recovered.committed.unwrap().revision(), 8);
            let cursor = store.append(&allocated).map_err(|e| e.to_string())?;
            assert_eq!(cursor.generation(), 2);
            assert_eq!(cursor.sequence(), 2);
            assert_eq!(cursor.state_revision(), 9);
            assert_eq!(
                store
                    .recover()
                    .map_err(|e| e.to_string())?
                    .committed
                    .unwrap()
                    .allocated_generation(),
                2
            );
            let prepared = prepare(&allocated, owner, 2, 10)?;
            let cursor = store.append(&prepared).map_err(|e| e.to_string())?;
            assert_eq!(
                (
                    cursor.generation(),
                    cursor.sequence(),
                    cursor.state_revision()
                ),
                (2, 3, 10)
            );
            assert!(
                !path
                    .join("journal-1.bin")
                    .try_exists()
                    .map_err(|e| e.to_string())?
            );
            assert!(
                !path
                    .join("head-1.json")
                    .try_exists()
                    .map_err(|e| e.to_string())?
            );
            Ok(())
        })?;
    }
    Ok(())
}

fn temporary_recovery(owner: &NativeUserSession) -> Result<()> {
    for (head, valid) in [(false, true), (true, true), (false, false), (true, false)] {
        with_case(|store, path, scope| {
            let genesis = enroll(store)?;
            let allocated = reserve(store, &genesis)?;
            let prepared = prepare(&allocated, owner, 1, 3)?;
            let old_head = bytes(path, "head-1.json")?;
            interrupted(
                store,
                &prepared,
                if head {
                    JournalFaultPoint::JournalPublished
                } else {
                    JournalFaultPoint::PendingAnchorPublished
                },
            )?;
            let pending = anchor(scope)?
                .pending()
                .cloned()
                .ok_or("missing pending fixture cursor")?;
            let name = if head {
                ".head-1.json.tmp"
            } else {
                ".journal-1.bin.tmp"
            };
            let data = if head {
                if valid {
                    pending.encode().map_err(|e| e.to_string())?
                } else {
                    old_head
                }
            } else {
                let mut journal = bytes(path, "journal-1.bin")?;
                let prior = decode_journal(&journal)
                    .map_err(|e| e.to_string())?
                    .cursor(1)
                    .map_err(|e| e.to_string())?;
                journal.extend(
                    encode_record(&prepared, prior.sequence() + 1, *prior.record_sha256())
                        .map_err(|e| e.to_string())?
                        .bytes,
                );
                if !valid {
                    journal.truncate(journal.len() - 1);
                }
                journal
            };
            make_temporary(path, name, &data)?;
            if valid {
                let recovered = store.recover().map_err(|e| e.to_string())?;
                assert_eq!(recovered.committed, Some(prepared));
                assert_eq!(recovered.action, RecoveryAction::StopOwner);
                assert_eq!(store.recover().map_err(|e| e.to_string())?, recovered);
                assert!(!path.join(name).try_exists().map_err(|e| e.to_string())?);
            } else {
                assert!(store.recover().is_err());
                assert_eq!(bytes(path, name)?, data);
                assert!(anchor(scope)?.pending().is_some());
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn rollback_and_missing_identity(owner: &NativeUserSession) -> Result<()> {
    with_case(|store, path, _| {
        let genesis = enroll(store)?;
        let old_journal = bytes(path, "journal-1.bin")?;
        let old_head = bytes(path, "head-1.json")?;
        let allocated = reserve(store, &genesis)?;
        let prepared = prepare(&allocated, owner, 1, 3)?;
        store.append(&prepared).map_err(|e| e.to_string())?;
        replace(path, "journal-1.bin", &old_journal)?;
        replace(path, "head-1.json", &old_head)?;
        assert!(store.recover().is_err());
        assert_eq!(bytes(path, "journal-1.bin")?, old_journal);
        Ok(())
    })?;
    for remove_anchor in [false, true] {
        with_case(|store, path, scope| {
            enroll(store)?;
            if remove_anchor {
                let record = PrivateMachineRecord::new(scope).map_err(|e| e.to_string())?;
                let guard = record.lock(LIMIT).map_err(|e| e.to_string())?;
                let before = guard
                    .read()
                    .map_err(|e| e.to_string())?
                    .ok_or("missing anchor before deletion test")?;
                guard.remove(&before).map_err(|e| e.to_string())?;
                guard.release().map_err(|e| e.to_string())?;
            } else {
                std::fs::remove_file(path.join("authority-store-v1")).map_err(|e| e.to_string())?;
            }
            assert!(store.recover().is_err());
            Ok(())
        })?;
    }
    with_case(|store, path, _| {
        enroll(store)?;
        let data = bytes(path, "journal-1.bin")?;
        replace(path, "journal-2.bin", &data)?;
        assert!(store.recover().is_err());
        assert_eq!(bytes(path, "journal-2.bin")?, data);
        Ok(())
    })
}
fn first_report() -> serde_json::Value {
    serde_json::json!({"success":true,"fault_runs":19,"existing_authority_admission_cases":6,"missing_authority_not_enrolled":true,"off_observation_does_not_publish":true,"allocation_fault_cases":4,"allocation_checkpoint_cases":1,"unused_allocations_survive_checkpoint":true,"temporary_cases":4,"identity_and_rollback_cases":4,"whole_sid_logon_session_retained":true,"off_requires_verification":true,"active_requires_reattestation":true,"checkpoint_recovery_and_cleanup":true,"full_authority_state_machine_proven":false,"power_loss_tested":false})
}
fn second_report() -> serde_json::Value {
    serde_json::json!({"success":true,"writer_process_exited":true,"revision":5,"allocated_generation":1,"state":"active","recovery_action":"reattest_owner","owner_matches_native_console":true,"configuration_identity_preserved":true,"executable_lease_restored":false})
}
fn write_report(role: &str, value: &serde_json::Value) -> Result<()> {
    let path = root()?.join(format!("authority-{role}.journal-validation.json"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}
pub(super) fn require_reports(path: &Path) -> Result<()> {
    for (role, expected) in [("a", first_report()), ("b", second_report())] {
        let value: serde_json::Value = serde_json::from_slice(&bytes(
            path,
            &format!("authority-{role}.journal-validation.json"),
        )?)
        .map_err(|e| e.to_string())?;
        if value != expected {
            return Err("journal validation report differs from actual fixture contract".into());
        }
    }
    Ok(())
}

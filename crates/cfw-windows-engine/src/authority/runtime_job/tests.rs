use super::*;
use crate::RunMode;

fn root() -> RootContext {
    RootContext {
        installation_id: uuid::Uuid::new_v4(),
        epoch: 1,
        generation: 7,
    }
}

#[test]
fn runtime_job_names_bind_full_durable_lineage() {
    let root = root();
    let name = job_name(&root).unwrap();
    assert!(name.starts_with("Global\\CFW.Runtime.v1."));
    assert!(name.len() < 128);
    for other in [
        RootContext {
            generation: 8,
            ..root.clone()
        },
        RootContext {
            epoch: 2,
            ..root.clone()
        },
        RootContext {
            installation_id: uuid::Uuid::new_v4(),
            ..root.clone()
        },
    ] {
        assert_ne!(name, job_name(&other).unwrap());
    }
    for invalid in [
        RootContext {
            generation: 0,
            ..root.clone()
        },
        RootContext {
            epoch: 0,
            ..root.clone()
        },
        RootContext {
            installation_id: uuid::Uuid::nil(),
            ..root.clone()
        },
    ] {
        assert!(matches!(
            job_name(&invalid),
            Err(RuntimeJobError::InvalidRoot)
        ));
    }
}

#[test]
fn ordinary_user_cannot_assign_or_observe_service_runtime_jobs() {
    let own = NativePeerProcess::open(std::process::id()).unwrap();
    assert!(
        !own.identity().is_local_system(),
        "test requires an ordinary CI user"
    );
    assert!(matches!(
        RuntimeJob::assign(&root(), &own),
        Err(RuntimeJobError::Service(_))
    ));
    assert!(matches!(observe(&root()), Err(RuntimeJobError::Service(_))));
    let mut enrollment = root();
    enrollment.epoch = 0;
    enrollment.generation = 0;
    assert!(matches!(
        observe(&enrollment),
        Err(RuntimeJobError::Service(_))
    ));
}

#[test]
fn a_missing_job_retires_an_admitted_run_only_when_its_logon_has_ended() {
    use crate::authority_journal::{
        AuthorityCommittedState, JournalOperation, JournalTransition, RecordedOwner,
    };
    use crate::peer::RecordedLogon;
    use cfw_engine_api::authority_v1::AuthorityState;
    type Logon = std::result::Result<RecordedLogon, PeerIdentityError>;
    fn never_asked(_: &RecordedOwner) -> Logon {
        panic!("a record that admitted no run has no logon to ask about")
    }
    let owner: RecordedOwner = serde_json::from_value(serde_json::json!({
        "sid":[1,1,0,0,0,0,0,5,21,0,0,0], "authentication_id":1, "session_id":1
    }))
    .unwrap();
    let operation = JournalOperation::new(
        uuid::Uuid::new_v4(),
        RunMode::SystemProxy,
        [1; 32],
        [2; 32],
        uuid::Uuid::new_v4(),
        owner.clone(),
    )
    .unwrap();
    let record = |state| {
        AuthorityCommittedState::new(
            root(),
            3,
            JournalTransition::Checkpoint,
            state,
            Some(operation.clone()),
        )
        .unwrap()
    };
    for state in [
        AuthorityState::Starting,
        AuthorityState::Active,
        AuthorityState::Stopping,
        AuthorityState::Quarantined,
    ] {
        let record = record(state);
        // Its logon still exists: a missing name is not a count of zero.
        assert!(
            matches!(
                RuntimeProcessObservation::unexecutable_record_with(&record, |asked| {
                    assert_eq!(asked, &owner);
                    Ok(RecordedLogon::Present)
                }),
                Err(RuntimeJobError::Unavailable)
            ),
            "{state:?}"
        );
        // The observation failed: that is unknown, not ended.
        assert!(
            matches!(
                RuntimeProcessObservation::unexecutable_record_with(&record, |_| Err(
                    PeerIdentityError::InvalidIdentity
                )),
                Err(RuntimeJobError::Peer(_))
            ),
            "{state:?}"
        );
        // Its logon has ended: no process of the run is left.
        let observation = RuntimeProcessObservation::unexecutable_record_with(&record, |_| {
            Ok(RecordedLogon::Ended)
        })
        .unwrap();
        assert_eq!(observation.state(), RuntimeProcessState::OwnerLogonEnded);
        assert_eq!(observation.root(), record.root());
        assert!(observation.processes_retired(), "{state:?}");
        assert_eq!(
            observation.run_retirement(record.root()),
            Some(ProcessRetirement::LogonEnded)
        );
        // It says nothing about a run under another root.
        assert_eq!(observation.run_retirement(&root()), None);
    }
    // A recorded Recovering state names no run this rule covers.
    assert!(matches!(
        RuntimeProcessObservation::unexecutable_record_with(
            &record(AuthorityState::Recovering),
            never_asked
        ),
        Err(RuntimeJobError::Unavailable)
    ));
    let preparing = AuthorityCommittedState::new(
        root(),
        2,
        JournalTransition::Prepare,
        AuthorityState::Preparing,
        Some(operation.clone()),
    )
    .unwrap();
    let observation =
        RuntimeProcessObservation::unexecutable_record_with(&preparing, never_asked).unwrap();
    assert_eq!(observation.state(), RuntimeProcessState::NeverAuthorized);
    assert!(
        !observation.processes_retired(),
        "no grant is not proof of Agent exit"
    );
    assert_eq!(observation.run_retirement(preparing.root()), None);
    let off = AuthorityCommittedState::new(
        root(),
        4,
        JournalTransition::GlobalOff,
        AuthorityState::Off,
        None,
    )
    .unwrap();
    let observation =
        RuntimeProcessObservation::unexecutable_record_with(&off, never_asked).unwrap();
    assert_eq!(observation.state(), RuntimeProcessState::DurablyRetired);
    assert_eq!(observation.root(), off.root());
    assert!(observation.processes_retired());
    // A record that is Off names no run that still needs this proof.
    assert_eq!(observation.run_retirement(off.root()), None);
}

#[test]
fn only_an_empty_job_that_admitted_a_process_counts_as_a_retired_run() {
    let root = root();
    let observed = |state| RuntimeProcessObservation {
        root: root.clone(),
        state,
    };
    let emptied = RuntimeProcessState::Accounting {
        active: 0,
        total: 3,
    };
    assert_eq!(
        observed(emptied).run_retirement(&root),
        Some(ProcessRetirement::Counted { total: 3 })
    );
    for state in [
        RuntimeProcessState::Accounting {
            active: 0,
            total: 0,
        },
        RuntimeProcessState::Accounting {
            active: 1,
            total: 3,
        },
        RuntimeProcessState::NoRuntimeRoot,
        RuntimeProcessState::DurablyRetired,
        RuntimeProcessState::NeverAuthorized,
    ] {
        assert_eq!(observed(state).run_retirement(&root), None, "{state:?}");
    }
    let other = RootContext {
        generation: root.generation + 1,
        ..root.clone()
    };
    assert_eq!(observed(emptied).run_retirement(&other), None);
}

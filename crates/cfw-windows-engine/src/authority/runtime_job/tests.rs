use super::*;

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
fn missing_job_cannot_retire_a_previously_authorized_runtime() {
    use crate::authority_journal::{
        AuthorityCommittedState, JournalOperation, JournalTransition, RecordedOwner,
    };
    use cfw_engine_api::authority_v1::{AuthorityMode, AuthorityState};
    let owner: RecordedOwner = serde_json::from_value(serde_json::json!({
        "sid":[1,1,0,0,0,0,0,5,21,0,0,0], "authentication_id":1, "session_id":1
    }))
    .unwrap();
    let operation = JournalOperation::new(
        uuid::Uuid::new_v4(),
        AuthorityMode::SystemProxy,
        [1; 32],
        [2; 32],
        uuid::Uuid::new_v4(),
        owner,
    )
    .unwrap();
    for state in [
        AuthorityState::Starting,
        AuthorityState::Active,
        AuthorityState::Stopping,
        AuthorityState::Quarantined,
        AuthorityState::Recovering,
    ] {
        let record = AuthorityCommittedState::new(
            root(),
            3,
            JournalTransition::Checkpoint,
            state,
            Some(operation.clone()),
        )
        .unwrap();
        assert!(
            matches!(
                RuntimeProcessObservation::unexecutable_record(&record),
                Err(RuntimeJobError::Unavailable)
            ),
            "{state:?}"
        );
    }
    let preparing = AuthorityCommittedState::new(
        root(),
        2,
        JournalTransition::Prepare,
        AuthorityState::Preparing,
        Some(operation),
    )
    .unwrap();
    let observation = RuntimeProcessObservation::unexecutable_record(&preparing).unwrap();
    assert_eq!(observation.state(), RuntimeProcessState::NeverAuthorized);
    assert!(
        !observation.processes_retired(),
        "no grant is not proof of Agent exit"
    );
    let off = AuthorityCommittedState::new(
        root(),
        4,
        JournalTransition::GlobalOff,
        AuthorityState::Off,
        None,
    )
    .unwrap();
    let observation = RuntimeProcessObservation::unexecutable_record(&off).unwrap();
    assert_eq!(observation.state(), RuntimeProcessState::DurablyRetired);
    assert_eq!(observation.root(), off.root());
    assert!(observation.processes_retired());
}

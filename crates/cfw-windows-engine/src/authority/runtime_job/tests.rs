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

use super::*;

#[test]
fn every_shutdown_path_uses_the_admitted_completion_boundary() {
    let source = include_str!("../lifecycle.rs")
        .split("#[cfg(test)]")
        .next()
        .expect("production lifecycle source");
    assert_eq!(source.matches("shutdown_to_completion().await").count(), 2);
    assert!(!source.contains("coordinator.shutdown().await"));
    // A shutdown error with the engine already Off ends the process on
    // every path; only an engine that is not Off keeps it running.
    assert_eq!(
        source
            .matches("coordinator.snapshot().state == cfw_engine_api::EngineState::Off")
            .count(),
        3
    );
    let owned = source
        .split("async fn prepare_owned_exit(")
        .nth(1)
        .expect("owned exit")
        .split("\n}\n")
        .next()
        .expect("owned exit body");
    let (before, after) = owned
        .split_once("if !safely_off {")
        .expect("the owned exit decides by the engine state");
    assert!(before.contains("Err(error) =>"));
    assert!(after.contains("return Err(OwnedExitError::Shutdown(error));"));
    assert!(after.contains("Some(error)"));
    assert!(after.contains(".mark_exit_ready(owner, maintenance)"));
    let quit = source
        .split("pub(crate) fn quit_app")
        .nth(1)
        .expect("quit command")
        .split('}')
        .next()
        .expect("quit command body");
    assert!(quit.contains("request_shutdown(app, 0)"));
    assert!(!quit.contains(".await"));
}

#[test]
#[cfg(target_os = "macos")]
fn handoff_failure_is_queryable_and_retry_replaces_it_with_in_progress() {
    let lifecycle = AppLifecycle::default();
    let mut lease = lifecycle.begin_handoff_lease().expect("handoff admission");
    assert_eq!(
        lifecycle.migration_handoff_status().expect("status"),
        MigrationHandoffStatus::InProgress
    );
    assert!(lifecycle.begin_shutdown().is_err());
    #[cfg(target_os = "macos")]
    assert!(lifecycle.begin_handoff_lease().is_err());
    lease
        .fail(MigrationHandoffFailure::Operation)
        .expect("handoff failure");

    let failure = lifecycle
        .migration_handoff_status()
        .expect("failure status");
    assert_eq!(failure, MigrationHandoffFailure::Operation.status());
    let encoded = serde_json::to_string(&failure).expect("serialize failure");
    assert!(encoded.len() < 512, "handoff status must remain bounded");
    assert!(!encoded.contains("/Users/"));

    let retry = lifecycle.begin_handoff_lease().expect("handoff retry");
    assert_eq!(
        lifecycle.migration_handoff_status().expect("retry status"),
        MigrationHandoffStatus::InProgress
    );
    drop(retry);
}

#[test]
#[cfg(target_os = "macos")]
fn dropped_handoff_lease_records_unexpected_failure_and_restores_admission() {
    let lifecycle = AppLifecycle::default();
    drop(lifecycle.begin_handoff_lease().expect("handoff admission"));
    assert_eq!(
        lifecycle
            .migration_handoff_status()
            .expect("failure status"),
        MigrationHandoffFailure::UnexpectedTaskEnd.status()
    );
    let retry = lifecycle
        .begin_handoff_lease()
        .expect("retry after task end");
    drop(retry);
}

#[test]
fn an_update_owns_the_lifecycle_alone_and_returns_it_when_abandoned() {
    let lifecycle = AppLifecycle::default();
    let update = lifecycle.begin_update_lease().expect("update admission");
    assert!(!lifecycle.startup_work_allowed());
    assert!(lifecycle.begin_update_lease().is_err());
    #[cfg(target_os = "macos")]
    assert!(lifecycle.begin_handoff_lease().is_err());
    let refused = lifecycle
        .begin_shutdown()
        .expect_err("shutdown waits for the update");
    assert!(refused.contains("update installation"), "{refused}");

    drop(update);
    assert!(
        lifecycle.startup_work_allowed(),
        "an abandoned update returns the application to normal operation"
    );
    let update = lifecycle.begin_update_lease().expect("a second update");
    drop(update);

    assert_eq!(
        lifecycle.begin_shutdown().expect("shutdown admission"),
        ShutdownAdmission::Started
    );
    let refused = lifecycle
        .begin_update_lease()
        .err()
        .expect("no update during shutdown");
    assert!(refused.contains("shutdown"), "{refused}");
}

#[test]
#[cfg(target_os = "macos")]
fn shutdown_is_idempotent_but_remains_mutually_exclusive_with_handoff() {
    let lifecycle = AppLifecycle::default();
    assert_eq!(
        lifecycle.begin_shutdown().expect("shutdown admission"),
        ShutdownAdmission::Started
    );
    assert_eq!(
        lifecycle.begin_shutdown().expect("idempotent shutdown"),
        ShutdownAdmission::AlreadyInProgress
    );
    #[cfg(target_os = "macos")]
    assert!(lifecycle.begin_handoff_lease().is_err());
    lifecycle
        .reset_owner_after_failure(LIFECYCLE_SHUTDOWN)
        .expect("shutdown rollback");
    let handoff = lifecycle
        .begin_handoff_lease()
        .expect("handoff after rollback");
    assert!(lifecycle.begin_shutdown().is_err());
    drop(handoff);
}

#[test]
#[cfg(target_os = "macos")]
fn simultaneous_handoff_and_shutdown_admit_exactly_one_owner() {
    for _ in 0..64 {
        let lifecycle = Arc::new(AppLifecycle::default());
        let start = Arc::new(std::sync::Barrier::new(3));
        let finish = Arc::new(std::sync::Barrier::new(3));

        let handoff_lifecycle = lifecycle.clone();
        let handoff_start = start.clone();
        let handoff_finish = finish.clone();
        let handoff = std::thread::spawn(move || {
            handoff_start.wait();
            let lease = handoff_lifecycle.begin_handoff_lease().ok();
            handoff_finish.wait();
            let admitted = lease.is_some();
            drop(lease);
            admitted
        });

        let shutdown_lifecycle = lifecycle.clone();
        let shutdown_start = start.clone();
        let shutdown_finish = finish.clone();
        let shutdown = std::thread::spawn(move || {
            shutdown_start.wait();
            let admitted = matches!(
                shutdown_lifecycle.begin_shutdown(),
                Ok(ShutdownAdmission::Started)
            );
            shutdown_finish.wait();
            admitted
        });

        start.wait();
        finish.wait();
        let admitted = [
            handoff.join().expect("handoff racer"),
            shutdown.join().expect("shutdown racer"),
        ];
        assert_eq!(admitted.into_iter().filter(|admitted| *admitted).count(), 1);
    }
}

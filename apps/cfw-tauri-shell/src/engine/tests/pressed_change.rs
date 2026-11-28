//! What a change of the runtime preferences is among the mode changes while
//! it is read before its turn: it is counted among them from its press, until
//! the read has ended, and its turn leaves an operation asked for meanwhile its
//! retries and a revision observed meanwhile current.
use super::restoration::{RestorationRightsBridge, engine_with_rights_bridge};
use super::saved_preferences::temporary_store;
use super::*;
use crate::engine::runtime_settings::{
    PreferencesBasis, RequestedChange, admit_runtime_preferences_change,
};
use cfw_singbox_config::{EngineLogLevel, RuntimePreferences};

/// The change of the log level that these tests make.
fn louder() -> RequestedChange {
    RequestedChange {
        preferences: RuntimePreferences {
            log_level: EngineLogLevel::Debug,
            ..RuntimePreferences::default()
        },
        expected_revision: None,
        basis: PreferencesBasis::InForce,
    }
}

/// An update of a subscription holds the profiles while a change is read
/// before its turn. The change is counted among the mode changes from its
/// press, so maintenance waits for it, and a start asked for while it is read
/// keeps its retry once the change takes its turn after it. That turn reads
/// the desired mode once it has come, as the start left it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_asked_for_while_a_change_is_read_keeps_its_retry() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let engine = engine_with_rights_bridge(Arc::new(RestorationRightsBridge::default()));
    let held = repository
        .begin_credential_profile_mutation()
        .expect("the repository");
    let admission =
        admit_runtime_preferences_change(&engine, store, repository.clone(), |_| Ok(louder()));
    tokio::pin!(admission);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut admission)
            .await
            .is_err(),
        "the change is read while the profiles are held"
    );
    assert!(
        matches!(
            engine.reserve_maintenance(),
            Err(EngineMaintenanceError::ModeChangeActive)
        ),
        "maintenance waits for the change that is read"
    );
    let start = engine
        .begin_mode_change(EngineMode::LocalProxy)
        .await
        .expect("the start");
    let retry = start.retry_guard();
    drop(held);
    let change = tokio::time::timeout(Duration::from_secs(5), &mut admission)
        .await
        .expect("read once the profiles are free")
        .expect("admitted");
    let turn = change.begin(&engine);
    tokio::pin!(turn);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut turn)
            .await
            .is_err(),
        "the change takes its turn after the start"
    );
    assert_eq!(
        retry(),
        Ok(()),
        "the start asked for while the change was read keeps its retry"
    );
    engine
        .coordinator
        .set_mode(
            EngineMode::LocalProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("the start");
    drop(start);
    let (mode, lease, requested) = tokio::time::timeout(Duration::from_secs(1), &mut turn)
        .await
        .expect("its turn")
        .expect("the change");
    assert_eq!(mode, EngineMode::LocalProxy, "the mode the start left");
    assert_eq!(requested.preferences.log_level, EngineLogLevel::Debug);
    drop(lease);
    engine.coordinator.shutdown().await.expect("shutdown");
}

/// A full queue of mode changes refuses a change before anything is read for
/// it.
#[tokio::test]
async fn a_full_queue_refuses_a_change_before_it_is_read() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let engine = engine_with_rights_bridge(Arc::new(RestorationRightsBridge::default()));
    let first = engine
        .begin_mode_change(EngineMode::Tunnel)
        .await
        .expect("the first change");
    let mut queued = Vec::new();
    for _ in 1..MAX_PENDING_MODE_CHANGES {
        let mut pending = Box::pin(engine.begin_mode_change(EngineMode::Tunnel));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), pending.as_mut())
                .await
                .is_err(),
            "a queued change waits for the first"
        );
        queued.push(pending);
    }
    let reads = Arc::new(AtomicUsize::new(0));
    let counted = reads.clone();
    let admitted = admit_runtime_preferences_change(&engine, store, repository, move |_| {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(louder())
    })
    .await;
    assert_eq!(
        reads.load(Ordering::SeqCst),
        0,
        "nothing is read for a change that the queue cannot take"
    );
    assert_eq!(
        admitted.map(|_| ()).err(),
        Some(EngineMaintenanceError::QueueFull.to_string())
    );
    drop(queued);
    drop(first);
}

/// A network rule that observes the network while a change is read asks for
/// its mode once the change has taken its turn. The press moved the revision
/// on, so the rule observed a revision later than the change, which leaves it
/// current.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_network_rule_that_observes_while_a_change_is_read_stays_current() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let engine = engine_with_rights_bridge(Arc::new(RestorationRightsBridge::default()));
    let held = repository
        .begin_credential_profile_mutation()
        .expect("the repository");
    let admission =
        admit_runtime_preferences_change(&engine, store, repository.clone(), |_| Ok(louder()));
    tokio::pin!(admission);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut admission)
            .await
            .is_err(),
        "the change is read while the profiles are held"
    );
    let observed = engine
        .mode_intent_revision()
        .expect("the revision the rule observes");
    drop(held);
    let change = tokio::time::timeout(Duration::from_secs(5), &mut admission)
        .await
        .expect("read once the profiles are free")
        .expect("admitted");
    let (_, lease, _) = tokio::time::timeout(Duration::from_secs(1), change.begin(&engine))
        .await
        .expect("its turn")
        .expect("the change");
    drop(lease);
    let rule = tokio::time::timeout(
        Duration::from_secs(1),
        engine.begin_automatic_mode_change(EngineMode::Tunnel, observed),
    )
    .await
    .expect("the rule's turn")
    .map(drop);
    assert_eq!(
        rule,
        Ok(()),
        "the rule observed the network after the press"
    );
    engine.coordinator.shutdown().await.expect("shutdown");
}

/// A command given up while its change is read does not stop that read, so
/// the change keeps its place among the mode changes until the read has
/// ended: maintenance waits for it meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_given_up_while_it_is_read_keeps_its_place_until_the_read_ends() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let engine = engine_with_rights_bridge(Arc::new(RestorationRightsBridge::default()));
    let held = repository
        .begin_credential_profile_mutation()
        .expect("the repository");
    let mut admission = Box::pin(admit_runtime_preferences_change(
        &engine,
        store,
        repository.clone(),
        |_| Ok(louder()),
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), admission.as_mut())
            .await
            .is_err(),
        "the change is read while the profiles are held"
    );
    drop(admission);
    assert!(
        matches!(
            engine.reserve_maintenance(),
            Err(EngineMaintenanceError::ModeChangeActive)
        ),
        "the read goes on, and maintenance waits for it"
    );
    drop(held);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let maintenance = loop {
        match engine.reserve_maintenance() {
            Ok(maintenance) => break maintenance,
            Err(EngineMaintenanceError::ModeChangeActive)
                if tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("maintenance once the read has ended: {error}"),
        }
    };
    drop(maintenance);
}

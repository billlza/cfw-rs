//! How an attempt is concluded, what the dashboard is told, and when a
//! profile counts as changed while an attempt ran.

use std::cell::{Cell, RefCell};

use cfw_profiles::ProfileSourceKind;

use super::*;
use crate::engine::EngineMaintenanceError;

const SAVED: u64 = 1_800_000_000;
const CLOCK: u64 = 1_800_090_000;

fn saved() -> (ProfileImportResult, Vec<String>) {
    (
        ProfileImportResult {
            id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            name: "Work".into(),
            bytes: 2,
            digest: "ab".repeat(32),
        },
        vec!["Auto".into()],
    )
}

fn updated() -> UiUpdatedProfile {
    UiUpdatedProfile {
        id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        name: "Work".into(),
        reset_proxy_groups: vec!["Auto".into()],
    }
}

#[test]
fn an_attempt_is_concluded_by_what_the_engine_queue_answered() {
    assert_eq!(concluded(Ok(saved()), false), Refresh::Updated(updated()));
    assert_eq!(
        concluded(
            Err(KeptEngineChangeError::NotAdmitted(
                EngineMaintenanceError::AlreadyActive
            )),
            false
        ),
        Refresh::NotAdmitted
    );
    assert_eq!(
        concluded(Err(KeptEngineChangeError::RunningEngineKept), false),
        Refresh::Left(Outcome::Waiting)
    );
    assert_eq!(
        concluded(
            Err(KeptEngineChangeError::Failed("timed out".into())),
            false
        ),
        Refresh::Left(Outcome::failed("timed out"))
    );
}

#[test]
fn only_a_failure_is_set_aside_when_the_profile_changed_meanwhile() {
    assert_eq!(
        concluded(Err(KeptEngineChangeError::Failed("stale".into())), true),
        Refresh::Superseded
    );
    assert_eq!(concluded(Ok(saved()), true), Refresh::Updated(updated()));
    assert_eq!(
        concluded(Err(KeptEngineChangeError::RunningEngineKept), true),
        Refresh::Left(Outcome::Waiting)
    );
    assert_eq!(
        concluded(
            Err(KeptEngineChangeError::NotAdmitted(
                EngineMaintenanceError::QueueFull
            )),
            true
        ),
        Refresh::NotAdmitted
    );
}

#[tokio::test]
async fn a_profile_changed_meanwhile_once_it_is_no_longer_the_stored_record() {
    const ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const ADDRESS: &str = "https://subscription.example/current";
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    repository
        .import_with_id_and_source(
            ID,
            Some("Work"),
            &ValidatedSingBoxProfile::direct(),
            Some(ADDRESS),
        )
        .expect("stored subscription");
    let record = repository
        .load(ID)
        .expect("load")
        .expect("stored profile")
        .record;
    assert!(!changed_meanwhile(&repository, record.clone()).await);

    repository
        .update_metadata(ID, Some("Renamed"), Some(ADDRESS))
        .expect("rename");
    assert!(changed_meanwhile(&repository, record.clone()).await);
    repository
        .delete(ID, cfw_profiles::InvalidSelection::Keep)
        .expect("delete");
    assert!(changed_meanwhile(&repository, record.clone()).await);

    // A repository that cannot be read shows no change: the attempt's own
    // failure is what the user is told.
    let not_a_directory = temporary.path().join("file");
    std::fs::write(&not_a_directory, b"").expect("file");
    let unreadable = ProfileRepository::new(&not_a_directory);
    assert!(unreadable.load(ID).is_err());
    assert!(!changed_meanwhile(&unreadable, record).await);
}

#[test]
fn the_dashboard_is_told_the_view_and_the_profiles_saved_again() {
    let updates = SubscriptionUpdates::default();
    let event = UiSubscriptionUpdatesChanged {
        view: updates.view(UpdateInterval::Weekly).expect("view"),
        updated: vec![updated()],
    };
    assert_eq!(
        serde_json::to_value(event).expect("serialize"),
        serde_json::json!({
            "interval": "weekly",
            "profiles": [],
            "updated": [{
                "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "name": "Work",
                "reset_proxy_groups": ["Auto"],
            }],
        })
    );
    assert_eq!(CHANGED_EVENT, "cfw://subscription-updates");
}

fn subscription(id: &str) -> ProfileRecord {
    ProfileRecord {
        id: id.into(),
        name: id.to_uppercase(),
        bytes: 2,
        digest: "00".repeat(32),
        created_epoch_secs: SAVED,
        source_kind: ProfileSourceKind::Subscription,
    }
}

fn saved_again(id: &str) -> UiUpdatedProfile {
    UiUpdatedProfile {
        id: id.into(),
        name: id.to_uppercase(),
        reset_proxy_groups: Vec::new(),
    }
}

/// What the ledger shows for each subscription, as the dashboard reads it.
fn notes(updates: &SubscriptionUpdates) -> serde_json::Value {
    serde_json::to_value(updates.view(UpdateInterval::Daily).expect("view")).expect("serialize")
        ["profiles"]
        .take()
}

struct Run {
    attempted: Vec<String>,
    looked: Looked,
    result: Result<(), String>,
}

/// Runs `due` through scripted attempts. The look may proceed `allowed`
/// times; an attempt beyond the script fails the test.
async fn run(
    updates: &SubscriptionUpdates,
    due: &[&str],
    allowed: usize,
    script: Vec<Refresh>,
    clock: Result<u64, String>,
) -> Run {
    let asked = Cell::new(0_usize);
    let attempted = RefCell::new(Vec::new());
    let mut script = script.into_iter();
    let mut looked = Looked::default();
    let result = attempt_each(
        updates,
        due.iter().map(|id| subscription(id)).collect(),
        || {
            asked.set(asked.get() + 1);
            asked.get() <= allowed
        },
        |record| {
            attempted.borrow_mut().push(record.id);
            std::future::ready(script.next().expect("an attempt the script expects"))
        },
        || clock.clone(),
        &mut looked,
    )
    .await;
    assert!(script.next().is_none(), "every scripted attempt was made");
    Run {
        attempted: attempted.into_inner(),
        looked,
        result,
    }
}

#[tokio::test]
async fn each_due_subscription_is_attempted_in_turn_and_what_it_left_is_kept() {
    let updates = SubscriptionUpdates::default();
    let run = run(
        &updates,
        &["a", "b", "c"],
        usize::MAX,
        vec![
            Refresh::Updated(saved_again("a")),
            Refresh::Left(Outcome::Waiting),
            Refresh::Left(Outcome::failed("timed out")),
        ],
        Ok(CLOCK),
    )
    .await;
    assert_eq!(run.result, Ok(()));
    assert_eq!(run.attempted, ["a", "b", "c"]);
    assert_eq!(
        run.looked,
        Looked {
            changed: true,
            updated: vec![saved_again("a")],
        }
    );
    assert_eq!(
        notes(&updates),
        serde_json::json!([
            { "id": "b", "attempted_epoch_secs": CLOCK, "state": "waiting" },
            { "id": "c", "attempted_epoch_secs": CLOCK, "state": "failed", "error": "timed out" },
        ])
    );
}

#[tokio::test]
async fn a_profile_saved_again_or_changed_meanwhile_loses_what_was_noted_about_it() {
    let updates = SubscriptionUpdates::default();
    for id in ["a", "b", "c"] {
        updates
            .remember(&subscription(id), SAVED, Outcome::Waiting)
            .expect("remember");
    }
    let run_with_notes = run(
        &updates,
        &["a", "b"],
        usize::MAX,
        vec![Refresh::Updated(saved_again("a")), Refresh::Superseded],
        Ok(CLOCK),
    )
    .await;
    assert_eq!(
        run_with_notes.looked,
        Looked {
            changed: true,
            updated: vec![saved_again("a")],
        }
    );
    assert_eq!(
        notes(&updates),
        serde_json::json!([{ "id": "c", "attempted_epoch_secs": SAVED, "state": "waiting" }])
    );

    // With nothing noted, the ledger is what the dashboard already read.
    let run_without_notes = run(
        &updates,
        &["a", "b"],
        usize::MAX,
        vec![Refresh::Updated(saved_again("a")), Refresh::Superseded],
        Ok(CLOCK),
    )
    .await;
    assert_eq!(
        run_without_notes.looked,
        Looked {
            changed: false,
            updated: vec![saved_again("a")],
        }
    );

    // One note that went is a change, whatever the attempts after it leave.
    let run_with_one_note = run(
        &updates,
        &["c", "d"],
        usize::MAX,
        vec![Refresh::Superseded, Refresh::Superseded],
        Ok(CLOCK),
    )
    .await;
    assert!(run_with_one_note.looked.changed);
    assert_eq!(notes(&updates), serde_json::json!([]));
}

#[tokio::test]
async fn a_refused_turn_ends_the_look_and_leaves_the_rest_for_the_next_one() {
    let updates = SubscriptionUpdates::default();
    let run = run(
        &updates,
        &["a", "b", "c"],
        usize::MAX,
        vec![
            Refresh::Left(Outcome::failed("refused")),
            Refresh::NotAdmitted,
        ],
        Ok(CLOCK),
    )
    .await;
    assert_eq!(run.result, Ok(()));
    assert_eq!(run.attempted, ["a", "b"]);
    assert_eq!(
        run.looked,
        Looked {
            changed: true,
            updated: Vec::new(),
        }
    );
    assert_eq!(
        notes(&updates),
        serde_json::json!([
            { "id": "a", "attempted_epoch_secs": CLOCK, "state": "failed", "error": "refused" },
        ])
    );
}

#[tokio::test]
async fn a_look_ends_as_soon_as_it_may_not_proceed() {
    let updates = SubscriptionUpdates::default();
    let stopped = run(&updates, &["a", "b"], 0, Vec::new(), Ok(CLOCK)).await;
    assert_eq!(stopped.result, Ok(()));
    assert!(stopped.attempted.is_empty());
    assert_eq!(stopped.looked, Looked::default());

    let interrupted = run(
        &updates,
        &["a", "b"],
        1,
        vec![Refresh::Left(Outcome::Waiting)],
        Ok(CLOCK),
    )
    .await;
    assert_eq!(interrupted.attempted, ["a"]);
    assert_eq!(
        notes(&updates),
        serde_json::json!([{ "id": "a", "attempted_epoch_secs": CLOCK, "state": "waiting" }])
    );
}

#[tokio::test]
async fn a_clock_that_fails_ends_the_look_and_keeps_what_was_done() {
    let updates = SubscriptionUpdates::default();
    let run = run(
        &updates,
        &["a", "b", "c"],
        usize::MAX,
        vec![
            Refresh::Updated(saved_again("a")),
            Refresh::Left(Outcome::Waiting),
        ],
        Err("the clock is before 1970".into()),
    )
    .await;
    assert_eq!(run.result, Err("the clock is before 1970".into()));
    assert_eq!(run.attempted, ["a", "b"]);
    assert_eq!(
        run.looked,
        Looked {
            changed: false,
            updated: vec![saved_again("a")],
        }
    );
    assert_eq!(notes(&updates), serde_json::json!([]));
}

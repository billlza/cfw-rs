//! How an attempt is concluded, what the dashboard is told, and how a look
//! runs its attempts.

use std::cell::{Cell, RefCell};

use cfw_profiles::ProfileSourceKind;

use super::*;
use crate::engine::EngineMaintenanceError;

mod superseded;

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

fn following(interval: UpdateInterval) -> SubscriptionUpdates {
    let updates = SubscriptionUpdates::default();
    updates.follow(interval).expect("follow");
    updates
}

/// What the dashboard reads: the interval and the notes.
fn view(updates: &SubscriptionUpdates) -> serde_json::Value {
    serde_json::to_value(updates.view().expect("view")).expect("serialize")
}

/// What the ledger shows for each subscription, as the dashboard reads it.
fn notes(updates: &SubscriptionUpdates) -> serde_json::Value {
    view(updates)["profiles"].take()
}

#[test]
fn the_dashboard_is_told_the_view_and_the_profiles_saved_again() {
    let updates = following(UpdateInterval::Weekly);
    let event = UiSubscriptionUpdatesChanged {
        view: updates.view().expect("view"),
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

/// What a scripted download brings: the subscription's document, or the
/// reason it could not be fetched.
fn document_of(id: &str) -> Result<String, String> {
    if id == "unreachable" {
        Err("timed out".into())
    } else {
        Ok(format!("document of {id}"))
    }
}

struct Run {
    /// The subscriptions whose download began.
    downloaded: Vec<String>,
    /// What each save was handed: what the download before it brought.
    saved: Vec<Result<String, String>>,
    looked: Looked,
    result: Result<(), String>,
}

/// Runs `due` through scripted attempts. The look is asked before each
/// download and before each save, and may proceed `allowed` times; a save
/// beyond the script fails the test.
async fn run(
    updates: &SubscriptionUpdates,
    due: &[&str],
    allowed: usize,
    script: Vec<Refresh>,
    clock: Result<u64, String>,
) -> Run {
    let asked = Cell::new(0_usize);
    let downloaded = RefCell::new(Vec::new());
    let saved = RefCell::new(Vec::new());
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
            let document = document_of(&record.id);
            downloaded.borrow_mut().push(record.id);
            std::future::ready(document)
        },
        |document| {
            saved.borrow_mut().push(document);
            std::future::ready(script.next().expect("a save the script expects"))
        },
        || clock.clone(),
        &mut looked,
    )
    .await;
    assert!(script.next().is_none(), "every scripted save was made");
    Run {
        downloaded: downloaded.into_inner(),
        saved: saved.into_inner(),
        looked,
        result,
    }
}

#[tokio::test]
async fn each_due_subscription_is_attempted_in_turn_and_what_it_left_is_kept() {
    let updates = following(UpdateInterval::Daily);
    let run = run(
        &updates,
        &["a", "b", "unreachable"],
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
    assert_eq!(run.downloaded, ["a", "b", "unreachable"]);
    // Each save is handed what the download before it brought, and a
    // download that failed is concluded like any other.
    assert_eq!(
        run.saved,
        [
            Ok("document of a".to_owned()),
            Ok("document of b".to_owned()),
            Err("timed out".to_owned()),
        ]
    );
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
            { "id": "unreachable", "attempted_epoch_secs": CLOCK, "state": "failed", "error": "timed out" },
        ])
    );
}

#[tokio::test]
async fn a_profile_saved_again_or_changed_meanwhile_loses_what_was_noted_about_it() {
    let updates = following(UpdateInterval::Daily);
    for id in ["a", "b", "c"] {
        assert_eq!(
            updates.remember(&subscription(id), SAVED, Outcome::Waiting),
            Ok(true)
        );
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
    let updates = following(UpdateInterval::Daily);
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
    assert_eq!(run.downloaded, ["a", "b"]);
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
    let updates = following(UpdateInterval::Daily);
    let stopped = run(&updates, &["a", "b"], 0, Vec::new(), Ok(CLOCK)).await;
    assert_eq!(stopped.result, Ok(()));
    assert!(stopped.downloaded.is_empty());
    assert_eq!(stopped.looked, Looked::default());

    // A download that ends after the look did is dropped: it is neither
    // saved nor noted.
    let ended_meanwhile = run(&updates, &["a", "b"], 1, Vec::new(), Ok(CLOCK)).await;
    assert_eq!(ended_meanwhile.result, Ok(()));
    assert_eq!(ended_meanwhile.downloaded, ["a"]);
    assert!(ended_meanwhile.saved.is_empty());
    assert_eq!(ended_meanwhile.looked, Looked::default());
    assert_eq!(notes(&updates), serde_json::json!([]));

    let interrupted = run(
        &updates,
        &["a", "b"],
        2,
        vec![Refresh::Left(Outcome::Waiting)],
        Ok(CLOCK),
    )
    .await;
    assert_eq!(interrupted.downloaded, ["a"]);
    assert_eq!(
        notes(&updates),
        serde_json::json!([{ "id": "a", "attempted_epoch_secs": CLOCK, "state": "waiting" }])
    );
}

#[tokio::test]
async fn updates_turned_off_while_an_attempt_runs_end_the_look_and_leave_no_note() {
    fn left_waiting() -> std::future::Ready<Refresh> {
        std::future::ready(Refresh::Left(Outcome::Waiting))
    }
    let due = || vec![subscription("a"), subscription("b")];
    let off = serde_json::json!({ "interval": "off", "profiles": [] });

    // Turned off during a download: the look ends before anything is saved.
    let updates = following(UpdateInterval::Daily);
    let saves = Cell::new(0_usize);
    let mut looked = Looked::default();
    let result = attempt_each(
        &updates,
        due(),
        || updates.followed() == UpdateInterval::Daily,
        |_due| {
            updates.follow(UpdateInterval::Off).expect("off");
            std::future::ready(())
        },
        |()| {
            saves.set(saves.get() + 1);
            left_waiting()
        },
        || Ok(CLOCK),
        &mut looked,
    )
    .await;
    assert_eq!(result, Ok(()));
    assert_eq!(saves.get(), 0);
    assert_eq!(looked, Looked::default());
    assert_eq!(view(&updates), off);

    // Turned off during a save: what the attempts leave is not kept, whatever
    // the look goes on to do. The answer to turning updates off has already
    // told the dashboard that every note is gone.
    let updates = following(UpdateInterval::Daily);
    assert_eq!(
        updates.remember(&subscription("earlier"), SAVED, Outcome::Waiting),
        Ok(true)
    );
    let mut looked = Looked::default();
    let result = attempt_each(
        &updates,
        due(),
        || true,
        |due| std::future::ready(due.id),
        |id: String| {
            if id == "a" {
                updates.follow(UpdateInterval::Off).expect("off");
            }
            left_waiting()
        },
        || Ok(CLOCK),
        &mut looked,
    )
    .await;
    assert_eq!(result, Ok(()));
    assert_eq!(looked, Looked::default());
    assert_eq!(view(&updates), off);
}

#[tokio::test]
async fn a_clock_that_fails_ends_the_look_and_keeps_what_was_done() {
    let updates = following(UpdateInterval::Daily);
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
    assert_eq!(run.downloaded, ["a", "b"]);
    assert_eq!(
        run.looked,
        Looked {
            changed: false,
            updated: vec![saved_again("a")],
        }
    );
    assert_eq!(notes(&updates), serde_json::json!([]));
}

//! The schedule and the ledger: when a subscription is due, what an attempt
//! leaves, and when that is forgotten.

use super::*;

const HOUR: u64 = 60 * 60;
const INTERVAL: u64 = 6 * HOUR;
const NOW: u64 = 1_800_000_000;

fn record(id: &str, saved: u64, source_kind: ProfileSourceKind) -> ProfileRecord {
    ProfileRecord {
        id: id.into(),
        name: id.to_uppercase(),
        bytes: 2,
        digest: "00".repeat(32),
        created_epoch_secs: saved,
        source_kind,
    }
}

fn subscription(id: &str, saved: u64) -> ProfileRecord {
    record(id, saved, ProfileSourceKind::Subscription)
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

fn due(
    updates: &SubscriptionUpdates,
    now: u64,
    interval: u64,
    records: &[ProfileRecord],
    running: Option<&str>,
) -> Vec<String> {
    updates
        .due(now, interval, records, running)
        .expect("due")
        .into_iter()
        .map(|record| record.id)
        .collect()
}

#[test]
fn the_interval_is_stored_by_name_and_off_has_no_period() {
    for (interval, name, seconds) in [
        (UpdateInterval::Off, "off", None),
        (UpdateInterval::SixHours, "six_hours", Some(21_600)),
        (UpdateInterval::TwelveHours, "twelve_hours", Some(43_200)),
        (UpdateInterval::Daily, "daily", Some(86_400)),
        (UpdateInterval::Weekly, "weekly", Some(604_800)),
    ] {
        let stored = format!(r#"{{"interval":"{name}"}}"#);
        assert_eq!(
            serde_json::to_string(&UpdatePreferences { interval }).expect("serialize"),
            stored
        );
        assert_eq!(
            serde_json::from_str::<UpdatePreferences>(&stored).expect("parse"),
            UpdatePreferences { interval }
        );
        assert_eq!(interval.seconds(), seconds, "{name}");
    }
    assert_eq!(UpdatePreferences::default().interval, UpdateInterval::Off);
    for refused in [
        r#"{"interval":"hourly"}"#,
        r#"{"interval":"off","extra":1}"#,
        r#"{}"#,
    ] {
        assert!(
            serde_json::from_str::<UpdatePreferences>(refused).is_err(),
            "{refused}"
        );
    }
}

#[test]
fn a_subscription_is_due_one_interval_after_it_was_saved_and_a_local_profile_never() {
    let updates = SubscriptionUpdates::default();
    let records = [
        subscription("early", NOW - INTERVAL + 1),
        subscription("exact", NOW - INTERVAL),
        record("local", NOW - 100 * INTERVAL, ProfileSourceKind::Local),
        subscription("old", NOW - 100 * INTERVAL),
        // A clock set back: the profile seems saved in the future.
        subscription("ahead", NOW + HOUR),
    ];
    assert_eq!(
        due(&updates, NOW, INTERVAL, &records, None),
        ["exact", "old"]
    );
    assert_eq!(
        due(&updates, NOW + 1, INTERVAL, &records, Some("exact")),
        ["early", "exact", "old"],
        "what the engine runs is fetched like any other"
    );
    assert!(due(&updates, NOW, 100 * INTERVAL + 1, &records, None).is_empty());
}

#[test]
fn a_failed_attempt_is_retried_after_half_an_hour_or_after_one_shorter_interval() {
    let updates = following(UpdateInterval::SixHours);
    let records = [subscription("a", NOW - 2 * INTERVAL)];
    updates
        .remember(&records[0], NOW, Outcome::failed("timed out"))
        .expect("remember");
    assert!(due(&updates, NOW + 30 * 60 - 1, INTERVAL, &records, None).is_empty());
    assert_eq!(
        due(&updates, NOW + 30 * 60, INTERVAL, &records, None),
        ["a"]
    );
    // An interval shorter than half an hour is the delay.
    assert!(due(&updates, NOW + 599, 600, &records, None).is_empty());
    assert_eq!(due(&updates, NOW + 600, 600, &records, None), ["a"]);
    // A clock set back after the attempt only delays the retry.
    assert!(due(&updates, NOW - 1, INTERVAL, &records, None).is_empty());
    assert!(due(&updates, NOW + 30 * 60 - 1, INTERVAL, &records, None).is_empty());
}

#[test]
fn a_waiting_change_is_fetched_once_the_engine_no_longer_runs_it_or_after_one_interval() {
    let updates = following(UpdateInterval::SixHours);
    let records = [subscription("a", NOW - INTERVAL)];
    updates
        .remember(&records[0], NOW, Outcome::Waiting)
        .expect("remember");
    assert!(due(&updates, NOW + 1, INTERVAL, &records, Some("a")).is_empty());
    assert!(due(&updates, NOW + INTERVAL - 1, INTERVAL, &records, Some("a")).is_empty());
    assert_eq!(
        due(&updates, NOW + INTERVAL, INTERVAL, &records, Some("a")),
        ["a"]
    );
    assert_eq!(
        due(&updates, NOW + 1, INTERVAL, &records, None),
        ["a"],
        "the engine is off"
    );
    assert_eq!(
        due(&updates, NOW + 1, INTERVAL, &records, Some("b")),
        ["a"],
        "the engine runs another profile"
    );
}

#[test]
fn what_an_attempt_left_is_dropped_once_the_profile_was_saved_again_is_local_or_is_gone() {
    let updates = following(UpdateInterval::Daily);
    for id in ["kept", "saved", "local", "gone"] {
        updates
            .remember(&subscription(id, NOW), NOW + 10, Outcome::Waiting)
            .expect("remember");
    }
    let records = [
        subscription("kept", NOW),
        subscription("saved", NOW + 20),
        record("local", NOW, ProfileSourceKind::Local),
        subscription("unrelated", NOW),
    ];
    assert_eq!(updates.prune(&records), Ok(true));
    assert_eq!(
        view(&updates)["profiles"],
        serde_json::json!([{ "id": "kept", "attempted_epoch_secs": NOW + 10, "state": "waiting" }])
    );
    assert_eq!(updates.prune(&records), Ok(false));
    assert_eq!(updates.prune(&[]), Ok(true));
    assert_eq!(updates.prune(&[]), Ok(false));
}

#[test]
fn the_view_names_the_interval_and_each_attempt_with_its_state() {
    let updates = following(UpdateInterval::TwelveHours);
    updates
        .remember(
            &subscription("b", NOW),
            NOW + 5,
            Outcome::failed("timed out"),
        )
        .expect("remember");
    updates
        .remember(&subscription("a", NOW), NOW, Outcome::Waiting)
        .expect("remember");
    assert_eq!(
        view(&updates),
        serde_json::json!({
            "interval": "twelve_hours",
            "profiles": [
                { "id": "a", "attempted_epoch_secs": NOW, "state": "waiting" },
                { "id": "b", "attempted_epoch_secs": NOW + 5, "state": "failed", "error": "timed out" },
            ],
        })
    );
    // A later attempt replaces what the earlier one left.
    updates
        .remember(&subscription("a", NOW), NOW + 9, Outcome::failed("refused"))
        .expect("remember");
    assert_eq!(
        view(&updates)["profiles"][0],
        serde_json::json!({ "id": "a", "attempted_epoch_secs": NOW + 9, "state": "failed", "error": "refused" })
    );
}

#[test]
fn notes_are_kept_only_while_an_interval_is_followed() {
    let updates = SubscriptionUpdates::default();
    let profile = subscription("a", NOW);
    let note =
        serde_json::json!({ "id": "a", "attempted_epoch_secs": NOW + 1, "state": "waiting" });
    // Updates are off until an interval is followed.
    assert_eq!(
        updates.remember(&profile, NOW + 1, Outcome::Waiting),
        Ok(false)
    );
    assert_eq!(
        view(&updates),
        serde_json::json!({ "interval": "off", "profiles": [] })
    );

    updates.follow(UpdateInterval::Daily).expect("daily");
    assert_eq!(
        updates.remember(&profile, NOW + 1, Outcome::Waiting),
        Ok(true)
    );
    // The same interval again, as every read of the stored one follows it,
    // and another interval keep what was noted.
    updates.follow(UpdateInterval::Daily).expect("daily again");
    assert_eq!(view(&updates)["profiles"], serde_json::json!([note]));
    updates.follow(UpdateInterval::Weekly).expect("weekly");
    assert_eq!(
        view(&updates),
        serde_json::json!({ "interval": "weekly", "profiles": [note] })
    );

    // Off forgets it, and an attempt that ends afterwards leaves nothing.
    updates.follow(UpdateInterval::Off).expect("off");
    assert_eq!(
        view(&updates),
        serde_json::json!({ "interval": "off", "profiles": [] })
    );
    assert_eq!(
        updates.remember(&profile, NOW + 2, Outcome::failed("late")),
        Ok(false)
    );
    // Turned on again, the ledger starts empty.
    updates.follow(UpdateInterval::SixHours).expect("six hours");
    assert_eq!(
        view(&updates),
        serde_json::json!({ "interval": "six_hours", "profiles": [] })
    );
}

#[test]
fn a_long_reason_is_cut_and_forgetting_says_whether_there_was_something() {
    let Outcome::Failed { error } = Outcome::failed(&"é".repeat(600)) else {
        panic!("a failure");
    };
    assert_eq!(error.chars().count(), 512);
    assert_eq!(
        Outcome::failed("short"),
        Outcome::Failed {
            error: "short".into()
        }
    );

    let updates = following(UpdateInterval::Daily);
    assert_eq!(updates.forget("a"), Ok(false));
    for id in ["a", "b"] {
        assert_eq!(
            updates.remember(&subscription(id, NOW), NOW, Outcome::Waiting),
            Ok(true)
        );
    }
    assert_eq!(updates.forget("a"), Ok(true));
    assert_eq!(updates.forget("a"), Ok(false));
    assert_eq!(view(&updates)["profiles"][0]["id"], "b");
}

fn temporary_store() -> (tempfile::TempDir, SettingsStore) {
    let root = tempfile::TempDir::new().expect("temporary directory");
    let store = SettingsStore::new(cfw_core::AppPaths::from_app_home(root.path().join("app")));
    (root, store)
}

fn stored_revision(store: &SettingsStore) -> Option<String> {
    store
        .subscription_settings::<UpdatePreferences>()
        .expect("stored preference")
        .revision
}

#[test]
fn the_interval_is_off_until_one_is_stored_and_the_stored_one_is_not_written_again() {
    let (_root, store) = temporary_store();
    assert_eq!(
        UpdateInterval::stored(&store).expect("stored"),
        UpdateInterval::Off
    );
    UpdateInterval::Off.store(&store).expect("store off");
    assert_eq!(
        stored_revision(&store),
        None,
        "off was the interval already"
    );
    UpdateInterval::Daily.store(&store).expect("store daily");
    assert_eq!(
        UpdateInterval::stored(&store).expect("stored"),
        UpdateInterval::Daily
    );
    let daily = stored_revision(&store);
    assert!(daily.is_some());
    UpdateInterval::Daily
        .store(&store)
        .expect("store daily again");
    assert_eq!(stored_revision(&store), daily);
    UpdateInterval::Off.store(&store).expect("store off");
    assert_eq!(
        UpdateInterval::stored(&store).expect("stored"),
        UpdateInterval::Off
    );
    let off = stored_revision(&store);
    assert!(
        off.is_some() && off != daily,
        "off replaces a stored interval"
    );
}

#[test]
fn a_stored_preference_that_cannot_be_read_is_an_error_and_is_left_as_it_is() {
    let (_root, store) = temporary_store();
    let raw = || {
        store
            .subscription_settings::<BTreeMap<String, String>>()
            .expect("the stored document")
    };
    store
        .compare_and_swap_subscription_settings(
            None,
            &BTreeMap::from([("interval".to_owned(), "hourly".to_owned())]),
        )
        .expect("store an interval this build does not know");
    let before = raw();
    assert!(UpdateInterval::stored(&store).is_err());
    assert!(UpdateInterval::Daily.store(&store).is_err());
    assert!(UpdateInterval::Off.store(&store).is_err());
    let after = raw();
    assert_eq!(after.settings, before.settings);
    assert_eq!(after.revision, before.revision);
}

#[test]
fn only_a_different_interval_wakes_the_scheduler() {
    let updates = SubscriptionUpdates::default();
    assert_eq!(updates.followed(), UpdateInterval::Off);
    let mut heard = updates.subscribe();
    updates.follow(UpdateInterval::Off).expect("off");
    assert!(!heard.has_changed().expect("the ledger lives"));
    updates.follow(UpdateInterval::Daily).expect("daily");
    assert!(heard.has_changed().expect("the ledger lives"));
    assert_eq!(*heard.borrow_and_update(), UpdateInterval::Daily);
    updates.follow(UpdateInterval::Daily).expect("daily again");
    assert!(!heard.has_changed().expect("the ledger lives"));
    assert_eq!(updates.followed(), UpdateInterval::Daily);
    // A scheduler that starts now hears only what changes from here on.
    let later = updates.subscribe();
    assert!(!later.has_changed().expect("the ledger lives"));
    updates.follow(UpdateInterval::Weekly).expect("weekly");
    assert!(later.has_changed().expect("the ledger lives"));
    // Turning updates off wakes it as well: the look under way ends.
    let mut last = updates.subscribe();
    updates.follow(UpdateInterval::Off).expect("off");
    assert!(last.has_changed().expect("the ledger lives"));
    assert_eq!(*last.borrow_and_update(), UpdateInterval::Off);
}

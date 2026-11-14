//! Subscriptions refreshed in the background.
//!
//! A subscription that is due is downloaded and validated exactly like a
//! manual update. What the engine runs is never replaced: a changed document
//! of the running profile stays at its source and is reported as waiting, for
//! the user to apply. Nothing here starts, stops or restarts the engine, and
//! nothing asks the system for authorization.

use std::future::Future;
use std::time::Duration;

use cfw_application::EngineCoordinatorError;
use cfw_engine_api::EngineMode;
use cfw_profiles::ProfileRecord;
use tauri::{AppHandle, Emitter, Manager};

use super::update_transaction::{RunningProfile, UpdatePreparationError, prepare_update};
use super::*;
use crate::engine::{KeptEngineChangeError, apply_profile_change_keeping_engine};

mod ledger;
use ledger::Outcome;
pub(crate) use ledger::{SubscriptionUpdates, UiSubscriptionUpdates, UpdateInterval};

/// How often the scheduler looks for subscriptions that are due.
const LOOK_EVERY: Duration = Duration::from_secs(5 * 60);
/// The first look after launch, once startup work has settled.
const FIRST_LOOK_AFTER: Duration = Duration::from_secs(60);
/// What the dashboard listens for.
const CHANGED_EVENT: &str = "cfw://subscription-updates";

/// A profile a look saved again, for the dashboard to read once more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UiUpdatedProfile {
    id: String,
    name: String,
    reset_proxy_groups: Vec<String>,
}

#[derive(Clone, Serialize)]
struct UiSubscriptionUpdatesChanged {
    #[serde(flatten)]
    view: UiSubscriptionUpdates,
    updated: Vec<UiUpdatedProfile>,
}

/// What one attempt came to.
#[derive(Debug, PartialEq, Eq)]
enum Refresh {
    /// The profile was saved again, changed or not.
    Updated(UiUpdatedProfile),
    /// The profile stays as it was, with something for the user to see.
    Left(Outcome),
    /// The profile changed while the attempt ran, so the attempt says nothing
    /// about it.
    Superseded,
    /// The engine queue refused the turn; the next look tries again.
    NotAdmitted,
}

/// What a look did, for the dashboard to hear about.
#[derive(Debug, Default, PartialEq, Eq)]
struct Looked {
    /// The ledger is no longer what the dashboard last read.
    changed: bool,
    updated: Vec<UiUpdatedProfile>,
}

/// Reads the stored interval and has the scheduler follow it, so that what
/// the dashboard shows is what happens.
async fn follow_stored_interval(updates: &SubscriptionUpdates) -> Result<(), String> {
    let _preference = updates.preference.lock().await;
    let store = settings_store()?;
    let interval = tauri::async_runtime::spawn_blocking(move || UpdateInterval::stored(&store))
        .await
        .map_err(|error| format!("subscription update preference read did not complete: {error}"))?
        .map_err(|error| error.to_string())?;
    updates.follow(interval)
}

/// The interval and what the last attempts left for the stored subscriptions.
#[tauri::command]
pub(crate) async fn subscription_updates(
    updates: State<'_, SubscriptionUpdates>,
    profiles: State<'_, ManagedProfiles>,
) -> Result<UiSubscriptionUpdates, String> {
    follow_stored_interval(&updates).await?;
    let records = read_repository(profiles.repository(), |repository| {
        repository
            .snapshot()
            .map(|snapshot| snapshot.profiles)
            .map_err(|error| error.to_string())
    })
    .await?;
    updates.prune(&records)?;
    updates.view()
}

/// Stores the interval and hands it to the scheduler, which looks for due
/// subscriptions at once. Turning updates off forgets what they reported.
#[tauri::command]
pub(crate) async fn set_subscription_update_interval(
    updates: State<'_, SubscriptionUpdates>,
    interval: UpdateInterval,
) -> Result<UiSubscriptionUpdates, String> {
    let _preference = updates.preference.lock().await;
    let store = settings_store()?;
    tauri::async_runtime::spawn_blocking(move || interval.store(&store))
        .await
        .map_err(|error| format!("subscription update preference write did not complete: {error}"))?
        .map_err(|error| error.to_string())?;
    updates.follow(interval)?;
    updates.view()
}

/// The user updated profile `id` or changed where it comes from: what a
/// background attempt reported about it no longer applies.
pub(super) fn settled_by_user(app: &AppHandle, id: &str) {
    let updates = app.state::<SubscriptionUpdates>();
    let refreshed = updates.forget(id).and_then(|forgotten| {
        if forgotten {
            publish(app, Vec::new())
        } else {
            Ok(())
        }
    });
    if let Err(error) = refreshed {
        // The profile itself is saved; only the note beside it is stale.
        eprintln!("subscription update state was not refreshed: {error}");
    }
}

fn publish(app: &AppHandle, updated: Vec<UiUpdatedProfile>) -> Result<(), String> {
    let view = app.state::<SubscriptionUpdates>().view()?;
    app.emit(
        CHANGED_EVENT,
        UiSubscriptionUpdatesChanged { view, updated },
    )
    .map_err(|error| format!("subscription update notification failed: {error}"))
}

/// Follows the stored interval for the rest of the process. The task holds no
/// engine or repository state between looks; an exit in progress and exclusive
/// maintenance are observed by every look.
pub(crate) fn start_subscription_updates(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let updates = app.state::<SubscriptionUpdates>();
        if let Err(error) = follow_stored_interval(&updates).await {
            // The dashboard asks for the same and shows this reason beside
            // the setting.
            eprintln!(
                "the stored subscription update interval is not followed; background updates stay off: {error}"
            );
        }
        // Subscribed once the stored interval is followed, so only a later
        // change of the preference brings the first look forward.
        let mut interval = updates.subscribe();
        let mut timer =
            tokio::time::interval_at(tokio::time::Instant::now() + FIRST_LOOK_AFTER, LOOK_EVERY);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut previous_error = None;
        loop {
            tokio::select! {
                changed = interval.changed() => if changed.is_err() { break },
                _ = timer.tick() => {}
            }
            let Some(seconds) = interval.borrow_and_update().seconds() else {
                continue;
            };
            match look(&app, seconds).await {
                Ok(()) => previous_error = None,
                Err(error) => {
                    if previous_error.as_ref() != Some(&error) {
                        eprintln!("subscription updates could not be looked up: {error}");
                    }
                    previous_error = Some(error);
                }
            }
        }
    });
}

/// Fetches every subscription that is due and tells the dashboard what
/// changed.
async fn look(app: &AppHandle, interval: u64) -> Result<(), String> {
    let lifecycle = app.state::<crate::lifecycle::AppLifecycle>();
    if !lifecycle.startup_work_allowed() {
        return Ok(());
    }
    let updates = app.state::<SubscriptionUpdates>();
    let engine = app.state::<ManagedEngine>();
    let profiles = app.state::<ManagedProfiles>();
    let snapshot = read_repository(profiles.repository(), |repository| {
        repository.snapshot().map_err(|error| error.to_string())
    })
    .await?;
    let running = (engine.coordinator.snapshot().desired_mode != EngineMode::Off)
        .then_some(snapshot.selected_profile_id.as_deref())
        .flatten();
    let now = super::super::providers::now;
    let mut looked = Looked {
        changed: updates.prune(&snapshot.profiles)?,
        updated: Vec::new(),
    };
    let due = updates.due(now()?, interval, &snapshot.profiles, running)?;
    let attempted = attempt_each(
        &updates,
        due,
        // An exit in progress or a changed preference ends this look.
        || lifecycle.startup_work_allowed() && updates.followed().seconds() == Some(interval),
        |record| download(&engine, &profiles, record),
        |record, downloaded| save_download(&engine, &profiles, record, downloaded),
        now,
        &mut looked,
    )
    .await;
    if looked.changed || !looked.updated.is_empty() {
        publish(app, looked.updated)?;
    }
    attempted
}

/// Attempts each due subscription in turn for as long as `proceed` allows:
/// downloads it, saves the download and keeps what the attempt left. A look
/// that ended while a download ran drops that download unsaved. `looked`
/// holds what was done, also when the ledger or the clock fails part of the
/// way.
async fn attempt_each<T, D, S>(
    updates: &SubscriptionUpdates,
    due: Vec<ProfileRecord>,
    proceed: impl Fn() -> bool,
    mut download: impl FnMut(ProfileRecord) -> D,
    mut save: impl FnMut(ProfileRecord, Result<T, String>) -> S,
    clock: impl Fn() -> Result<u64, String>,
    looked: &mut Looked,
) -> Result<(), String>
where
    D: Future<Output = Result<T, String>>,
    S: Future<Output = Refresh>,
{
    for record in due {
        if !proceed() {
            break;
        }
        let downloaded = download(record.clone()).await;
        // A download takes its time: the look may have ended meanwhile.
        if !proceed() {
            break;
        }
        let different = match save(record.clone(), downloaded).await {
            Refresh::NotAdmitted => break,
            Refresh::Updated(profile) => {
                looked.updated.push(profile);
                updates.forget(&record.id)?
            }
            Refresh::Superseded => updates.forget(&record.id)?,
            Refresh::Left(outcome) => updates.remember(&record, clock()?, outcome)?,
        };
        looked.changed |= different;
    }
    Ok(())
}

/// The first half of an attempt: the subscription's current document.
async fn download(
    engine: &ManagedEngine,
    profiles: &ManagedProfiles,
    record: ProfileRecord,
) -> Result<FetchedUpdate, String> {
    fetch_update(engine, profiles, &record.id).await
}

/// The second half: saves the download, if there is one, and says what the
/// attempt came to.
async fn save_download(
    engine: &ManagedEngine,
    profiles: &ManagedProfiles,
    record: ProfileRecord,
    downloaded: Result<FetchedUpdate, String>,
) -> Refresh {
    let result = match downloaded {
        Ok(fetched) => {
            save_keeping_engine(
                engine,
                profiles.repository().clone(),
                profiles.credential_vault().clone(),
                fetched,
            )
            .await
        }
        Err(error) => Err(KeptEngineChangeError::Failed(error)),
    };
    let superseded = matches!(result, Err(KeptEngineChangeError::Failed(_)))
        && changed_meanwhile(profiles.repository(), record).await;
    concluded(result, superseded)
}

/// Prepares a download as the replacement of its profile and commits it, in
/// the engine queue and without touching what the engine runs. While the
/// engine is on, its profile is saved again only when the download is the
/// document it already runs; any other profile is replaced.
pub(super) async fn save_keeping_engine(
    engine: &ManagedEngine,
    repository: ProfileRepository,
    vault: impl CredentialVaultProvisioner,
    fetched: FetchedUpdate,
) -> Result<(ProfileImportResult, Vec<String>), KeptEngineChangeError> {
    apply_profile_change_keeping_engine(engine, move |settings, mode| async move {
        // An engine that is off runs no profile.
        let running_profile = if mode == EngineMode::Off {
            RunningProfile::Replaceable
        } else {
            RunningProfile::Kept
        };
        prepare_update(&repository, &vault, &fetched, &settings, running_profile)
            .await
            .map_err(|error| match error {
                UpdatePreparationError::RunningProfileChanged => {
                    EngineCoordinatorError::RunningEngineKept
                }
                UpdatePreparationError::Failed(message) => {
                    EngineCoordinatorError::ProfilePreparation(message)
                }
            })
    })
    .await
}

/// Whether the stored profile is no longer the one an attempt set out for:
/// the user updated, edited, renamed or deleted it meanwhile.
async fn changed_meanwhile(repository: &ProfileRepository, expected: ProfileRecord) -> bool {
    read_repository(repository, move |repository| {
        repository
            .load(&expected.id)
            .map(|stored| stored.map(|stored| stored.record) != Some(expected))
            .map_err(|error| error.to_string())
    })
    .await
    // An unreadable repository shows no change; the attempt's failure stands.
    .unwrap_or(false)
}

fn concluded(
    result: Result<(ProfileImportResult, Vec<String>), KeptEngineChangeError>,
    superseded: bool,
) -> Refresh {
    match result {
        Ok((profile, reset_proxy_groups)) => Refresh::Updated(UiUpdatedProfile {
            id: profile.id,
            name: profile.name,
            reset_proxy_groups,
        }),
        Err(KeptEngineChangeError::NotAdmitted(_)) => Refresh::NotAdmitted,
        Err(KeptEngineChangeError::RunningEngineKept) => Refresh::Left(Outcome::Waiting),
        Err(KeptEngineChangeError::Failed(_)) if superseded => Refresh::Superseded,
        Err(KeptEngineChangeError::Failed(error)) => Refresh::Left(Outcome::failed(&error)),
    }
}

#[cfg(test)]
mod tests;

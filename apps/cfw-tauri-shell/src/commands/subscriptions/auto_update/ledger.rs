//! What background updates remember: the interval they follow and, for each
//! subscription, what its last attempt left for the user to see. Only the
//! interval is stored; a restart begins with an empty ledger.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use cfw_core::{SettingsStore, SettingsStoreError};
use cfw_profiles::{ProfileRecord, ProfileSourceKind};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// After a failed attempt the next one waits this long, or one interval if
/// that is shorter.
pub(super) const RETRY_AFTER_SECONDS: u64 = 30 * 60;
/// A longer reason is cut; the dashboard shows it on one line.
const MAX_ERROR_CHARACTERS: usize = 512;

/// How often a subscription is refreshed in the background.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpdateInterval {
    #[default]
    Off,
    SixHours,
    TwelveHours,
    Daily,
    Weekly,
}

impl UpdateInterval {
    /// The interval in seconds; `None` while background updates are off.
    pub(super) const fn seconds(self) -> Option<u64> {
        const HOUR: u64 = 60 * 60;
        match self {
            Self::Off => None,
            Self::SixHours => Some(6 * HOUR),
            Self::TwelveHours => Some(12 * HOUR),
            Self::Daily => Some(24 * HOUR),
            Self::Weekly => Some(7 * 24 * HOUR),
        }
    }

    /// The stored interval: off until one is stored. A document that cannot
    /// be read is an error, not a reason to turn updates off silently.
    pub(super) fn stored(store: &SettingsStore) -> Result<Self, SettingsStoreError> {
        Ok(store
            .subscription_settings::<UpdatePreferences>()?
            .settings
            .interval)
    }

    /// Stores this interval, unless it is the stored one already.
    pub(super) fn store(self, store: &SettingsStore) -> Result<(), SettingsStoreError> {
        let saved = store.subscription_settings::<UpdatePreferences>()?;
        if saved.settings.interval == self {
            return Ok(());
        }
        store.compare_and_swap_subscription_settings(
            saved.revision.as_deref(),
            &UpdatePreferences { interval: self },
        )
    }
}

/// The stored preference.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdatePreferences {
    interval: UpdateInterval,
}

/// What an attempt left for the user to see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(super) enum Outcome {
    /// The engine runs this profile and its subscription has changed.
    /// Applying the change restarts the engine, so it waits for the user.
    Waiting,
    Failed {
        error: String,
    },
}

impl Outcome {
    pub(super) fn failed(error: &str) -> Self {
        Self::Failed {
            error: error.chars().take(MAX_ERROR_CHARACTERS).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Attempt {
    /// When the attempt ended, in seconds since the Unix epoch.
    at: u64,
    /// The saved time of the profile the attempt was made for. A profile saved
    /// since then is no longer what the attempt saw.
    saved: u64,
    outcome: Outcome,
}

/// The interval and what the attempts left, as the dashboard reads them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiSubscriptionUpdates {
    interval: UpdateInterval,
    profiles: Vec<UiProfileUpdate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UiProfileUpdate {
    id: String,
    attempted_epoch_secs: u64,
    #[serde(flatten)]
    outcome: Outcome,
}

pub(crate) struct SubscriptionUpdates {
    /// The interval the scheduler follows: the stored preference, once it was
    /// read. It changes only under the lock of `attempts`.
    interval: watch::Sender<UpdateInterval>,
    /// What the attempts left. Empty for as long as updates are off.
    attempts: Mutex<BTreeMap<String, Attempt>>,
    /// Held while the stored preference is read or written and handed to the
    /// scheduler, so the two never disagree.
    pub(super) preference: tokio::sync::Mutex<()>,
}

impl Default for SubscriptionUpdates {
    fn default() -> Self {
        Self {
            interval: watch::channel(UpdateInterval::Off).0,
            attempts: Mutex::new(BTreeMap::new()),
            preference: tokio::sync::Mutex::new(()),
        }
    }
}

impl SubscriptionUpdates {
    /// Has the scheduler follow `interval`. Only a different one wakes it.
    /// Turning updates off forgets what they reported, and an attempt that
    /// still runs then leaves nothing behind: see [`Self::remember`].
    pub(super) fn follow(&self, interval: UpdateInterval) -> Result<(), String> {
        let mut attempts = self.attempts()?;
        self.interval.send_if_modified(|followed| {
            let different = *followed != interval;
            *followed = interval;
            different
        });
        if interval == UpdateInterval::Off {
            attempts.clear();
        }
        Ok(())
    }

    /// The interval the scheduler follows.
    pub(super) fn followed(&self) -> UpdateInterval {
        *self.interval.borrow()
    }

    /// Hears every later change of the followed interval.
    pub(super) fn subscribe(&self) -> watch::Receiver<UpdateInterval> {
        self.interval.subscribe()
    }

    fn attempts(&self) -> Result<MutexGuard<'_, BTreeMap<String, Attempt>>, String> {
        self.attempts
            .lock()
            .map_err(|_| "subscription update state is unavailable".to_owned())
    }

    /// Drops what no longer describes a stored subscription: a profile that is
    /// gone, has no address any more, or was saved after the attempt. True
    /// when something was dropped.
    pub(super) fn prune(&self, records: &[ProfileRecord]) -> Result<bool, String> {
        let mut attempts = self.attempts()?;
        let before = attempts.len();
        attempts.retain(|id, attempt| {
            records.iter().any(|record| {
                record.id == *id
                    && record.source_kind == ProfileSourceKind::Subscription
                    && record.created_epoch_secs == attempt.saved
            })
        });
        Ok(attempts.len() != before)
    }

    /// The subscriptions to fetch at `now`, in the order they are stored.
    /// `running` names the profile the engine runs. Call [`Self::prune`] with
    /// the same records first.
    pub(super) fn due(
        &self,
        now: u64,
        interval: u64,
        records: &[ProfileRecord],
        running: Option<&str>,
    ) -> Result<Vec<ProfileRecord>, String> {
        let attempts = self.attempts()?;
        Ok(records
            .iter()
            .filter(|record| {
                record.source_kind == ProfileSourceKind::Subscription
                    && is_due(
                        now,
                        interval,
                        record.created_epoch_secs,
                        attempts.get(&record.id),
                        running == Some(record.id.as_str()),
                    )
            })
            .cloned()
            .collect())
    }

    /// Keeps what an attempt that ended at `now` left for the profile `record`
    /// describes. False when updates were turned off while the attempt ran:
    /// it then leaves nothing.
    pub(super) fn remember(
        &self,
        record: &ProfileRecord,
        now: u64,
        outcome: Outcome,
    ) -> Result<bool, String> {
        let mut attempts = self.attempts()?;
        if self.followed() == UpdateInterval::Off {
            return Ok(false);
        }
        attempts.insert(
            record.id.clone(),
            Attempt {
                at: now,
                saved: record.created_epoch_secs,
                outcome,
            },
        );
        Ok(true)
    }

    /// Forgets what the last attempt left for `id`. True when there was
    /// something.
    pub(super) fn forget(&self, id: &str) -> Result<bool, String> {
        Ok(self.attempts()?.remove(id).is_some())
    }

    /// The followed interval and what the attempts left, read together.
    pub(super) fn view(&self) -> Result<UiSubscriptionUpdates, String> {
        let attempts = self.attempts()?;
        Ok(UiSubscriptionUpdates {
            interval: self.followed(),
            profiles: attempts
                .iter()
                .map(|(id, attempt)| UiProfileUpdate {
                    id: id.clone(),
                    attempted_epoch_secs: attempt.at,
                    outcome: attempt.outcome.clone(),
                })
                .collect(),
        })
    }
}

/// Whether a subscription saved at `saved` is fetched at `now`. Every time is
/// in seconds since the Unix epoch, so the schedule survives a sleep and a
/// restart; a clock set back only delays the next attempt.
fn is_due(now: u64, interval: u64, saved: u64, attempt: Option<&Attempt>, running: bool) -> bool {
    if now.saturating_sub(saved) < interval {
        return false;
    }
    let Some(attempt) = attempt else {
        return true;
    };
    let waited = now.saturating_sub(attempt.at);
    match attempt.outcome {
        Outcome::Failed { .. } => waited >= RETRY_AFTER_SECONDS.min(interval),
        // A waiting change is fetched again as soon as it can be applied
        // without a restart, and otherwise as rarely as any subscription.
        Outcome::Waiting => !running || waited >= interval,
    }
}

#[cfg(test)]
mod tests;

//! When an attempt says nothing about its profile: the profile is no longer
//! the one the look read, or it changed while the attempt ran.

use std::sync::Arc;

use super::*;
use crate::commands::subscriptions::tests::ScriptedCredentialVault;
use crate::engine::tests::{RestorationRightsBridge, engine_with_rights_bridge};

const ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ADDRESS: &str = "https://subscription.example/current";
const OTHER_ADDRESS: &str = "https://subscription.example/other";
/// A document other than the stored one, which names no credential.
const CHANGED: &str = r#"{"route":{"final":"direct"},"outbounds":[{"tag":"direct","type":"direct"},{"tag":"second","type":"direct"}]}"#;

/// One stored subscription, and the profile a download finds when it begins.
struct Subscription {
    temporary: tempfile::TempDir,
    repository: ProfileRepository,
    before: StoredProfile,
}

impl Subscription {
    fn new() -> Self {
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
        let before = repository.load(ID).expect("load").expect("stored profile");
        Self {
            temporary,
            repository,
            before,
        }
    }

    /// The record a look reads for the subscription.
    fn listed(&self) -> ProfileRecord {
        let mut profiles = self.repository.snapshot().expect("snapshot").profiles;
        assert_eq!(profiles.len(), 1);
        profiles.remove(0)
    }

    fn stored(&self) -> StoredProfile {
        self.repository
            .load(ID)
            .expect("load")
            .expect("stored profile")
    }

    /// Gives the profile a name and an address, as its details in the
    /// dashboard do; no address makes it a local profile.
    fn set(&self, name: &str, address: Option<&str>) {
        self.repository
            .update_metadata(ID, Some(name), address)
            .expect("change the profile");
    }

    fn delete(&self) {
        self.repository
            .delete(ID, cfw_profiles::InvalidSelection::Keep)
            .expect("delete");
    }

    /// Whether the profile changed since the download began.
    async fn changed(&self) -> bool {
        changed_meanwhile(&self.repository, self.before.clone()).await
    }

    /// A repository that cannot be read.
    fn unreadable(&self) -> ProfileRepository {
        let not_a_directory = self.temporary.path().join("file");
        std::fs::write(&not_a_directory, b"").expect("file");
        let unreadable = ProfileRepository::new(&not_a_directory);
        assert!(unreadable.load(ID).is_err());
        unreadable
    }

    /// A vault that answers nothing: no test here lets a download reach it.
    fn vault(&self) -> Arc<ScriptedCredentialVault> {
        Arc::new(ScriptedCredentialVault::new(
            self.temporary.path().join("profiles"),
            Vec::new(),
        ))
    }

    /// The second half of an attempt whose download began from the profile
    /// as it was first stored: `document` is what came from its address, or
    /// why nothing came.
    async fn save(
        &self,
        vault: Arc<ScriptedCredentialVault>,
        document: Result<&str, &str>,
    ) -> Refresh {
        let engine = engine_with_rights_bridge(Arc::new(RestorationRightsBridge::default()));
        let address = validate_subscription_url(ADDRESS).expect("subscription address");
        let downloaded = Downloaded {
            before_fetch: self.before.clone(),
            document: document
                .map(|body| (address, body.to_owned()))
                .map_err(str::to_owned),
        };
        save_download(&engine, &self.repository, vault, Ok(downloaded)).await
    }
}

#[tokio::test]
async fn an_attempt_sets_out_for_the_due_profile_as_it_is_stored_now() {
    let subscription = Subscription::new();
    let due = subscription.listed();
    assert_eq!(due, subscription.before.record);
    assert_eq!(
        stored_now(&subscription.repository, due.clone()).await,
        Ok(subscription.before.clone())
    );

    // Another address is in no list record: the profile is still the one the
    // look read, and its download goes to the address stored now.
    subscription.set("Work", Some(OTHER_ADDRESS));
    let readdressed = stored_now(&subscription.repository, due.clone())
        .await
        .expect("still the due profile");
    assert_eq!(readdressed.record, due);
    assert_eq!(readdressed.source_url.as_deref(), Some(OTHER_ADDRESS));

    // Renamed or made local since the look read it: the attempt ends before
    // anything is downloaded.
    subscription.set("Renamed", Some(ADDRESS));
    assert_eq!(
        stored_now(&subscription.repository, due.clone()).await,
        Err(Refresh::Superseded)
    );
    subscription.set("Work", None);
    assert_eq!(
        stored_now(&subscription.repository, due.clone()).await,
        Err(Refresh::Superseded)
    );
    // Stored again as the look read it, it is the due profile again.
    subscription.set("Work", Some(ADDRESS));
    assert_eq!(
        stored_now(&subscription.repository, due.clone()).await,
        Ok(subscription.before.clone())
    );
    subscription.delete();
    assert_eq!(
        stored_now(&subscription.repository, due).await,
        Err(Refresh::Superseded)
    );
}

#[tokio::test]
async fn a_repository_that_cannot_be_read_fails_the_attempt_before_its_download() {
    let subscription = Subscription::new();
    let unreadable = subscription.unreadable();
    let reason = unreadable.load(ID).expect_err("unreadable").to_string();

    assert_eq!(
        stored_now(&unreadable, subscription.listed()).await,
        Err(Refresh::Left(Outcome::failed(&reason)))
    );
}

#[tokio::test]
async fn a_profile_changed_meanwhile_once_it_is_no_longer_stored_as_the_download_found_it() {
    let subscription = Subscription::new();
    assert!(!subscription.changed().await);

    // Another address alone: the list record is the same, the profile is not.
    subscription.set("Work", Some(OTHER_ADDRESS));
    assert_eq!(subscription.stored().record, subscription.before.record);
    assert!(subscription.changed().await);
    // Given the address it had, it is stored as the download found it.
    subscription.set("Work", Some(ADDRESS));
    assert!(!subscription.changed().await);

    subscription.set("Renamed", Some(ADDRESS));
    assert!(subscription.changed().await);
    subscription.delete();
    assert!(subscription.changed().await);

    // A repository that cannot be read shows no change: the attempt's own
    // failure is what the user is told.
    assert!(!changed_meanwhile(&subscription.unreadable(), subscription.before.clone()).await);
}

#[tokio::test]
async fn a_download_for_a_profile_given_another_address_meanwhile_leaves_nothing() {
    // The document arrived, to be refused as stale, or the previous address
    // did not answer: either way the attempt ends in a failure.
    for document in [Ok(CHANGED), Err("timed out")] {
        let subscription = Subscription::new();
        let vault = subscription.vault();
        subscription.set("Work", Some(OTHER_ADDRESS));
        let readdressed = subscription.stored();

        let refresh = subscription.save(vault.clone(), document).await;

        assert_eq!(refresh, Refresh::Superseded, "{document:?}");
        assert!(vault.requests().is_empty(), "{document:?}");
        assert_eq!(subscription.stored(), readdressed, "{document:?}");
    }
}

#[tokio::test]
async fn a_download_is_saved_over_a_profile_still_stored_as_the_download_found_it() {
    let subscription = Subscription::new();
    let vault = subscription.vault();

    let refresh = subscription.save(vault.clone(), Ok(CHANGED)).await;

    assert_eq!(
        refresh,
        Refresh::Updated(UiUpdatedProfile {
            id: ID.into(),
            name: "Work".into(),
            reset_proxy_groups: Vec::new(),
        })
    );
    let saved = subscription.stored();
    assert_ne!(saved.record.digest, subscription.before.record.digest);
    assert_eq!(saved.source_url.as_deref(), Some(ADDRESS));
    assert!(
        vault.requests().is_empty(),
        "the document names no credential"
    );
}

#[tokio::test]
async fn a_failure_is_kept_for_a_profile_still_stored_as_the_download_found_it() {
    let subscription = Subscription::new();
    let vault = subscription.vault();

    let unreachable = subscription.save(vault.clone(), Err("timed out")).await;
    assert_eq!(unreachable, Refresh::Left(Outcome::failed("timed out")));

    let no_profile = subscription
        .save(vault.clone(), Ok("<html>sign in</html>"))
        .await;
    assert!(
        matches!(
            &no_profile,
            Refresh::Left(Outcome::Failed { error })
                if error.starts_with("profile preparation failed: ")
        ),
        "{no_profile:?}"
    );

    assert!(vault.requests().is_empty());
    assert_eq!(subscription.stored(), subscription.before);
}

#[tokio::test]
async fn an_attempt_that_ended_before_its_download_is_concluded_as_it_ended() {
    let subscription = Subscription::new();
    let engine = engine_with_rights_bridge(Arc::new(RestorationRightsBridge::default()));
    let vault = subscription.vault();

    assert_eq!(
        save_download(
            &engine,
            &subscription.repository,
            vault.clone(),
            Err(Refresh::Superseded)
        )
        .await,
        Refresh::Superseded
    );
    assert_eq!(
        save_download(
            &engine,
            &subscription.repository,
            vault.clone(),
            Err(Refresh::Left(Outcome::failed("unreadable")))
        )
        .await,
        Refresh::Left(Outcome::failed("unreadable"))
    );
    assert!(vault.requests().is_empty());
    assert_eq!(subscription.stored(), subscription.before);
}

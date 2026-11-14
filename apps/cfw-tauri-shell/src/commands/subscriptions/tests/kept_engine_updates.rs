//! An update that keeps the running engine: a changed document of the running
//! profile is declined before the vault is written, the document the engine
//! already runs is prepared, and any other profile is updated as by hand. An
//! update by hand restarts the engine onto the changed document.

use std::sync::Arc;

use cfw_engine_api::{EngineMode, EngineState};

use super::*;
use crate::commands::subscriptions::auto_update::save_keeping_engine;
use crate::engine::tests::{RestorationRightsBridge, engine_with_rights_bridge};
use crate::engine::{KeptEngineChangeError, ManagedEngine};

const OLD_BODY: &str = "trojan://old-secret@proxy.example.com:443?sni=proxy.example.com#Work";
const NEW_SECRET_BODY: &str =
    "trojan://new-secret@proxy.example.com:443?sni=proxy.example.com#Work";
const NEW_NODE_BODY: &str = "trojan://old-secret@proxy.example.com:443?sni=proxy.example.com#Work\ntrojan://old-secret@second.example.com:443?sni=second.example.com#Second";
const STALE: &str = "subscription profile changed while downloading; the response was not applied";

/// A stored subscription with one credential.
fn seeded(repository: &ProfileRepository, selected: bool) -> StoredProfile {
    seeded_with(repository, selected, &EngineSettings::default())
}

fn seeded_with(
    repository: &ProfileRepository,
    selected: bool,
    settings: &EngineSettings,
) -> StoredProfile {
    let initial = validated_subscription_import_with_namespace(
        OLD_BODY,
        settings,
        Uuid::parse_str("77777777-7777-4777-8777-777777777777").expect("credential namespace"),
    )
    .expect("initial subscription");
    repository
        .import_with_id_and_source(
            TRANSACTION_PROFILE_ID,
            Some("Work"),
            &initial.profile,
            Some(TRANSACTION_SOURCE_URL),
        )
        .expect("seed subscription profile");
    if selected {
        repository
            .select(TRANSACTION_PROFILE_ID)
            .expect("select the profile");
    }
    stored(repository)
}

fn stored(repository: &ProfileRepository) -> StoredProfile {
    repository
        .load(TRANSACTION_PROFILE_ID)
        .expect("load profile")
        .expect("stored profile")
}

fn download(before_fetch: &StoredProfile, body: &str) -> FetchedUpdate {
    FetchedUpdate {
        before_fetch: before_fetch.clone(),
        target: validate_subscription_url(TRANSACTION_SOURCE_URL).expect("subscription address"),
        body: body.to_owned(),
    }
}

#[tokio::test]
async fn a_changed_document_of_the_running_profile_is_declined_before_the_vault_is_written() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let before = seeded(&repository, true);
    let vault = ScriptedCredentialVault::new(profiles_dir, Vec::new());

    let error = prepare_update(
        &repository,
        &vault,
        &download(&before, NEW_NODE_BODY),
        &EngineSettings::default(),
        RunningProfile::Kept,
    )
    .await
    .err()
    .expect("the running profile is kept");

    assert_eq!(error, UpdatePreparationError::RunningProfileChanged);
    assert!(
        vault.requests().is_empty(),
        "a document that cannot be committed leaves nothing in the vault"
    );
    assert_eq!(stored(&repository), before);
}

#[tokio::test]
async fn the_same_document_under_other_credentials_is_declined_without_a_rotation() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let before = seeded(&repository, true);
    let vault = RotationCredentialVault::new(profiles_dir, RotationVaultMode::ImmutableThenEcho);

    let error = prepare_update(
        &repository,
        &vault,
        &download(&before, NEW_SECRET_BODY),
        &EngineSettings::default(),
        RunningProfile::Kept,
    )
    .await
    .err()
    .expect("the running profile is kept");

    assert_eq!(error, UpdatePreparationError::RunningProfileChanged);
    let requests = vault.requests();
    assert_eq!(
        requests.len(),
        1,
        "the vault is asked once and no fresh reference is provisioned"
    );
    assert_eq!(requests[0].profile_digest, before.record.digest);
    assert_eq!(
        requests[0].required_references,
        before.profile.credential_references_in_outbound_order()
    );
    assert_eq!(stored(&repository), before);
}

#[tokio::test]
async fn the_document_the_engine_already_runs_is_prepared_and_saved_again() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let before = seeded(&repository, true);
    let vault = ScriptedCredentialVault::new(
        profiles_dir,
        vec![Ok(CredentialVaultReceipt {
            profile_id: TRANSACTION_PROFILE_ID.into(),
            profile_digest: before.record.digest.clone(),
        })],
    );

    let candidate = prepare_update(
        &repository,
        &vault,
        &download(&before, OLD_BODY),
        &EngineSettings::default(),
        RunningProfile::Kept,
    )
    .await
    .expect("the same document is prepared");

    assert!(candidate.activate);
    assert_eq!(candidate.profile_id, TRANSACTION_PROFILE_ID);
    assert_eq!(candidate.profile.digest(), before.profile.digest());
    assert_eq!(
        candidate.profile.proxy_selections(),
        before.profile.proxy_selections()
    );
    let (saved, reset_groups) = (candidate.commit)().expect("commit");
    assert_eq!(saved.digest, before.record.digest);
    assert!(reset_groups.is_empty());
    assert_eq!(vault.requests().len(), 1);
    let after = stored(&repository);
    assert_eq!(after.profile, before.profile);
    assert_eq!(after.source_url, before.source_url);
    assert!(after.record.created_epoch_secs >= before.record.created_epoch_secs);
}

#[tokio::test]
async fn a_profile_the_engine_does_not_run_is_updated_while_the_engine_is_on() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let before = seeded(&repository, false);
    let vault = RotationCredentialVault::new(profiles_dir, RotationVaultMode::ImmutableThenEcho);

    let candidate = prepare_update(
        &repository,
        &vault,
        &download(&before, NEW_SECRET_BODY),
        &EngineSettings::default(),
        RunningProfile::Kept,
    )
    .await
    .expect("another profile is updated with one rotation");

    assert!(!candidate.activate);
    assert_eq!(vault.requests().len(), 2);
    (candidate.commit)().expect("commit");
    assert_ne!(stored(&repository).record.digest, before.record.digest);
}

#[tokio::test]
async fn an_update_by_hand_replaces_the_selected_profile_whatever_the_engine_runs() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let before = seeded(&repository, true);
    let vault = RotationCredentialVault::new(profiles_dir, RotationVaultMode::ImmutableThenEcho);

    let candidate = prepare_update(
        &repository,
        &vault,
        &download(&before, NEW_SECRET_BODY),
        &EngineSettings::default(),
        RunningProfile::Replaceable,
    )
    .await
    .expect("an update by hand rotates and replaces");

    assert!(candidate.activate);
    assert_eq!(vault.requests().len(), 2);
    assert_ne!(candidate.profile.digest(), before.profile.digest());
}

#[tokio::test]
async fn a_profile_renamed_or_given_another_address_since_the_download_began_is_left_alone() {
    const OTHER_ADDRESS: &str = "https://subscription.example/other";
    for (name, address) in [("Renamed", TRANSACTION_SOURCE_URL), ("Work", OTHER_ADDRESS)] {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let profiles_dir = temporary.path().join("profiles");
        let repository = ProfileRepository::new(&profiles_dir);
        let before = seeded(&repository, true);
        let fetched = download(&before, NEW_NODE_BODY);
        repository
            .update_metadata(TRANSACTION_PROFILE_ID, Some(name), Some(address))
            .expect("change the profile while downloading");
        let changed = stored(&repository);
        assert_ne!(changed, before, "{name} {address}");
        let vault = ScriptedCredentialVault::new(profiles_dir, Vec::new());

        for running_profile in [RunningProfile::Replaceable, RunningProfile::Kept] {
            let error = prepare_update(
                &repository,
                &vault,
                &fetched,
                &EngineSettings::default(),
                running_profile,
            )
            .await
            .err()
            .expect("a stale download is refused");
            assert_eq!(
                error,
                UpdatePreparationError::Failed(STALE.into()),
                "{name} {address}"
            );
            assert_eq!(error.to_string(), STALE);
        }
        assert!(vault.requests().is_empty(), "{name} {address}");
        assert_eq!(stored(&repository), changed, "{name} {address}");
    }
}

#[tokio::test]
async fn the_groups_whose_chosen_node_is_gone_are_named_with_the_saved_profile() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let two_nodes = validated_subscription_import_with_namespace(
        NEW_NODE_BODY,
        &EngineSettings::default(),
        Uuid::parse_str("77777777-7777-4777-8777-777777777777").expect("credential namespace"),
    )
    .expect("initial subscription");
    let selector = two_nodes
        .profile
        .app_selector()
        .expect("two nodes are offered by the app's selector");
    let chosen = two_nodes
        .profile
        .with_selected_outbound(&selector.tag, "Second")
        .expect("choose the second node");
    repository
        .import_with_id_and_source(
            TRANSACTION_PROFILE_ID,
            Some("Work"),
            &chosen,
            Some(TRANSACTION_SOURCE_URL),
        )
        .expect("seed subscription profile");
    let before = stored(&repository);
    assert_eq!(
        before.profile.proxy_selections().get(&selector.tag),
        Some(&"Second".to_owned())
    );
    let vault = RotationCredentialVault::new(profiles_dir, RotationVaultMode::ImmutableThenEcho);

    // The download no longer lists the chosen node.
    let candidate = prepare_update(
        &repository,
        &vault,
        &download(&before, OLD_BODY),
        &EngineSettings::default(),
        RunningProfile::Replaceable,
    )
    .await
    .expect("the update is prepared");
    let (saved, reset_groups) = (candidate.commit)().expect("commit");

    assert_eq!(reset_groups, vec![selector.tag]);
    let after = stored(&repository);
    assert_eq!(after.record.digest, saved.digest);
    assert!(after.profile.proxy_selections().is_empty());
}

/// A test engine and the selected subscription stored under its settings.
struct Background {
    _temporary: tempfile::TempDir,
    profiles_dir: PathBuf,
    repository: ProfileRepository,
    engine: ManagedEngine,
    rights: Arc<RestorationRightsBridge>,
    before: StoredProfile,
}

impl Background {
    fn new() -> Self {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let profiles_dir = temporary.path().join("profiles");
        let repository = ProfileRepository::new(&profiles_dir);
        let rights = Arc::new(RestorationRightsBridge::default());
        let engine = engine_with_rights_bridge(rights.clone());
        let before = seeded_with(
            &repository,
            true,
            &engine.engine_settings().expect("engine settings"),
        );
        Self {
            _temporary: temporary,
            profiles_dir,
            repository,
            engine,
            rights,
            before,
        }
    }

    /// Starts the engine in System Proxy mode on the stored profile.
    async fn start(&self) -> cfw_engine_api::EngineSnapshot {
        self.engine
            .coordinator
            .set_mode(
                EngineMode::SystemProxy,
                self.before.record.id.clone(),
                self.before.profile.clone(),
                self.engine.engine_settings().expect("engine settings"),
            )
            .await
            .expect("running engine")
    }

    async fn save(
        &self,
        vault: impl CredentialVaultProvisioner,
        body: &str,
    ) -> Result<(ProfileImportResult, Vec<String>), KeptEngineChangeError> {
        save_keeping_engine(
            &self.engine,
            self.repository.clone(),
            vault,
            download(&self.before, body),
        )
        .await
    }
}

#[tokio::test]
async fn a_changed_subscription_of_the_running_profile_changes_nothing_at_all() {
    let background = Background::new();
    let running = background.start().await;
    let revision = background.engine.mode_intent_revision().expect("revision");
    let vault = Arc::new(ScriptedCredentialVault::new(
        background.profiles_dir.clone(),
        Vec::new(),
    ));

    let result = background.save(vault.clone(), NEW_NODE_BODY).await;

    assert_eq!(result, Err(KeptEngineChangeError::RunningEngineKept));
    assert!(vault.requests().is_empty(), "no credential is staged");
    assert_eq!(stored(&background.repository), background.before);
    assert_eq!(background.engine.coordinator.snapshot(), running);
    assert!(
        background.rights.requests().is_empty(),
        "macOS is asked for nothing"
    );
    assert_eq!(background.engine.mode_intent_revision(), Ok(revision));
}

#[tokio::test]
async fn the_subscription_the_engine_runs_is_saved_again_without_a_restart() {
    let background = Background::new();
    let running = background.start().await;
    let vault = Arc::new(ScriptedCredentialVault::new(
        background.profiles_dir.clone(),
        vec![Ok(CredentialVaultReceipt {
            profile_id: TRANSACTION_PROFILE_ID.into(),
            profile_digest: background.before.record.digest.clone(),
        })],
    ));

    let (saved, reset_groups) = background
        .save(vault.clone(), OLD_BODY)
        .await
        .expect("the same document is saved again");

    assert_eq!(saved.id, TRANSACTION_PROFILE_ID);
    assert_eq!(saved.digest, background.before.record.digest);
    assert!(reset_groups.is_empty());
    assert_eq!(vault.requests().len(), 1);
    assert_eq!(
        stored(&background.repository).profile,
        background.before.profile
    );
    assert_eq!(
        background.engine.coordinator.snapshot(),
        running,
        "the same generation keeps running"
    );
    assert!(background.rights.requests().is_empty());
}

#[tokio::test]
async fn with_the_engine_off_a_changed_subscription_replaces_the_selected_profile() {
    let background = Background::new();
    let vault = Arc::new(RotationCredentialVault::new(
        background.profiles_dir.clone(),
        RotationVaultMode::ImmutableThenEcho,
    ));

    let (saved, _reset_groups) = background
        .save(vault.clone(), NEW_SECRET_BODY)
        .await
        .expect("an off engine lets the selected profile be replaced");

    assert_eq!(
        vault.requests().len(),
        2,
        "replaced as an update by hand is, with one rotation"
    );
    let after = stored(&background.repository);
    assert_eq!(after.record.digest, saved.digest);
    assert_ne!(after.record.digest, background.before.record.digest);
    assert_eq!(
        background.engine.coordinator.snapshot().state,
        EngineState::Off
    );
    assert!(background.rights.requests().is_empty());
}

#[tokio::test]
async fn an_update_by_hand_restarts_the_running_engine_onto_the_changed_subscription() {
    let background = Background::new();
    let running = background.start().await;
    let vault = Arc::new(RotationCredentialVault::new(
        background.profiles_dir.clone(),
        RotationVaultMode::ImmutableThenEcho,
    ));
    let repository = background.repository.clone();
    let fetched = download(&background.before, NEW_NODE_BODY);
    let by_hand = vault.clone();

    let (saved, reset_groups) = crate::engine::apply_profile_change_admitted_by(
        &background.engine,
        |_mode| Ok(()),
        move |settings| prepare_update_by_hand(repository, by_hand, fetched, settings),
    )
    .await
    .expect("an update by hand replaces the profile the engine runs");

    assert!(reset_groups.is_empty());
    assert_eq!(vault.requests().len(), 2, "one rotation");
    let after = stored(&background.repository);
    assert_eq!(after.record.digest, saved.digest);
    assert_ne!(after.record.digest, background.before.record.digest);
    let restarted = background.engine.coordinator.snapshot();
    assert_eq!(restarted.desired_mode, EngineMode::SystemProxy);
    assert!(
        restarted.generation > running.generation,
        "the engine was restarted"
    );
    assert_ne!(restarted.config_digest, running.config_digest);
    assert_eq!(
        background.rights.requests(),
        [false],
        "macOS authorizes the System Proxy change once"
    );
}

#[tokio::test]
async fn a_download_that_is_no_profile_fails_and_is_told_apart_from_a_waiting_change() {
    let background = Background::new();
    let running = background.start().await;
    let vault = Arc::new(ScriptedCredentialVault::new(
        background.profiles_dir.clone(),
        Vec::new(),
    ));

    let result = background.save(vault.clone(), "<html>sign in</html>").await;

    let Err(KeptEngineChangeError::Failed(reason)) = result else {
        panic!("a failure, not a waiting change: {result:?}");
    };
    assert!(
        reason.starts_with("profile preparation failed: "),
        "{reason}"
    );
    assert!(vault.requests().is_empty());
    assert_eq!(stored(&background.repository), background.before);
    assert_eq!(background.engine.coordinator.snapshot(), running);
}

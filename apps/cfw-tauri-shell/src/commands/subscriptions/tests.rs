use cfw_singbox_config::MAX_PROFILE_BYTES;
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use cfw_engine_api::{
    CredentialGarbageCollectionCommitFuture, CredentialGarbageCollectionCommitRequest,
    CredentialGarbageCollectionPreviewFuture, CredentialGarbageCollectionRequest,
    CredentialPresenceFuture, CredentialPresenceRequest, CredentialProvisionRequest, CredentialRef,
    CredentialVaultError, CredentialVaultFuture, CredentialVaultReceipt,
};
use sha2::{Digest as _, Sha256};

use super::fetch::*;
use super::*;
use reqwest::Client;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{CONTENT_ENCODING, HeaderMap, HeaderValue};
use reqwest::redirect::Policy;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

const PROFILE_JSON: &str = r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#;
const DIRECT_PROFILE_JSON: &str =
    r#"{"route":{"final":"direct"},"outbounds":[{"tag":"direct","type":"direct"}]}"#;
const TRANSACTION_PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TRANSACTION_SOURCE_URL: &str = "https://subscription.example/current";
const IMPORT_SECRET: &str = "subscription-secret-must-not-leak";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProvisionRequestSnapshot {
    profile_id: String,
    profile_digest: String,
    required_references: Vec<CredentialRef>,
    entries: Vec<(CredentialRef, [u8; 32])>,
    repository_profile_visible: bool,
}

fn provision_request_snapshot(
    profiles_dir: &Path,
    request: &CredentialProvisionRequest<'_>,
) -> ProvisionRequestSnapshot {
    let entries = request
        .entries()
        .iter()
        .map(|entry| {
            let digest = Sha256::digest(entry.secret().expose_to_vault().as_bytes());
            (entry.reference().clone(), digest.into())
        })
        .collect();
    let profile_path = profiles_dir.join(format!("{}.profile.json", request.profile_id()));
    let repository_profile_visible = match std::fs::symlink_metadata(profile_path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("observe repository before vault response: {error}"),
    };
    ProvisionRequestSnapshot {
        profile_id: request.audience().profile_id().to_owned(),
        profile_digest: request.audience().profile_digest().to_owned(),
        required_references: request.required_references().to_vec(),
        entries,
        repository_profile_visible,
    }
}

#[derive(Debug)]
struct ScriptedCredentialVault {
    profiles_dir: PathBuf,
    responses: Mutex<VecDeque<Result<CredentialVaultReceipt, CredentialVaultError>>>,
    requests: Mutex<Vec<ProvisionRequestSnapshot>>,
    garbage_collection_requests: Mutex<usize>,
    provision_entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    provision_release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl ScriptedCredentialVault {
    fn new(
        profiles_dir: PathBuf,
        responses: Vec<Result<CredentialVaultReceipt, CredentialVaultError>>,
    ) -> Self {
        Self {
            profiles_dir,
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
            garbage_collection_requests: Mutex::new(0),
            provision_entered: Mutex::new(None),
            provision_release: Mutex::new(None),
        }
    }

    fn new_paused(
        profiles_dir: PathBuf,
        response: Result<CredentialVaultReceipt, CredentialVaultError>,
    ) -> (
        Self,
        std::sync::mpsc::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
        (
            Self {
                profiles_dir,
                responses: Mutex::new(VecDeque::from([response])),
                requests: Mutex::new(Vec::new()),
                garbage_collection_requests: Mutex::new(0),
                provision_entered: Mutex::new(Some(entered_sender)),
                provision_release: Mutex::new(Some(release_receiver)),
            },
            entered_receiver,
            release_sender,
        )
    }

    fn requests(&self) -> Vec<ProvisionRequestSnapshot> {
        self.requests.lock().expect("request lock").clone()
    }

    fn garbage_collection_requests(&self) -> usize {
        *self
            .garbage_collection_requests
            .lock()
            .expect("garbage collection request lock")
    }
}

impl CredentialVaultProvisioner for ScriptedCredentialVault {
    fn provision_profile_credentials<'a>(
        &'a self,
        request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a> {
        let request_snapshot = provision_request_snapshot(&self.profiles_dir, &request);
        self.requests
            .lock()
            .expect("request lock")
            .push(request_snapshot);
        let response = self
            .responses
            .lock()
            .expect("response lock")
            .pop_front()
            .unwrap_or(Err(CredentialVaultError::Internal));
        if let Some(sender) = self
            .provision_entered
            .lock()
            .expect("provision entered lock")
            .take()
        {
            sender.send(()).expect("signal paused provision");
        }
        let release = self
            .provision_release
            .lock()
            .expect("provision release lock")
            .take();
        Box::pin(async move {
            if let Some(release) = release {
                release.await.map_err(|_| CredentialVaultError::Internal)?;
            }
            response
        })
    }

    fn query_profile_credentials(
        &self,
        _request: CredentialPresenceRequest,
    ) -> CredentialPresenceFuture<'_> {
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }

    fn preview_credential_garbage_collection(
        &self,
        _request: CredentialGarbageCollectionRequest,
    ) -> CredentialGarbageCollectionPreviewFuture<'_> {
        *self
            .garbage_collection_requests
            .lock()
            .expect("garbage collection request lock") += 1;
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }

    fn commit_credential_garbage_collection(
        &self,
        _request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_> {
        *self
            .garbage_collection_requests
            .lock()
            .expect("garbage collection request lock") += 1;
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }
}

#[derive(Debug, Clone, Copy)]
enum RotationVaultMode {
    ImmutableThenEcho,
    AlwaysOutcomeUnknown,
}

#[derive(Debug)]
struct RotationCredentialVault {
    profiles_dir: PathBuf,
    mode: RotationVaultMode,
    requests: Mutex<Vec<ProvisionRequestSnapshot>>,
}

impl RotationCredentialVault {
    fn new(profiles_dir: PathBuf, mode: RotationVaultMode) -> Self {
        Self {
            profiles_dir,
            mode,
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<ProvisionRequestSnapshot> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl CredentialVaultProvisioner for RotationCredentialVault {
    fn provision_profile_credentials<'a>(
        &'a self,
        request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a> {
        let request_snapshot = provision_request_snapshot(&self.profiles_dir, &request);
        let receipt = CredentialVaultReceipt {
            profile_id: request_snapshot.profile_id.clone(),
            profile_digest: request_snapshot.profile_digest.clone(),
        };
        let call = {
            let mut requests = self.requests.lock().expect("request lock");
            let call = requests.len();
            requests.push(request_snapshot);
            call
        };
        let response = match (self.mode, call) {
            (RotationVaultMode::ImmutableThenEcho, 0) => {
                Err(CredentialVaultError::ImmutableConflict)
            }
            (RotationVaultMode::ImmutableThenEcho, 1) => Ok(receipt),
            (RotationVaultMode::ImmutableThenEcho, _) => Err(CredentialVaultError::Internal),
            (RotationVaultMode::AlwaysOutcomeUnknown, _) => {
                Err(CredentialVaultError::OutcomeUnknown)
            }
        };
        Box::pin(async move { response })
    }

    fn query_profile_credentials(
        &self,
        _request: CredentialPresenceRequest,
    ) -> CredentialPresenceFuture<'_> {
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }

    fn preview_credential_garbage_collection(
        &self,
        _request: CredentialGarbageCollectionRequest,
    ) -> CredentialGarbageCollectionPreviewFuture<'_> {
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }

    fn commit_credential_garbage_collection(
        &self,
        _request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_> {
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }
}

fn credential_subscription(namespace: &str) -> crate::subscription_import::ImportedSubscription {
    validated_subscription_import_with_namespace(
        &format!("trojan://{IMPORT_SECRET}@proxy.example.com:443?sni=proxy.example.com#Work"),
        &EngineSettings::default(),
        Uuid::parse_str(namespace).expect("credential namespace"),
    )
    .expect("credential subscription")
}

fn successful_receipt(
    profile_id: &str,
    imported: &crate::subscription_import::ImportedSubscription,
) -> CredentialVaultReceipt {
    CredentialVaultReceipt {
        profile_id: profile_id.into(),
        profile_digest: imported.profile.digest().to_owned(),
    }
}

fn selected_direct_profile(repository: &ProfileRepository) -> StoredProfile {
    let profile = ValidatedSingBoxProfile::parse(DIRECT_PROFILE_JSON).expect("direct profile");
    repository
        .import_with_id_and_source(
            TRANSACTION_PROFILE_ID,
            Some("Original"),
            &profile,
            Some(TRANSACTION_SOURCE_URL),
        )
        .expect("import original profile");
    repository
        .select(TRANSACTION_PROFILE_ID)
        .expect("select original profile");
    repository
        .load(TRANSACTION_PROFILE_ID)
        .expect("load original profile")
        .expect("stored original profile")
}

mod import_audience;
mod local_sources;
mod profile_documents;
mod subscription_updates;
mod transport_policy;

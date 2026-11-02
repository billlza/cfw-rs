use std::{
    pin::pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use cfw_singbox_config::{CredentialSecret, EngineSettings};

use super::*;
use crate::{
    CredentialPresence, CredentialProvision, CredentialVaultReceipt,
    test_support::{CREDENTIAL_ID, PROFILE_ID, VAULT_REVISION, trojan_profile, trojan_reference},
};

/// Polls a future the fake vault completes without waiting.
fn ready<T>(future: impl Future<Output = T>) -> T {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the fake vault answers at once"),
    }
}

#[derive(Default)]
struct RecordingVault {
    calls: Mutex<Vec<&'static str>>,
}

impl RecordingVault {
    fn record(&self, call: &'static str) {
        self.calls.lock().expect("call log").push(call);
    }
}

impl CredentialVaultProvisioner for RecordingVault {
    fn provision_profile_credentials<'a>(
        &'a self,
        request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a> {
        self.record("provision");
        let receipt = CredentialVaultReceipt {
            profile_id: request.profile_id().to_owned(),
            profile_digest: "ef".repeat(32),
        };
        Box::pin(async move { Ok(receipt) })
    }

    fn query_profile_credentials(
        &self,
        request: CredentialPresenceRequest,
    ) -> CredentialPresenceFuture<'_> {
        self.record("query");
        let presence = request
            .references()
            .iter()
            .cloned()
            .map(|reference| CredentialPresence {
                reference,
                present: true,
            })
            .collect();
        Box::pin(async move { Ok(presence) })
    }

    fn preview_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionRequest,
    ) -> CredentialGarbageCollectionPreviewFuture<'_> {
        self.record("preview");
        let preview = CredentialGarbageCollectionPreview {
            snapshot_digest: request.snapshot_digest().to_owned(),
            vault_revision: VAULT_REVISION.into(),
            orphan_bindings: Vec::new(),
            orphan_count: 0,
        };
        Box::pin(async move { Ok(preview) })
    }

    fn commit_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_> {
        self.record("commit");
        let receipt = CredentialGarbageCollectionReceipt {
            vault_revision: request.expected_vault_revision().to_owned(),
            deleted_count: 0,
        };
        Box::pin(async move { Ok(receipt) })
    }
}

#[test]
fn a_shared_vault_forwards_every_operation_to_its_owner() {
    type Shared = Arc<RecordingVault>;
    let vault = Shared::default();
    let profile = trojan_profile(CREDENTIAL_ID, 443);
    let reference = trojan_reference(CREDENTIAL_ID);
    let secret = CredentialSecret::new("secret").expect("bounded secret");
    let provision = CredentialProvisionRequest::new(
        PROFILE_ID,
        &profile,
        vec![CredentialProvision::new(&reference, secret)],
    )
    .expect("provision request");
    assert_eq!(
        ready(
            <Shared as CredentialVaultProvisioner>::provision_profile_credentials(
                &vault, provision
            )
        )
        .expect("receipt")
        .profile_id,
        PROFILE_ID
    );

    let query = CredentialPresenceRequest::new(PROFILE_ID, &profile).expect("query");
    assert_eq!(
        ready(<Shared as CredentialVaultProvisioner>::query_profile_credentials(&vault, query)),
        Ok(vec![CredentialPresence {
            reference,
            present: true,
        }])
    );

    let snapshot =
        CredentialGarbageCollectionRequest::new("ab".repeat(32), Vec::new()).expect("snapshot");
    let preview = ready(
        <Shared as CredentialVaultProvisioner>::preview_credential_garbage_collection(
            &vault,
            snapshot.clone(),
        ),
    )
    .expect("preview");
    let commit = CredentialGarbageCollectionCommitRequest::new(snapshot, &preview).expect("commit");
    assert_eq!(
        ready(
            <Shared as CredentialVaultProvisioner>::commit_credential_garbage_collection(
                &vault, commit
            )
        )
        .expect("receipt")
        .vault_revision,
        VAULT_REVISION
    );
    assert_eq!(
        *vault.calls.lock().expect("call log"),
        ["provision", "query", "preview", "commit"]
    );
}

#[test]
fn a_vault_without_rebinding_reports_it_unavailable() {
    let vault = Arc::new(RecordingVault::default());
    let profile = trojan_profile(CREDENTIAL_ID, 443);
    let rebind =
        CredentialRebindRequest::new(PROFILE_ID, &profile, &profile, &EngineSettings::default())
            .expect("rebind request");
    assert_eq!(
        ready(
            <Arc<RecordingVault> as CredentialVaultProvisioner>::rebind_profile_credentials(
                &vault, rebind
            )
        ),
        Err(CredentialVaultError::Unavailable)
    );
    assert!(vault.calls.lock().expect("call log").is_empty());
}

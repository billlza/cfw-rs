use cfw_engine_api::{
    CredentialGarbageCollectionCommitFuture, CredentialGarbageCollectionCommitRequest,
    CredentialGarbageCollectionPreviewFuture, CredentialGarbageCollectionRequest,
    CredentialPresenceRequest, CredentialPresenceWireRequest, CredentialProvisionRequest,
    CredentialRef, CredentialVaultError, CredentialVaultFuture, CredentialVaultProvisioner,
    NativeBridgeCommand, NativeBridgeResult,
};
use serde::Serialize;
use zeroize::Zeroize;

use crate::{NativeBridgeError, NativeBridgeErrorCode};

use super::NativeFrameworkBridge;

#[derive(Serialize)]
struct SensitiveRequestEnvelope {
    schema_version: u16,
    request_id: uuid::Uuid,
    command: SensitiveCommand,
}

#[derive(Serialize)]
#[serde(tag = "opcode", content = "payload", rename_all = "snake_case")]
enum SensitiveCommand {
    ProvisionCredentials { request: SensitiveProvisionRequest },
}

#[derive(Serialize)]
struct SensitiveProvisionRequest {
    profile_id: String,
    required_references: Vec<CredentialRef>,
    entries: Vec<SensitiveProvisionEntry>,
}

impl Drop for SensitiveProvisionRequest {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            entry.secret.zeroize();
        }
    }
}

#[derive(Serialize)]
struct SensitiveProvisionEntry {
    reference: CredentialRef,
    secret: String,
}

impl std::fmt::Debug for SensitiveProvisionEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SensitiveProvisionEntry")
            .field("reference", &self.reference)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SensitiveProvisionEntry {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl CredentialVaultProvisioner for NativeFrameworkBridge {
    fn provision_profile_credentials<'a>(
        &'a self,
        request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a> {
        Box::pin(async move {
            let request_id = uuid::Uuid::new_v4();
            let sensitive_request = SensitiveRequestEnvelope {
                schema_version: cfw_engine_api::ENGINE_PROTOCOL_VERSION,
                request_id,
                command: SensitiveCommand::ProvisionCredentials {
                    request: SensitiveProvisionRequest {
                        profile_id: request.profile_id().to_owned(),
                        required_references: request.required_references().to_vec(),
                        entries: request
                            .entries()
                            .iter()
                            .map(|entry| SensitiveProvisionEntry {
                                reference: entry.reference().clone(),
                                secret: entry.secret().expose_to_vault().to_owned(),
                            })
                            .collect(),
                    },
                },
            };
            let request_bytes = serde_json::to_vec(&sensitive_request)
                .map_err(|_| CredentialVaultError::InvalidMaterial)?;
            drop(sensitive_request);
            match self
                .invoke_bytes(request_id, request_bytes)
                .await
                .map_err(map_vault_error)?
            {
                NativeBridgeResult::CredentialReceipt(receipt) => Ok(receipt),
                _ => Err(CredentialVaultError::Internal),
            }
        })
    }

    fn query_profile_credentials(
        &self,
        request: CredentialPresenceRequest,
    ) -> cfw_engine_api::CredentialPresenceFuture<'_> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::QueryCredentialPresence {
                    request: CredentialPresenceWireRequest::from(request),
                })
                .await
                .map_err(map_vault_error)?
            {
                NativeBridgeResult::CredentialPresence(presence) => Ok(presence),
                _ => Err(CredentialVaultError::Internal),
            }
        })
    }

    fn preview_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionRequest,
    ) -> CredentialGarbageCollectionPreviewFuture<'_> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::PreviewCredentialGarbageCollection { request })
                .await
                .map_err(map_vault_error)?
            {
                NativeBridgeResult::CredentialGarbageCollectionPreview(preview) => Ok(preview),
                _ => Err(CredentialVaultError::Internal),
            }
        })
    }

    fn commit_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::CommitCredentialGarbageCollection { request })
                .await
                .map_err(map_vault_error)?
            {
                NativeBridgeResult::CredentialGarbageCollectionReceipt(receipt) => Ok(receipt),
                _ => Err(CredentialVaultError::Internal),
            }
        })
    }
}

fn map_vault_error(error: NativeBridgeError) -> CredentialVaultError {
    match error.code {
        NativeBridgeErrorCode::PermissionDenied => CredentialVaultError::AccessDenied,
        NativeBridgeErrorCode::CredentialConflict => CredentialVaultError::ImmutableConflict,
        NativeBridgeErrorCode::CredentialVaultMissing => CredentialVaultError::MissingVault,
        NativeBridgeErrorCode::CredentialGcConflict => CredentialVaultError::ConcurrentModification,
        NativeBridgeErrorCode::ConfigurationRejected => CredentialVaultError::InvalidMaterial,
        NativeBridgeErrorCode::IdentityRejected => CredentialVaultError::Corrupt,
        NativeBridgeErrorCode::Busy
        | NativeBridgeErrorCode::ApprovalDenied
        | NativeBridgeErrorCode::CredentialsUnavailable
        | NativeBridgeErrorCode::Timeout
        | NativeBridgeErrorCode::Unavailable => CredentialVaultError::Unavailable,
        NativeBridgeErrorCode::Internal => CredentialVaultError::Internal,
    }
}

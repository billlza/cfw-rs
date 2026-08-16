use cfw_engine_api::{
    CredentialAudience, CredentialGarbageCollectionCommitFuture,
    CredentialGarbageCollectionCommitRequest, CredentialGarbageCollectionPreviewFuture,
    CredentialGarbageCollectionRequest, CredentialPresenceRequest, CredentialPresenceWireRequest,
    CredentialProvisionRequest, CredentialRef, CredentialVaultError, CredentialVaultFuture,
    CredentialVaultProvisioner, NativeBridgeCommand, NativeBridgeResult,
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
    audience: CredentialAudience,
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

fn sensitive_provision_envelope(
    request_id: uuid::Uuid,
    request: &CredentialProvisionRequest<'_>,
) -> SensitiveRequestEnvelope {
    SensitiveRequestEnvelope {
        schema_version: cfw_engine_api::ENGINE_PROTOCOL_VERSION,
        request_id,
        command: SensitiveCommand::ProvisionCredentials {
            request: SensitiveProvisionRequest {
                audience: request.audience().clone(),
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
    }
}

impl CredentialVaultProvisioner for NativeFrameworkBridge {
    fn provision_profile_credentials<'a>(
        &'a self,
        request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a> {
        Box::pin(async move {
            let request_id = uuid::Uuid::new_v4();
            let sensitive_request = sensitive_provision_envelope(request_id, &request);
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
        NativeBridgeErrorCode::Timeout => CredentialVaultError::OutcomeUnknown,
        NativeBridgeErrorCode::PermissionDenied => CredentialVaultError::AccessDenied,
        NativeBridgeErrorCode::CredentialConflict => CredentialVaultError::ImmutableConflict,
        NativeBridgeErrorCode::CredentialVaultMissing => CredentialVaultError::MissingVault,
        NativeBridgeErrorCode::CredentialMigrationRequired => {
            CredentialVaultError::MigrationRequired
        }
        NativeBridgeErrorCode::CredentialGcConflict => CredentialVaultError::ConcurrentModification,
        NativeBridgeErrorCode::ConfigurationRejected => CredentialVaultError::InvalidMaterial,
        NativeBridgeErrorCode::IdentityRejected => CredentialVaultError::Corrupt,
        NativeBridgeErrorCode::Busy
        | NativeBridgeErrorCode::ResourceExhausted
        | NativeBridgeErrorCode::JournalCapacityExhausted
        | NativeBridgeErrorCode::ApprovalDenied
        | NativeBridgeErrorCode::CredentialsUnavailable
        | NativeBridgeErrorCode::ProxyAgentApprovalRequired
        | NativeBridgeErrorCode::GlobalAuthorityUnavailable
        | NativeBridgeErrorCode::GlobalAuthorityRegistrationRequired
        | NativeBridgeErrorCode::GlobalAuthorityApprovalRequired
        | NativeBridgeErrorCode::GlobalAuthorityIdentityRejected
        | NativeBridgeErrorCode::GlobalAuthorityProtocolMismatch
        | NativeBridgeErrorCode::GlobalAuthorityRecovering
        | NativeBridgeErrorCode::GlobalAuthorityTimeout
        | NativeBridgeErrorCode::GlobalAuthorityInterrupted
        | NativeBridgeErrorCode::GlobalLeaseConflict
        | NativeBridgeErrorCode::ReplayRejected
        | NativeBridgeErrorCode::StaleOperation
        | NativeBridgeErrorCode::TicketExpired
        | NativeBridgeErrorCode::TicketAlreadyRedeemed
        | NativeBridgeErrorCode::TicketInvalid
        | NativeBridgeErrorCode::CompensationConflict
        | NativeBridgeErrorCode::CleanupUnproven
        | NativeBridgeErrorCode::Quarantined
        | NativeBridgeErrorCode::OwnerUnresponsive
        | NativeBridgeErrorCode::Unavailable => CredentialVaultError::Unavailable,
        NativeBridgeErrorCode::InvalidMessage
        | NativeBridgeErrorCode::SecretBoundsExceeded
        | NativeBridgeErrorCode::SecretLifecycleViolation
        | NativeBridgeErrorCode::JournalCorrupt
        | NativeBridgeErrorCode::Internal => CredentialVaultError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_engine_api::{
        CredentialKind, CredentialProvision, CredentialSecret, ValidatedSingBoxProfile,
    };

    #[test]
    fn only_an_admitted_bridge_timeout_has_an_unknown_vault_outcome() {
        assert_eq!(
            map_vault_error(NativeBridgeError::new(
                NativeBridgeErrorCode::Timeout,
                "bounded timeout",
            )),
            CredentialVaultError::OutcomeUnknown
        );
        assert_eq!(
            map_vault_error(NativeBridgeError::new(
                NativeBridgeErrorCode::Unavailable,
                "bridge unavailable",
            )),
            CredentialVaultError::Unavailable
        );
        assert_eq!(
            map_vault_error(NativeBridgeError::new(
                NativeBridgeErrorCode::PermissionDenied,
                "denied",
            )),
            CredentialVaultError::AccessDenied
        );
    }

    #[test]
    fn sensitive_provision_wire_is_canonical_and_keeps_secret_bindings() {
        const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const FIRST_ID: &str = "11111111-1111-4111-8111-111111111111";
        const SECOND_ID: &str = "22222222-2222-4222-8222-222222222222";
        let first = CredentialRef::new(FIRST_ID, CredentialKind::TrojanPassword)
            .expect("canonical first reference");
        let second = CredentialRef::new(SECOND_ID, CredentialKind::TrojanPassword)
            .expect("canonical second reference");
        let profile = ValidatedSingBoxProfile::parse(&format!(
            r#"{{"outbounds":[{{"type":"trojan","tag":"first","server":"first.example.com","server_port":443,"credential_ref":{{"id":"{FIRST_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"first.example.com"}}}},{{"type":"trojan","tag":"second","server":"second.example.com","server_port":443,"credential_ref":{{"id":"{SECOND_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"second.example.com"}}}}]}}"#
        ))
        .expect("typed profile");
        let request = CredentialProvisionRequest::new(
            PROFILE_ID,
            &profile,
            vec![
                CredentialProvision::new(
                    &second,
                    CredentialSecret::new("second-dummy-secret").expect("second secret"),
                ),
                CredentialProvision::new(
                    &first,
                    CredentialSecret::new("first-dummy-secret").expect("first secret"),
                ),
            ],
        )
        .expect("canonical request");
        let wire = serde_json::to_value(sensitive_provision_envelope(
            uuid::Uuid::parse_str("33333333-3333-4333-8333-333333333333").expect("request UUID"),
            &request,
        ))
        .expect("sensitive wire");
        let entries = wire
            .pointer("/command/payload/request/entries")
            .and_then(serde_json::Value::as_array)
            .expect("wire entries");

        assert_eq!(entries[0]["reference"]["id"], FIRST_ID);
        assert_eq!(entries[0]["secret"], "first-dummy-secret");
        assert_eq!(entries[1]["reference"]["id"], SECOND_ID);
        assert_eq!(entries[1]["secret"], "second-dummy-secret");
    }
}

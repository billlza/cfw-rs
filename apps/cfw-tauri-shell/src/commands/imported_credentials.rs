//! Shared credential-vault transaction for imported profiles.
//!
//! A native boundary timeout has an unknown outcome. The immutable vault
//! contract makes one byte-for-byte equivalent replay safe, but no repository
//! mutation may treat a second unknown outcome as success.

use std::fmt;

use cfw_engine_api::{
    CredentialProvision, CredentialProvisionRequest, CredentialVaultError,
    CredentialVaultProvisioner, CredentialVaultReceipt,
};
use cfw_singbox_config::{CredentialSecret, ValidatedSingBoxProfile};

use crate::subscription_import::ImportedCredential;

#[derive(Debug)]
pub(super) enum ImportedCredentialProvisionAttemptError {
    InvalidRequest(String),
    Vault(CredentialVaultError),
    ReceiptAudienceMismatch,
}

impl ImportedCredentialProvisionAttemptError {
    fn outcome_unknown(&self) -> bool {
        matches!(self, Self::Vault(CredentialVaultError::OutcomeUnknown))
    }
}

impl fmt::Display for ImportedCredentialProvisionAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => formatter.write_str(message),
            Self::Vault(error) => error.fmt(formatter),
            Self::ReceiptAudienceMismatch => formatter
                .write_str("credential vault returned a receipt for a different profile audience"),
        }
    }
}

#[derive(Debug)]
pub(super) enum ImportedCredentialProvisionError {
    Rejected(ImportedCredentialProvisionAttemptError),
    OutcomeUnknownReplay {
        first: ImportedCredentialProvisionAttemptError,
        replay: ImportedCredentialProvisionAttemptError,
    },
}

impl fmt::Display for ImportedCredentialProvisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(error) => error.fmt(formatter),
            Self::OutcomeUnknownReplay { first, replay } => write!(
                formatter,
                "credential vault did not confirm the exact batch after one outcome-unknown replay ({first}; replay: {replay})"
            ),
        }
    }
}

/// Provisions one immutable audience, replaying the exact request once only
/// when the first native result is unknown.
///
/// Callers decide whether a profile without any credential references needs a
/// vault transaction. Once called, this function always asks the vault to
/// validate the profile's complete reference set, including references whose
/// secret material is intentionally omitted because it must already exist.
pub(super) async fn provision_imported_credentials_with_exact_replay(
    vault: &impl CredentialVaultProvisioner,
    profile_id: &str,
    profile: &ValidatedSingBoxProfile,
    credentials: &[ImportedCredential],
) -> Result<(), ImportedCredentialProvisionError> {
    let first = provision_once(vault, profile_id, profile, credentials).await;
    match first {
        Ok(()) => Ok(()),
        Err(first) if first.outcome_unknown() => {
            match provision_once(vault, profile_id, profile, credentials).await {
                Ok(()) => Ok(()),
                Err(replay) => {
                    Err(ImportedCredentialProvisionError::OutcomeUnknownReplay { first, replay })
                }
            }
        }
        Err(error) => Err(ImportedCredentialProvisionError::Rejected(error)),
    }
}

async fn provision_once(
    vault: &impl CredentialVaultProvisioner,
    profile_id: &str,
    profile: &ValidatedSingBoxProfile,
    credentials: &[ImportedCredential],
) -> Result<(), ImportedCredentialProvisionAttemptError> {
    let entries = credentials
        .iter()
        .map(|credential| {
            CredentialSecret::new(&credential.secret)
                .map(|secret| CredentialProvision::new(&credential.reference, secret))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            ImportedCredentialProvisionAttemptError::InvalidRequest(error.to_string())
        })?;
    let request =
        CredentialProvisionRequest::new(profile_id, profile, entries).map_err(|error| {
            ImportedCredentialProvisionAttemptError::InvalidRequest(error.to_string())
        })?;
    let receipt: CredentialVaultReceipt = vault
        .provision_profile_credentials(request)
        .await
        .map_err(ImportedCredentialProvisionAttemptError::Vault)?;
    if receipt.profile_id != profile_id || receipt.profile_digest != profile.digest() {
        return Err(ImportedCredentialProvisionAttemptError::ReceiptAudienceMismatch);
    }
    Ok(())
}

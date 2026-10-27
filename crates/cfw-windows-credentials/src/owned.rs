use cfw_engine_api::{CredentialProvisionRequest, CredentialVaultError as Error};
use cfw_singbox_config::{CredentialAudience, CredentialRef};
use zeroize::Zeroizing;

/// Owned transfer to a blocking worker, created only from a checked request.
/// No serde, Clone or Debug representation exposes the secret buffers. Drop
/// erases each owned copy; it does not erase the caller's borrowed material.
pub struct OwnedCredentialProvision {
    pub(super) audience: CredentialAudience,
    pub(super) references: Vec<CredentialRef>,
    pub(super) entries: Vec<(CredentialRef, Zeroizing<String>)>,
}
impl OwnedCredentialProvision {
    pub fn capture(request: &CredentialProvisionRequest<'_>) -> Result<Self, Error> {
        let total = request.entries().iter().try_fold(0usize, |total, entry| {
            total
                .checked_add(entry.secret().expose_to_vault().len())
                .ok_or(Error::CapacityExceeded)
        })?;
        if total > crate::document::MAX_TOTAL_SECRET_BYTES {
            return Err(Error::CapacityExceeded);
        }
        Ok(Self {
            audience: request.audience().clone(),
            references: request.required_references().to_vec(),
            entries: request
                .entries()
                .iter()
                .map(|entry| {
                    (
                        entry.reference().clone(),
                        Zeroizing::new(entry.secret().expose_to_vault().to_owned()),
                    )
                })
                .collect(),
        })
    }
}

use cfw_singbox_config::{
    CredentialAudience, CredentialSlot, EngineSettings, ProjectionMode, ValidatedSingBoxProfile,
};
use serde::{Deserialize, Serialize};

/// Rebind only unchanged credential-bearing transports within the same stored
/// profile. Secrets remain native; source and destination audiences stay exact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CredentialRebindWire")]
pub struct CredentialRebindRequest {
    previous_audience: CredentialAudience,
    audience: CredentialAudience,
    slots: Vec<CredentialSlot>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRebindWire {
    previous_audience: CredentialAudience,
    audience: CredentialAudience,
    slots: Vec<CredentialSlot>,
}

impl TryFrom<CredentialRebindWire> for CredentialRebindRequest {
    type Error = &'static str;
    fn try_from(value: CredentialRebindWire) -> Result<Self, Self::Error> {
        if value.previous_audience.profile_id() != value.audience.profile_id()
            || value.slots.len() > crate::MAX_CREDENTIAL_SLOTS
            || value
                .slots
                .iter()
                .map(CredentialSlot::json_pointer)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != value.slots.len()
        {
            return Err("credential rebind has mismatched profile identity or invalid slots");
        }
        Ok(Self {
            previous_audience: value.previous_audience,
            audience: value.audience,
            slots: value.slots,
        })
    }
}

impl CredentialRebindRequest {
    pub fn for_retained_credentials(
        id: &str,
        previous: &ValidatedSingBoxProfile,
        candidate: &ValidatedSingBoxProfile,
        settings: &EngineSettings,
    ) -> Result<Option<Self>, String> {
        let retained = candidate
            .retained_credential_references(previous)
            .map_err(|error| error.to_string())?;
        if retained.is_empty() {
            return Ok(None);
        }
        let projection = candidate
            .project(id, ProjectionMode::LocalProxy, settings)
            .map_err(|error| error.to_string())?;
        let slots = projection
            .credential_slots()
            .iter()
            .filter(|slot| retained.contains(slot.reference()))
            .cloned()
            .collect();
        Ok(Some(Self {
            previous_audience: CredentialAudience::new(id, previous.digest())
                .map_err(|error| error.to_string())?,
            audience: projection.credential_audience().clone(),
            slots,
        }))
    }

    pub fn new(
        id: &str,
        previous: &ValidatedSingBoxProfile,
        candidate: &ValidatedSingBoxProfile,
        settings: &EngineSettings,
    ) -> Result<Self, String> {
        if !candidate.can_rebind_credentials_from(previous) {
            return Err("credential-bearing nodes changed; import the updated node definition with its credentials before applying it".into());
        }
        let projection = candidate
            .project(id, ProjectionMode::LocalProxy, settings)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            previous_audience: CredentialAudience::new(id, previous.digest())
                .map_err(|error| error.to_string())?,
            audience: projection.credential_audience().clone(),
            slots: projection.credential_slots().to_vec(),
        })
    }
    pub fn audience(&self) -> &CredentialAudience {
        &self.audience
    }
}

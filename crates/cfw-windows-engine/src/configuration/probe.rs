//! The shared profile probe is independent of runtime generations and leases.
//! Validate its closed outbound-only shape before opening the credential vault.
use super::{Error, ResolvedProjection, SecretDocument, serialize_bounded};
use cfw_engine_api::ProfileDelayTestRequest;
use cfw_singbox_config::{
    CredentialAudience, CredentialRef, MAX_CREDENTIAL_SLOTS, MAX_ENGINE_CONFIG_BYTES,
    canonicalize_configuration_value, validate_credential_slots,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};
use zeroize::Zeroize;

#[derive(Clone, Serialize)]
pub(crate) struct ProbeOptions {
    pub(crate) proxies: Vec<String>,
    pub(crate) timeout_ms: u16,
    pub(crate) target_url: String,
    pub(crate) expected_status: String,
}

pub struct CheckedProbeConfiguration {
    request: ProfileDelayTestRequest,
    digest: String,
}
impl Drop for CheckedProbeConfiguration {
    fn drop(&mut self) {
        self.request.config_json.zeroize();
    }
}
pub struct ResolvedProbe {
    pub(crate) projection: ResolvedProjection,
    pub(crate) options: ProbeOptions,
}
impl fmt::Debug for ResolvedProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedProbe")
            .field("digest", &self.projection.digest())
            .field("proxy_count", &self.options.proxies.len())
            .finish_non_exhaustive()
    }
}
impl CheckedProbeConfiguration {
    pub fn new(request: ProfileDelayTestRequest) -> Result<Self, Error> {
        let mut value = Self {
            request,
            digest: String::new(),
        };
        value.validate()?;
        let options = serialize_bounded(&value.options(), 65536)?;
        // Hash the original template and audience, never resolved credentials.
        // Length framing binds every option and slot to this one probe request.
        let slots = serialize_bounded(&value.request.credential_slots, MAX_ENGINE_CONFIG_BYTES)?;
        let mut hash = Sha256::new();
        hash.update(b"cfw.windows.profile-probe.v1\0");
        for part in [
            value.request.audience.profile_id().as_bytes(),
            value.request.audience.profile_digest().as_bytes(),
            value.request.config_json.as_bytes(),
            slots.as_slice(),
            options.as_slice(),
        ] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part);
        }
        value.digest = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
        Ok(value)
    }
    pub fn credential_audience(&self) -> &CredentialAudience {
        &self.request.audience
    }
    pub fn credential_references(&self) -> Vec<CredentialRef> {
        self.request
            .credential_slots
            .iter()
            .map(|slot| slot.reference().clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    fn options(&self) -> ProbeOptions {
        ProbeOptions {
            proxies: self.request.proxies.clone(),
            timeout_ms: self.request.timeout_ms,
            target_url: self.request.target_url.clone().unwrap_or_default(),
            expected_status: self.request.expected_status.clone().unwrap_or_default(),
        }
    }
    fn validate(&self) -> Result<(), Error> {
        let request = &self.request;
        if request.config_json.is_empty()
            || request.config_json.len() > MAX_ENGINE_CONFIG_BYTES
            || request.credential_slots.len() > MAX_CREDENTIAL_SLOTS
            || !(1..=32).contains(&request.proxies.len())
            || !(100..=10000).contains(&request.timeout_ms)
            || request
                .proxies
                .iter()
                .any(|name| name.is_empty() || name.len() > 512)
            || request.proxies.iter().collect::<BTreeSet<_>>().len() != request.proxies.len()
        {
            return Err(Error::Configuration("invalid profile probe bounds"));
        }
        serialize_bounded(&request.proxies, 32768)?;
        let document = SecretDocument(canonicalize_configuration_value(
            serde_json::from_str(&request.config_json)
                .map_err(|_| Error::Configuration("invalid probe configuration"))?,
        ));
        let root = document
            .0
            .as_object()
            .ok_or(Error::Configuration("probe must be an object"))?;
        if root
            .keys()
            .any(|key| !["outbounds", "endpoints", "dns", "route"].contains(&key.as_str()))
            || serialize_bounded(&document.0, MAX_ENGINE_CONFIG_BYTES)?.as_slice()
                != request.config_json.as_bytes()
        {
            return Err(Error::Configuration(
                "probe cannot configure runtime integration",
            ));
        }
        if let Some(route) = root.get("route") {
            let route = route
                .as_object()
                .ok_or(Error::Configuration("invalid probe resolver"))?;
            if route.keys().any(|key| key != "default_domain_resolver") {
                return Err(Error::Configuration("probe cannot configure routes"));
            }
        }
        validate_credential_slots(&document.0, &request.credential_slots)
            .map_err(|_| Error::Configuration("invalid probe credential slot binding"))?;
        let target = request.target_url.as_deref().unwrap_or("");
        if !target.is_empty() {
            if target.len() > 2048 || target.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(Error::Configuration("invalid probe target"));
            }
            let (_, authority) = target
                .split_once("://")
                .ok_or(Error::Configuration("invalid probe target"))?;
            if authority
                .split(['/', '?', '#'])
                .next()
                .is_none_or(|part| part.contains('@'))
            {
                return Err(Error::Configuration("invalid probe target"));
            }
            let url = url::Url::parse(target)
                .map_err(|_| Error::Configuration("invalid probe target"))?;
            if !["http", "https"].contains(&url.scheme())
                || url.host_str().is_none_or(str::is_empty)
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || url.port() == Some(0)
            {
                return Err(Error::Configuration("invalid probe target"));
            }
        }
        let expected = request.expected_status.as_deref().unwrap_or("");
        cfw_singbox_config::validate_expected_status(expected)
            .map_err(|_| Error::Configuration("invalid probe expected status"))?;
        Ok(())
    }
    pub fn resolve<'a>(
        &self,
        material: impl IntoIterator<Item = (&'a CredentialRef, &'a str)>,
    ) -> Result<ResolvedProbe, Error> {
        Ok(ResolvedProbe {
            projection: ResolvedProjection::resolve_template(
                &self.request.config_json,
                &self.request.credential_slots,
                &self.digest,
                material,
            )?,
            options: self.options(),
        })
    }
}

#[cfg(test)]
mod tests;

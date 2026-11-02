//! What the cutover and the diagnostics need of SystemConfiguration: the
//! services of the current network set, each one's identity and proxy
//! configuration, and a session that locks, stages and commits.
//!
//! `preferences.rs` implements these traits on live SCPreferences. The tests
//! implement them in memory, so no test touches this Mac's network settings.

use anyhow::{Context, Result, bail};
use objc2_core_foundation::{CFDictionary, CFRetained};

use crate::legacy_proxy::LegacyProxyServiceIdentity;
use crate::sysproxy_sc::{MAX_IDENTITY_BYTES, MAX_SERVICES};

/// A service's proxy settings as SystemConfiguration holds them.
pub(crate) enum ProxyConfiguration {
    /// The service has no Proxies protocol.
    NoProtocol,
    /// The Proxies protocol carries no configuration dictionary.
    Unconfigured,
    Configured(CFRetained<CFDictionary>),
}

/// One service of a preferences session.
pub(crate) trait ProxyService {
    /// The service's stable identifier, when it has one.
    fn identifier(&self) -> Option<String>;
    /// The name System Settings shows for the service, when it has one.
    fn display_name(&self) -> Option<String>;
    fn proxy_configuration(&self) -> ProxyConfiguration;
    /// Stages `configuration` as the service's proxy configuration in this
    /// session; false when SystemConfiguration refuses it.
    fn stage_proxy_configuration(&self, configuration: &CFDictionary) -> bool;
}

/// One preferences session.
pub(crate) trait ProxyPreferences {
    type Service: ProxyService;

    /// Takes the preferences lock, held until the session ends.
    fn lock(&mut self) -> Result<()>;
    /// The services of the current network set, in set order.
    fn services(&self) -> Result<Vec<Self::Service>>;
    /// Commits the staged changes and applies them to the running system.
    fn commit_apply(&self) -> Result<()>;
}

pub(crate) fn current_services<P: ProxyPreferences>(preferences: &P) -> Result<Vec<P::Service>> {
    let services = preferences.services()?;
    if services.len() > MAX_SERVICES {
        bail!("current network service count exceeds the cutover safety bound")
    }
    Ok(services)
}

pub(crate) fn service_id(service: &impl ProxyService) -> Result<String> {
    let value = service
        .identifier()
        .context("SC network service has no stable identifier")?;
    validate_identity_text("service identifier", &value)?;
    Ok(value)
}

pub(crate) fn service_name(service: &impl ProxyService, id: &str) -> Result<String> {
    let value = service.display_name().unwrap_or_else(|| id.to_owned());
    validate_identity_text("service display name", &value)?;
    Ok(value)
}

pub(crate) fn validate_identity_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("SC network {label} is invalid")
    }
    Ok(())
}

pub(crate) fn find_service<'a, S: ProxyService>(
    services: &'a [S],
    identity: &LegacyProxyServiceIdentity,
) -> Result<&'a S> {
    let service = services
        .iter()
        .find(|service| {
            service
                .identifier()
                .is_some_and(|id| id == identity.service_id)
        })
        .with_context(|| {
            format!(
                "SC network service identity disappeared: {}",
                identity.service_id
            )
        })?;
    if service_name(service, &identity.service_id)? != identity.display_name {
        bail!(
            "SC network service {} changed display identity during cutover",
            identity.service_id
        )
    }
    Ok(service)
}

#[cfg(test)]
mod tests;

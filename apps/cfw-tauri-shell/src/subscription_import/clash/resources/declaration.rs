//! One provider declaration: its source, filter, health check and rule format.

use cfw_singbox_config::{ProviderFilter, ProviderHealthCheck, ProviderRuleFormat, ProviderSource};

use super::{MAX_SUBSCRIPTION_DOCUMENT_BYTES, ProxyFields, YamlValue};

pub(super) fn provider_mapping(value: YamlValue, context: String) -> Result<ProxyFields, String> {
    let YamlValue::Mapping(mapping) = value else {
        return Err(format!("{context} must be a mapping"));
    };
    Ok(ProxyFields::new(mapping, context))
}

pub(super) fn source(fields: &mut ProxyFields) -> Result<(ProviderSource, usize), String> {
    let kind = fields.require_string("type")?;
    let url = fields.take_string("url")?;
    let interval = fields
        .take_string("interval")?
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| "provider interval must be an integer")?;
    let maximum = fields
        .take_string("size-limit")?
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| "provider size-limit must be an integer")?
        .filter(|value| *value > 0)
        .unwrap_or(MAX_SUBSCRIPTION_DOCUMENT_BYTES)
        .min(MAX_SUBSCRIPTION_DOCUMENT_BYTES);
    // The application owns its cache location; a subscription cannot choose a
    // filesystem write target. The cache hint does not change routing content.
    fields.take_string("path")?;
    if fields
        .take_string("proxy")?
        .is_some_and(|proxy| proxy != "DIRECT")
    {
        return Err(
            "provider download via a named proxy requires the profile resource transport".into(),
        );
    }
    let source = match (kind.as_str(), url) {
        ("http", Some(url)) => {
            let url = reqwest::Url::parse(&url).map_err(|_| "provider URL is invalid")?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(
                    "provider downloads require HTTPS without userinfo or a fragment".into(),
                );
            }
            let interval_seconds = interval.unwrap_or(3600);
            if !(60..=604800).contains(&interval_seconds) {
                return Err("provider interval must be 60..=604800 seconds".into());
            }
            ProviderSource {
                url: Some(url.to_string()),
                interval_seconds,
            }
        }
        ("inline", None) if interval.is_none_or(|value| value == 0) => ProviderSource {
            url: None,
            interval_seconds: 0,
        },
        _ => {
            return Err(
                "provider requires type http with a URL, or type inline with a payload".into(),
            );
        }
    };
    Ok((source, maximum))
}

pub(super) fn filter(fields: &mut ProxyFields) -> Result<ProviderFilter, String> {
    let filter = ProviderFilter {
        include: fields.take_string("filter")?,
        exclude: fields.take_string("exclude-filter")?,
    };
    filter.accepts("").map_err(|error| error.to_string())?;
    Ok(filter)
}

pub(super) fn health(fields: &mut ProxyFields) -> Result<Option<ProviderHealthCheck>, String> {
    let Some(value) = fields.take("health-check") else {
        return Ok(None);
    };
    let mut fields = provider_mapping(value, "provider health-check".into())?;
    let enabled = fields.take_bool("enable")?.unwrap_or(false);
    let url = fields.take_string("url")?;
    let interval = fields
        .take_string("interval")?
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| "health interval must be an integer")?
        .unwrap_or(300);
    let lazy = fields.take_bool("lazy")?.unwrap_or(true);
    let timeout_ms = fields
        .take_string("timeout")?
        .map(|value| value.parse::<u16>())
        .transpose()
        .map_err(|_| "health timeout must be an integer")?
        .unwrap_or(5000);
    let expected_status = fields.take_string("expected-status")?;
    fields.reject_leftovers()?;
    if !enabled {
        return Ok(None);
    }
    Ok(Some(ProviderHealthCheck {
        url: url.ok_or("enabled provider health check requires a URL")?,
        interval_seconds: interval,
        lazy,
        timeout_ms,
        expected_status,
    }))
}

pub(super) fn format(fields: &mut ProxyFields) -> Result<ProviderRuleFormat, String> {
    match fields.take_string("format")?.as_deref().unwrap_or("yaml") {
        "yaml" => Ok(ProviderRuleFormat::Yaml),
        "text" => Ok(ProviderRuleFormat::Text),
        _ => Err("rule provider format must be yaml or text".into()),
    }
}

//! Selector and automatic group members, health checks and timing.

use std::collections::BTreeSet;

use super::{MAX_PATH_BYTES, unsupported_shape};
use crate::ConfigError;
use crate::profile::MAX_OUTBOUNDS;

/// Whether a group names between one and `MAX_OUTBOUNDS` members, each once.
pub(super) fn has_unique_members(outbounds: &[String]) -> bool {
    !outbounds.is_empty()
        && outbounds.len() <= MAX_OUTBOUNDS
        && outbounds.iter().collect::<BTreeSet<_>>().len() == outbounds.len()
}

pub(super) fn validate_health_check_url(url: &str, path: &str) -> Result<(), ConfigError> {
    let parsed =
        url::Url::parse(url).map_err(|_| unsupported_shape(path, "invalid health-check URL"))?;
    if url.len() > MAX_PATH_BYTES
        || url.chars().any(char::is_whitespace)
        || !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.port() == Some(0)
    {
        return Err(unsupported_shape(
            path,
            "health-check URL must be bounded HTTP(S) without credentials or a fragment",
        ));
    }
    Ok(())
}

pub(super) fn validate_group_timing(
    interval_seconds: u32,
    tolerance_ms: u16,
    idle_timeout_seconds: u32,
    path: &str,
) -> Result<(), ConfigError> {
    if !(30..=86_400).contains(&interval_seconds)
        || tolerance_ms > 10_000
        || idle_timeout_seconds < interval_seconds
        || idle_timeout_seconds > 604_800
    {
        return Err(unsupported_shape(
            path,
            "automatic group interval must be 30..=86400 seconds, tolerance at most 10000 ms, and idle timeout between interval and 604800 seconds",
        ));
    }
    Ok(())
}

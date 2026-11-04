//! Errors of the Clash-compatible controller client.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("invalid controller endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("controller HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("controller JSON decode failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("controller rejected request with HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("failed to read controller HTTP {status} response body: {source}")]
    ResponseBodyRead {
        status: u16,
        #[source]
        source: reqwest::Error,
    },
    #[error("controller HTTP {status} response exceeds the {maximum}-byte limit")]
    ResponseTooLarge { status: u16, maximum: usize },
    #[error("controller {resource} exceeds the {maximum}-entry limit")]
    PayloadLimit {
        resource: &'static str,
        maximum: usize,
    },
    #[error("controller capability `{capability}` is unsupported by the pinned sing-box engine")]
    UnsupportedByPinnedEngine { capability: &'static str },
}

pub(crate) fn unsupported_provider_subsystem<T>() -> Result<T, ControllerError> {
    Err(ControllerError::UnsupportedByPinnedEngine {
        capability: "provider management",
    })
}

/// Fixed capability admission for the pinned engine line. The strict sing-box
/// 1.14.4 profile schema cannot create proxy or rule providers, while its
/// clash-compatible endpoints are inert compatibility stubs.
pub fn require_provider_management() -> Result<(), ControllerError> {
    unsupported_provider_subsystem()
}

#[cfg(test)]
mod tests;

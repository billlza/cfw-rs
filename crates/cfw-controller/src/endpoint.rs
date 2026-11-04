//! The loopback endpoint of the engine controller.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ControllerError;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerEndpoint {
    pub host: String,
    pub port: u16,
    pub secret: Option<String>,
}

/// The secret authenticates the caller to the engine controller, so it is
/// redacted here: the endpoint is carried through application state and must
/// stay safe to include in diagnostics.
impl fmt::Debug for ControllerEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerEndpoint")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl ControllerEndpoint {
    pub fn new(host: impl Into<String>, port: u16, secret: Option<String>) -> Self {
        Self {
            host: host.into(),
            port,
            secret,
        }
    }

    pub fn base_url(&self) -> Result<String, ControllerError> {
        if self.host != "127.0.0.1" || self.port == 0 {
            return Err(ControllerError::InvalidEndpoint(
                "controller endpoint must be the fixed IPv4 loopback address and a nonzero port"
                    .into(),
            ));
        }
        Ok(format!("http://{}:{}", self.host, self.port))
    }

    pub fn websocket_url(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<String, ControllerError> {
        self.base_url()?;

        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let mut params = Vec::new();
        if let Some(secret) = self.secret.as_deref().filter(|secret| !secret.is_empty()) {
            params.push(format!("token={}", urlencoding::encode(secret)));
        }
        params.extend(query.iter().map(|(key, value)| {
            format!(
                "{}={}",
                urlencoding::encode(key),
                urlencoding::encode(value)
            )
        }));

        let query = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        Ok(format!("ws://{}:{}{}{}", self.host, self.port, path, query))
    }
}

#[cfg(test)]
mod tests;

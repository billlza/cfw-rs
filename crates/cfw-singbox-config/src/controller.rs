//! The application-owned, clash-compatible controller listener.
//!
//! libbox only exposes the RESTful controller when the configuration carries an
//! `experimental.clash_api` block. That block is owned by the application, not
//! by an imported profile: `experimental` stays in `FORBIDDEN_PROFILE_KEYS`, so
//! the only way it can reach the engine is this projection.
//!
//! Two properties are structural rather than configurable:
//!
//! * the listener address is a loopback constant, never a wildcard and never a
//!   LAN address, so engine control is not reachable from the network;
//! * the shared secret is generated once per process run from the operating
//!   system CSPRNG, so only this run of this application can drive the
//!   controller. It is never a fixed string, never empty, never written to
//!   settings, never logged, and never published in a snapshot.

use std::fmt;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

use serde_json::{Value, json};
use uuid::Uuid;

use crate::ConfigError;

/// Loopback address the controller binds. Taking this from settings or from a
/// profile would allow a wildcard or LAN listener, so it is a constant.
pub const CLASH_API_ADDRESS: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// Bounded default controller port, used when settings do not choose one.
pub const DEFAULT_CLASH_API_PORT: u16 = 9090;

/// Lowest port the controller may bind. Privileged ports stay unavailable so
/// the loopback listener never needs elevation.
pub const MIN_CLASH_API_PORT: u16 = 1024;

/// Hex characters in the per-run secret: 256 bits.
const CLASH_API_SECRET_LENGTH: usize = 64;

/// Loopback endpoint plus per-run secret of the controller this process opens.
///
/// `Debug` redacts the secret, and the type is deliberately neither
/// `Serialize` nor `Display`, so the secret can only leave through
/// [`ClashApiEndpoint::expose_secret`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClashApiEndpoint {
    port: u16,
    secret: &'static str,
}

impl ClashApiEndpoint {
    pub(crate) fn resolve(port: u16, mixed_port: u16) -> Result<Self, ConfigError> {
        if port < MIN_CLASH_API_PORT || port == mixed_port {
            return Err(ConfigError::InvalidControllerPort(port));
        }
        Ok(Self {
            port,
            secret: process_secret(),
        })
    }

    pub fn address(&self) -> Ipv4Addr {
        CLASH_API_ADDRESS
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The `external_controller` listener value: loopback host and port only.
    pub fn external_controller(&self) -> String {
        format!("{CLASH_API_ADDRESS}:{}", self.port)
    }

    /// The single accessor for the secret. Callers must not log, persist, or
    /// publish the returned value.
    pub fn expose_secret(&self) -> &'static str {
        self.secret
    }

    pub(crate) fn experimental_value(&self) -> Value {
        json!({
            "clash_api": {
                "external_controller": self.external_controller(),
                "secret": self.secret,
            }
        })
    }
}

impl fmt::Debug for ClashApiEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClashApiEndpoint")
            .field("address", &CLASH_API_ADDRESS)
            .field("port", &self.port)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Per-run controller secret, kept in process memory only.
///
/// Two RFC 9562 version 4 UUIDs are drawn from the operating system CSPRNG and
/// concatenated, which yields 64 lowercase hex characters. Every projection in
/// one process run shares the value, so a projection stays byte-identical for
/// identical inputs within the run.
fn process_secret() -> &'static str {
    static SECRET: OnceLock<String> = OnceLock::new();
    SECRET
        .get_or_init(|| {
            let mut secret = String::with_capacity(CLASH_API_SECRET_LENGTH);
            let mut buffer = Uuid::encode_buffer();
            while secret.len() < CLASH_API_SECRET_LENGTH {
                secret.push_str(Uuid::new_v4().simple().encode_lower(&mut buffer));
            }
            secret
        })
        .as_str()
}

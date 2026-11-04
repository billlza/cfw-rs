use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Route {
    System,
    Tunnel,
    EngineProxy { port: u16 },
}

/// A failure is distinct from a successful observation whose optional data is
/// unavailable. Messages are local constants, never remote response bodies.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum Observation<T> {
    Observed { value: T },
    Failed { reason: &'static str },
}

impl<T> From<Result<T, &'static str>> for Observation<T> {
    fn from(value: Result<T, &'static str>) -> Self {
        match value {
            Ok(value) => Self::Observed { value },
            Err(reason) => Self::Failed { reason },
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Trace {
    pub ip: IpAddr,
    pub country: Option<String>,
    pub colo: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ServiceObservation {
    pub name: &'static str,
    pub host: &'static str,
    pub response: Observation<HttpObservation>,
    pub egress: Option<Observation<Trace>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct HttpObservation {
    pub http_status: u16,
    pub elapsed_ms: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConnectivityReport {
    pub observed_at_ms: u64,
    pub route: Route,
    pub system_egress: Observation<Trace>,
    pub routed_egress: Observation<Trace>,
    pub ipv4: Observation<IpAddr>,
    pub ipv6: Observation<IpAddr>,
    pub services: Vec<ServiceObservation>,
}

/// ipapi.is anonymous tier: null means the provider has no value. Detection
/// flags are deliberately absent; missing data must not become `false`.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct IpInformation {
    pub ip: IpAddr,
    #[serde(deserialize_with = "nullable_text")]
    pub company: Option<String>,
    #[serde(deserialize_with = "nullable_text")]
    pub asn: Option<String>,
    #[serde(deserialize_with = "nullable_text")]
    pub city: Option<String>,
    #[serde(deserialize_with = "nullable_text")]
    pub region: Option<String>,
    #[serde(deserialize_with = "nullable_text")]
    pub country: Option<String>,
    #[serde(deserialize_with = "nullable_text")]
    pub timezone: Option<String>,
}

// Anonymous responses promise these keys, with null for unknown data. A
// truncated or changed schema must not quietly become a list of unknowns.
fn nullable_text<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

pub(super) fn validate_text(value: &str) -> bool {
    value.len() <= 256 && !value.chars().any(char::is_control)
}

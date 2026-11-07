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

/// A third-party record for the selected address, not a routing observation or
/// a service's own account-risk assessment.
#[derive(Debug, Serialize)]
pub(crate) struct IpInformation {
    pub ip: IpAddr,
    pub company: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub timezone: Option<String>,
    pub risk: NetworkIndicators,
}

/// Required provider fields: omitted/null flags must never default to false.
/// False means no match in this source, not proof that an address is safe.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct NetworkIndicators {
    pub is_mobile: bool,
    pub is_vpn: bool,
    pub is_tor: bool,
    pub is_proxy: bool,
    pub is_datacenter: bool,
    pub risk_score: u16,
}

pub(super) fn validate_text(value: &str) -> bool {
    value.len() <= 256 && !value.chars().any(char::is_control)
}

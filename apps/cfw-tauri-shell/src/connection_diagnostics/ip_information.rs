//! Optional, attributed IPQuery lookup. Provider schema stays at this boundary.
use super::http::{body, client, transport_failure};
use super::types::{IpInformation, NetworkIndicators, Route, validate_text};
use serde::Deserialize;
use std::net::IpAddr;

#[derive(Deserialize)]
struct ProviderRecord {
    ip: IpAddr,
    isp: ProviderNetwork,
    location: ProviderLocation,
    risk: NetworkIndicators,
}

#[derive(Deserialize)]
struct ProviderNetwork {
    asn: String,
    org: String,
    isp: String,
}

#[derive(Deserialize)]
struct ProviderLocation {
    country: String,
    city: String,
    state: String,
    timezone: String,
}

pub(crate) async fn lookup_ip(route: Route, ip: IpAddr) -> Result<IpInformation, &'static str> {
    let client = client(route).map_err(|_| "client_unavailable")?;
    let response = client
        .get(format!("https://api.ipquery.io/{ip}?format=json"))
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|error| transport_failure(&error))?;
    // Local limits apply even though the service publishes no numeric quota.
    // Refusal stops further lookups for a day; there is no automatic retry.
    if matches!(response.status().as_u16(), 403 | 429) {
        return Err("provider_rate_limited");
    }
    parse_ip_information(&body(response).await?, ip)
}

pub(super) fn parse_ip_information(
    bytes: &[u8],
    expected: IpAddr,
) -> Result<IpInformation, &'static str> {
    let value: ProviderRecord = serde_json::from_slice(bytes).map_err(|_| "invalid_response")?;
    if value.ip != expected
        // The documented weights total 150, not a probability or a /100 score.
        || value.risk.risk_score > 150
        || [
            &value.isp.org,
            &value.isp.isp,
            &value.isp.asn,
            &value.location.city,
            &value.location.state,
            &value.location.country,
            &value.location.timezone,
        ]
        .into_iter()
        .any(|text| !validate_text(text))
    {
        return Err("invalid_response");
    }
    // The provider explicitly defines empty source strings as missing data;
    // omitted keys and wrong types above are schema failures, not unknowns.
    let supplied = |text: String| if text.is_empty() { None } else { Some(text) };
    Ok(IpInformation {
        ip: value.ip,
        company: supplied(value.isp.org),
        isp: supplied(value.isp.isp),
        asn: supplied(value.isp.asn),
        city: supplied(value.location.city),
        region: supplied(value.location.state),
        country: supplied(value.location.country),
        timezone: supplied(value.location.timezone),
        risk: value.risk,
    })
}

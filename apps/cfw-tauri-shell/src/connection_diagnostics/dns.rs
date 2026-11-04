//! Authoritative resolver observation using bash.ws's documented CLI protocol.
//! Resolver ASN/country differences alone never establish a DNS leak.
use super::types::validate_text;
use super::{DiagnosticsGate, Route, http, timestamp};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Serialize)]
pub(crate) struct DnsResolver {
    pub ip: IpAddr,
    pub country: Option<String>,
    pub asn: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DnsReport {
    pub observed_at_ms: u64,
    pub resolvers: Vec<DnsResolver>,
    pub lookup_failures: usize,
}

#[derive(Deserialize)]
struct Record {
    #[serde(rename = "type")]
    kind: String,
    ip: Option<String>,
    country_name: Option<String>,
    asn: Option<String>,
}

pub(super) fn test_id(bytes: &[u8]) -> Result<&str, &'static str> {
    let id = std::str::from_utf8(bytes)
        .map_err(|_| "invalid_response")?
        .trim();
    if id.is_empty() || id.len() > 48 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("invalid_response");
    }
    Ok(id)
}

pub(super) fn parse_resolvers(bytes: &[u8]) -> Result<Vec<DnsResolver>, &'static str> {
    let records: Vec<Record> = serde_json::from_slice(bytes).map_err(|_| "invalid_response")?;
    if records.len() > 64 {
        return Err("response_too_large");
    }
    let mut resolvers = Vec::new();
    for record in records {
        if record.kind == "error" {
            return Err("dns_provider_failed");
        }
        if record.kind != "dns" {
            continue;
        }
        let ip = record
            .ip
            .ok_or("invalid_response")?
            .parse()
            .map_err(|_| "invalid_response")?;
        if [&record.country_name, &record.asn]
            .into_iter()
            .flatten()
            .any(|text| !validate_text(text))
        {
            return Err("invalid_response");
        }
        if !resolvers
            .iter()
            .any(|resolver: &DnsResolver| resolver.ip == ip)
        {
            resolvers.push(DnsResolver {
                ip,
                country: record.country_name,
                asn: record.asn,
            });
        }
    }
    if resolvers.is_empty() {
        return Err("no_resolvers_observed");
    }
    Ok(resolvers)
}

pub(crate) async fn run_dns_check(
    route: Route,
    gate: &DiagnosticsGate,
) -> Result<DnsReport, &'static str> {
    let client = http::client(route).map_err(|_| "client_unavailable")?;
    let bytes = http::get(&client, "https://bash.ws/id").await?;
    let id = test_id(&bytes)?;
    // Four unique OS lookups, not proxy HTTP fetches. The blocking resolver
    // holds its permit even if the outer request is cancelled or times out.
    // Thus repeated cancellation cannot accumulate unbounded OS resolver jobs.
    let failures = stream::iter(1..=4)
        .map(|index| {
            let resolvers = Arc::clone(&gate.resolvers);
            let host = format!("{index}.{id}.bash.ws");
            async move {
                tokio::time::timeout(Duration::from_secs(6), async move {
                    let permit = resolvers.acquire_owned().await.map_err(|_| ())?;
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        (host.as_str(), 443)
                            .to_socket_addrs()
                            .map(|mut values| values.next().is_some())
                            .map_err(|_| ())
                    })
                    .await
                    .map_err(|_| ())?
                    .and_then(|any| if any { Ok(()) } else { Err(()) })
                })
                .await
                .map_or(true, |result| result.is_err())
            }
        })
        .buffer_unordered(4)
        .collect::<Vec<_>>()
        .await;
    // Give the authoritative collector one bounded settling interval; no poll
    // or provider retry. Empty/error responses remain inconclusive.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let bytes = http::get(
        &client,
        &format!("https://bash.ws/dnsleak/test/{id}?json=2"),
    )
    .await?;
    Ok(DnsReport {
        observed_at_ms: timestamp().map_err(|_| "clock_unavailable")?,
        resolvers: parse_resolvers(&bytes)?,
        lookup_failures: failures.into_iter().filter(|failed| *failed).count(),
    })
}

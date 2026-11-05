//! User-initiated, bounded observations. No probe changes the engine or the OS.
//! An HTTP response is reachability evidence, never an account/region verdict.
mod dns;
mod http;
mod ip_information;
mod session;
mod types;

pub(crate) use dns::{DnsReport, run_dns_check};
pub(crate) use ip_information::lookup_ip;
pub(crate) use session::DiagnosticsGate;
pub(crate) use types::{ConnectivityReport, IpInformation, Route};

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) async fn run_connectivity(route: Route) -> Result<ConnectivityReport, String> {
    let system = http::client(Route::System)?;
    let routed = http::client(route)?;
    let (system_egress, routed_egress, ipv4, ipv6, services) = tokio::join!(
        http::trace(&system, "https://www.cloudflare.com/cdn-cgi/trace"),
        http::trace(&routed, "https://www.cloudflare.com/cdn-cgi/trace"),
        http::ip_echo(&routed, "https://api4.ipify.org", false),
        http::ip_echo(&routed, "https://api6.ipify.org", true),
        http::services(&routed),
    );
    Ok(ConnectivityReport {
        observed_at_ms: timestamp()?,
        route,
        system_egress,
        routed_egress,
        ipv4,
        ipv6,
        services,
    })
}

fn timestamp() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "diagnostic clock precedes Unix epoch")?
            .as_millis(),
    )
    .map_err(|_| "diagnostic clock is outside its supported range".into())
}

#[cfg(test)]
mod tests;

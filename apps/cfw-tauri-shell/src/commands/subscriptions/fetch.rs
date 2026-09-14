//! Bounded HTTPS resource transport and destination validation.
use crate::subscription_import::MAX_SUBSCRIPTION_DOCUMENT_BYTES;
use crate::transport_security::external_https_client_builder;
use futures_util::{StreamExt as _, TryStreamExt as _};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, HeaderMap, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, Url};
use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

pub(super) const SUBSCRIPTION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const SUBSCRIPTION_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Subscription panels negotiate the response format on this header. The
/// `clash.meta` product token makes them serve Clash Meta YAML with the full
/// modern protocol set (VLESS/Reality, Hysteria2), which the importer
/// converts into the closed schema. It must not contain `sing-box`: panels
/// answer that token with raw sing-box JSON whose inline secrets the closed
/// schema deliberately rejects.
pub(super) const SUBSCRIPTION_USER_AGENT: &str =
    concat!("clash.meta cfw-rs/", env!("CARGO_PKG_VERSION"));
pub(super) const MAX_SUBSCRIPTION_REDIRECTS: usize = 5;
/// Subscription URLs may carry credentials in their query string. Never let
/// reqwest synthesize a Referer header while following a redirect, including
/// redirects between otherwise-valid public HTTPS origins.
pub(super) const FORWARD_SUBSCRIPTION_REFERER: bool = false;
pub(super) const MAX_SUBSCRIPTION_DNS_ADDRESSES: usize = 64;
pub(super) const IANA_IPV4_PROTOCOL_ASSIGNMENTS: ([u8; 4], u8) = ([192, 0, 0, 0], 24);
pub(super) const IANA_IPV6_GLOBAL_UNICAST: ([u8; 16], u8) =
    ([0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 3);
pub(super) const IANA_IPV6_PROTOCOL_ASSIGNMENTS: ([u8; 16], u8) =
    ([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 23);
pub(super) const WELL_KNOWN_NAT64_PREFIX: ([u8; 16], u8) = (
    [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    96,
);
/// Accepts only a bounded `https` subscription URL with a routable host.
///
/// Plain HTTP is refused: a configuration fetched over an unauthenticated
/// transport can be replaced in flight. Loopback and private literals are
/// refused so a subscription cannot be aimed at this app's own loopback
/// controller or at a host-local service.
pub(in crate::commands) fn validate_subscription_url(url: &str) -> Result<Url, String> {
    let trimmed = url.trim();
    if trimmed.len() > 2_048 {
        return Err("subscription URL is too long".into());
    }
    let parsed = Url::parse(trimmed).map_err(|_| "subscription URL is not a valid URL")?;
    if parsed.scheme() != "https" {
        return Err("subscription URL must use https".into());
    }
    if parsed.as_str() != trimmed
        || trimmed
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err("subscription URL is not a plain absolute https URL".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("subscription URL must not carry embedded credentials".into());
    }
    let host = parsed
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or("subscription URL has no host")?;
    if host_is_public(host) {
        Ok(parsed)
    } else {
        Err("subscription URL host is not a public endpoint".into())
    }
}

/// True when the host is a routable domain or a public IP literal.
///
/// `Url::host_str` returns an IPv6 literal in brackets, so both forms are
/// examined. A name is accepted without resolving it; a literal is checked so a
/// subscription cannot be aimed at loopback or a host-local network.
pub(super) fn host_is_public(host: &str) -> bool {
    let literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    match literal.parse::<std::net::IpAddr>() {
        Ok(address) => is_public_ip(address),
        Err(_) => {
            !host.eq_ignore_ascii_case("localhost")
                && !host.to_ascii_lowercase().ends_with(".localhost")
                && host.contains('.')
                && host.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
        }
    }
}

pub(super) fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

/// Public subscription endpoints are restricted to globally reachable unicast
/// addresses. This table follows the IANA IPv4 Special-Purpose Address Registry
/// and additionally excludes multicast, which is never a valid HTTPS origin for
/// this product. Keep it aligned with
/// <https://www.iana.org/assignments/iana-ipv4-special-registry/>.
pub(super) fn is_public_ipv4(address: Ipv4Addr) -> bool {
    if matches!(address.octets(), [192, 0, 0, 9 | 10]) {
        return true;
    }
    const NON_PUBLIC: &[([u8; 4], u8)] = &[
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        IANA_IPV4_PROTOCOL_ASSIGNMENTS,
        ([192, 0, 2, 0], 24),
        // Deprecated 6to4 relay space has no generally reachable assignment;
        // the sole specific 192.88.99.2 registration is explicitly non-global.
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ];
    !NON_PUBLIC
        .iter()
        .any(|(network, prefix)| ipv4_has_prefix(address, *network, *prefix))
}

/// IPv4-mapped and well-known NAT64 addresses inherit the classification of
/// their embedded IPv4 address. Native IPv6 is admitted only from IANA's global
/// unicast 2000::/3 allocation and then has every non-global special-purpose
/// subrange removed. Everything else fails closed, including multicast, ULA,
/// link-local, site-local, discard-only and future-reserved ranges. Keep the
/// exceptions aligned with
/// <https://www.iana.org/assignments/iana-ipv6-special-registry/>.
pub(super) fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    if ipv6_has_prefix(
        address,
        WELL_KNOWN_NAT64_PREFIX.0,
        WELL_KNOWN_NAT64_PREFIX.1,
    ) {
        let octets = address.octets();
        return is_public_ipv4(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    if !ipv6_has_prefix(
        address,
        IANA_IPV6_GLOBAL_UNICAST.0,
        IANA_IPV6_GLOBAL_UNICAST.1,
    ) {
        return false;
    }

    if ipv6_has_prefix(
        address,
        IANA_IPV6_PROTOCOL_ASSIGNMENTS.0,
        IANA_IPV6_PROTOCOL_ASSIGNMENTS.1,
    ) {
        return is_globally_reachable_ietf_protocol_assignment(address);
    }

    const NON_PUBLIC_GLOBAL_UNICAST: &[([u8; 16], u8)] = &[
        // Documentation ranges.
        (
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        ),
        ([0x3f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 20),
        // 6to4 has no unconditional globally-reachable guarantee.
        ([0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 16),
    ];
    !NON_PUBLIC_GLOBAL_UNICAST
        .iter()
        .any(|(network, prefix)| ipv6_has_prefix(address, *network, *prefix))
}

pub(super) fn is_globally_reachable_ietf_protocol_assignment(address: Ipv6Addr) -> bool {
    let value = u128::from_be_bytes(address.octets());
    const PCP_ANYCAST: u128 = 0x2001_0001_0000_0000_0000_0000_0000_0001;
    const TURN_ANYCAST: u128 = 0x2001_0001_0000_0000_0000_0000_0000_0002;
    const DNS_SD_ANYCAST: u128 = 0x2001_0001_0000_0000_0000_0000_0000_0003;
    if matches!(value, PCP_ANYCAST | TURN_ANYCAST | DNS_SD_ANYCAST) {
        return true;
    }
    const GLOBAL_EXCEPTIONS: &[([u8; 16], u8)] = &[
        (
            [0x20, 0x01, 0, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        ),
        (
            [
                0x20, 0x01, 0, 0x04, 0x01, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            48,
        ),
        (
            [0x20, 0x01, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            28,
        ),
        (
            [0x20, 0x01, 0, 0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            28,
        ),
    ];
    GLOBAL_EXCEPTIONS
        .iter()
        .any(|(network, prefix)| ipv6_has_prefix(address, *network, *prefix))
}

pub(super) fn ipv4_has_prefix(address: Ipv4Addr, network: [u8; 4], prefix: u8) -> bool {
    debug_assert!(prefix <= 32);
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    u32::from_be_bytes(address.octets()) & mask == u32::from_be_bytes(network) & mask
}

pub(super) fn ipv6_has_prefix(address: Ipv6Addr, network: [u8; 16], prefix: u8) -> bool {
    debug_assert!(prefix <= 128);
    let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
    u128::from_be_bytes(address.octets()) & mask == u128::from_be_bytes(network) & mask
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubscriptionResolutionError {
    EmptyAnswer,
    TooManyAnswers,
    NonPublicAnswer,
}

impl fmt::Display for SubscriptionResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAnswer => formatter.write_str("subscription DNS answer was empty"),
            Self::TooManyAnswers => formatter.write_str("subscription DNS answer was too large"),
            Self::NonPublicAnswer => {
                formatter.write_str("subscription DNS answer was not globally reachable")
            }
        }
    }
}

impl StdError for SubscriptionResolutionError {}

pub(super) fn validate_resolved_addresses(
    addresses: &[SocketAddr],
) -> Result<(), SubscriptionResolutionError> {
    if addresses.is_empty() {
        return Err(SubscriptionResolutionError::EmptyAnswer);
    }
    if addresses.len() > MAX_SUBSCRIPTION_DNS_ADDRESSES {
        return Err(SubscriptionResolutionError::TooManyAnswers);
    }
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(SubscriptionResolutionError::NonPublicAnswer);
    }
    Ok(())
}

#[derive(Debug, Default)]
pub(super) struct SystemSubscriptionDnsResolver;

impl Resolve for SystemSubscriptionDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|error| Box::new(error) as Box<dyn StdError + Send + Sync>)?
                .take(MAX_SUBSCRIPTION_DNS_ADDRESSES + 1)
                .collect::<Vec<_>>();
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

#[derive(Debug)]
pub(super) struct PublicSubscriptionDnsResolver<R> {
    inner: R,
}

impl<R> PublicSubscriptionDnsResolver<R> {
    pub(super) fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R> Resolve for PublicSubscriptionDnsResolver<R>
where
    R: Resolve,
{
    fn resolve(&self, name: Name) -> Resolving {
        let resolving = self.inner.resolve(name);
        Box::pin(async move {
            let addresses = resolving
                .await?
                .take(MAX_SUBSCRIPTION_DNS_ADDRESSES + 1)
                .collect::<Vec<_>>();
            validate_resolved_addresses(&addresses)
                .map_err(|error| Box::new(error) as Box<dyn StdError + Send + Sync>)?;
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::commands) enum SubscriptionRoute {
    Direct,
    LocalProxy(u16),
}

impl SubscriptionRoute {
    pub(in crate::commands) fn for_engine(
        engine: &crate::engine::ManagedEngine,
    ) -> Result<Self, String> {
        use cfw_engine_api::EngineState;
        let snapshot = engine.coordinator.snapshot();
        match snapshot.state {
            EngineState::LocalProxyActive { .. }
            | EngineState::ProxyActive { .. }
            | EngineState::TunnelSystemProxyActive { .. } => {
                let identity = crate::commands::controller::running_runtime_identity(&snapshot)
                    .map_err(
                        |_| "subscription download cannot bind an inconsistent active engine",
                    )?;
                let access = engine.active_controller_access(
                    identity.context.generation,
                    &identity.config_digest,
                )?;
                Ok(Self::LocalProxy(access.settings().mixed_port))
            }
            // Pure TUN captures the ordinary socket. Off/failed configurations
            // can still download repairs without starting a network owner.
            _ => Ok(Self::Direct),
        }
    }
}

pub(super) async fn resolve_provider_documents(
    body: String,
    route: SubscriptionRoute,
) -> Result<String, String> {
    let requests = crate::subscription_import::provider_requests(&body)?;
    if requests.is_empty() {
        return Ok(body);
    }
    let resources = fetch_provider_resources(requests, body.len(), route).await?;
    let materialized = crate::subscription_import::materialize_providers(&body, &resources)?;
    if materialized.len() > MAX_SUBSCRIPTION_DOCUMENT_BYTES {
        return Err("materialized provider profile exceeds the subscription source limit".into());
    }
    Ok(materialized)
}

pub(in crate::commands) async fn fetch_provider_resources(
    requests: Vec<crate::subscription_import::ProviderRequest>,
    existing_bytes: usize,
    route: SubscriptionRoute,
) -> Result<Vec<(crate::subscription_import::ProviderRequest, String)>, String> {
    let operation = async {
        // Preserve source order even when requests finish out of order. Node
        // credential positions and provider precedence must remain deterministic.
        let mut pending = futures_util::stream::iter(requests)
            .map(|request| async move {
                let target = validate_subscription_url(&request.url)?;
                let payload = fetch_subscription_bounded(&target, request.maximum_bytes, route)
                    .await
                    .map_err(|error| {
                        format!("provider {} download failed: {error}", request.name)
                    })?;
                Ok::<_, String>((request, payload))
            })
            .buffered(4);
        let mut resources = Vec::new();
        let mut bytes = existing_bytes;
        while let Some(resource) = pending.try_next().await? {
            bytes = bytes.saturating_add(resource.1.len());
            if bytes > MAX_SUBSCRIPTION_DOCUMENT_BYTES {
                return Err(
                    "combined provider resources exceed the subscription source limit".into(),
                );
            }
            resources.push(resource);
        }
        Ok(resources)
    };
    tokio::time::timeout(Duration::from_secs(120), operation)
        .await
        .map_err(|_| "provider downloads exceeded the 120-second transaction deadline".to_owned())?
}

pub(super) async fn fetch_subscription_bounded(
    url: &Url,
    maximum_bytes: usize,
    route: SubscriptionRoute,
) -> Result<String, String> {
    let client = subscription_client(route)?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|error| sanitized_fetch_error("request", &error))?;
    if !response.status().is_success() {
        return Err(format!(
            "subscription download failed with HTTP {}",
            response.status().as_u16()
        ));
    }
    validate_subscription_content_encoding(response.headers())?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(format!(
            "subscription document exceeds the {maximum_bytes}-byte limit"
        ));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| sanitized_fetch_error("response body", &error))?;
        if body.len() + chunk.len() > maximum_bytes {
            return Err(format!(
                "subscription document exceeds the {maximum_bytes}-byte limit"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty() {
        return Err("subscription document is empty".into());
    }
    String::from_utf8(body).map_err(|_| "subscription document is not UTF-8".to_owned())
}

pub(super) fn subscription_client(route: SubscriptionRoute) -> Result<Client, String> {
    subscription_client_with_resolver(route, SystemSubscriptionDnsResolver)
}

pub(super) fn subscription_client_with_resolver<R: Resolve + 'static>(
    route: SubscriptionRoute,
    resolver: R,
) -> Result<Client, String> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    let builder = external_https_client_builder()
        .map_err(|error| error.to_string())?
        .user_agent(SUBSCRIPTION_USER_AGENT)
        .default_headers(headers)
        .referer(FORWARD_SUBSCRIPTION_REFERER)
        .connect_timeout(SUBSCRIPTION_CONNECT_TIMEOUT)
        .timeout(SUBSCRIPTION_REQUEST_TIMEOUT)
        // Ignore ambient proxies. The only optional proxy is the exact owned
        // loopback listener, using local DNS so public-address checks remain
        // authoritative before a numeric SOCKS CONNECT. TLS keeps the hostname.
        .no_proxy()
        // Bound the exact bytes the importer receives,
        // even if another workspace crate enables reqwest compression later.
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .dns_resolver(PublicSubscriptionDnsResolver::new(resolver))
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() >= MAX_SUBSCRIPTION_REDIRECTS {
                return attempt.error("too many subscription redirects");
            }
            match validate_subscription_url(attempt.url().as_str()) {
                Ok(_) => attempt.follow(),
                Err(error) => attempt.error(error),
            }
        }));
    let builder = match route {
        SubscriptionRoute::Direct => builder,
        SubscriptionRoute::LocalProxy(port) => builder.proxy(
            reqwest::Proxy::all(format!("socks5://127.0.0.1:{port}"))
                .map_err(|error| sanitized_fetch_error("local proxy", &error))?,
        ),
    };
    builder
        .build()
        .map_err(|error| sanitized_fetch_error("client build", &error))
}

pub(super) fn validate_subscription_content_encoding(headers: &HeaderMap) -> Result<(), String> {
    for value in headers.get_all(CONTENT_ENCODING) {
        let value = value
            .to_str()
            .map_err(|_| "subscription response has an invalid Content-Encoding".to_owned())?;
        let mut coding_count = 0_usize;
        for coding in value.split(',').map(str::trim) {
            coding_count += 1;
            if coding.is_empty() || !coding.eq_ignore_ascii_case("identity") {
                return Err("subscription response uses an unsupported Content-Encoding".to_owned());
            }
        }
        if coding_count == 0 {
            return Err("subscription response has an invalid Content-Encoding".to_owned());
        }
    }
    Ok(())
}

/// Transport failures are reported by category only. A subscription URL can
/// carry an access token, and reqwest errors quote the URL they failed on.
pub(super) fn sanitized_fetch_error(stage: &str, error: &reqwest::Error) -> String {
    let category = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "secure connection failed (TLS 1.2 or newer is required)"
    } else if error.is_redirect() {
        "redirect was rejected"
    } else if error.is_body() || error.is_decode() {
        "response was unreadable"
    } else if error.is_builder() {
        "client could not be built"
    } else {
        "request failed"
    };
    format!("subscription {stage} {category}")
}

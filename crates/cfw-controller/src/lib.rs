use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use futures_util::{StreamExt, stream};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_CONTROLLER_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONTROLLER_ERROR_BYTES: usize = 16 * 1024;
const MAX_CONTROLLER_CONNECTIONS: usize = 4_096;
const MAX_CONTROLLER_PROXIES: usize = 8_192;
const MAX_CONTROLLER_RULES: usize = 16_384;
const MAX_CONTROLLER_LOG_FIELDS: usize = 64;

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
    #[error(
        "controller capability `{capability}` is unsupported by pinned engine sing-box 1.13.14"
    )]
    UnsupportedByPinnedEngine { capability: &'static str },
}

fn unsupported_provider_subsystem<T>() -> Result<T, ControllerError> {
    Err(ControllerError::UnsupportedByPinnedEngine {
        capability: "provider management",
    })
}

/// Fixed capability admission for the pinned engine line. The strict sing-box
/// 1.13.14 profile schema cannot create proxy or rule providers, while its
/// clash-compatible endpoints are inert compatibility stubs.
pub fn require_provider_management() -> Result<(), ControllerError> {
    unsupported_provider_subsystem()
}

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

#[derive(Clone)]
pub struct ControllerClient {
    endpoint: ControllerEndpoint,
    http: reqwest::Client,
}

/// The HTTP client authenticates with the controller secret in a default
/// `Authorization` header, and `reqwest::Client`'s own `Debug` prints its
/// default headers. Rendering the client through this impl keeps the secret out
/// of any diagnostic that formats a client, or a value that owns one.
impl fmt::Debug for ControllerClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerClient")
            .field("endpoint", &self.endpoint)
            .field("http", &"[REDACTED]")
            .finish()
    }
}

impl ControllerClient {
    pub fn new(endpoint: ControllerEndpoint) -> Result<Self, ControllerError> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        if let Some(secret) = endpoint
            .secret
            .as_deref()
            .filter(|secret| !secret.is_empty())
        {
            let value = HeaderValue::from_str(&format!("Bearer {secret}"))
                .map_err(|err| ControllerError::InvalidEndpoint(err.to_string()))?;
            headers.insert(AUTHORIZATION, value);
        }

        let http = reqwest::Client::builder()
            .default_headers(headers)
            // The controller is an application-owned loopback endpoint. System
            // or environment proxies could create a routing loop and disclose
            // its bearer capability, so this client always connects directly.
            .no_proxy()
            // A controller response never has authority to move an authenticated
            // request to another URL or origin.
            .redirect(Policy::none())
            .connect_timeout(Duration::from_millis(350))
            .timeout(Duration::from_secs(2))
            .pool_max_idle_per_host(4)
            .build()?;

        Ok(Self { endpoint, http })
    }

    pub async fn snapshot(&self) -> Result<ControllerSnapshot, ControllerError> {
        // A snapshot is one observation. Returning an empty connection set when
        // its request failed would make transport failure indistinguishable from
        // an engine with no connections, so every component must succeed.
        let (config, proxies, connections) =
            futures_util::future::try_join3(self.configs(), self.proxies(), self.connections())
                .await?;
        Ok(ControllerSnapshot {
            config,
            proxies,
            connections,
        })
    }

    pub async fn configs(&self) -> Result<ClashConfig, ControllerError> {
        self.get_json("/configs").await
    }

    pub async fn version(&self) -> Result<ControllerVersion, ControllerError> {
        self.get_json("/version").await
    }

    pub async fn dns_query(
        &self,
        name: &str,
        record_type: &str,
    ) -> Result<serde_json::Value, ControllerError> {
        let path = format!(
            "/dns/query?name={}&type={}",
            urlencoding::encode(name),
            urlencoding::encode(record_type)
        );
        self.get_json(&path).await
    }

    pub async fn patch_configs(&self, patch: ConfigPatch) -> Result<(), ControllerError> {
        self.patch_json("/configs", &patch).await
    }

    pub async fn reload_config(&self, path: &str, force: bool) -> Result<(), ControllerError> {
        let force = if force { "true" } else { "false" };
        let request = ConfigReloadRequest {
            path: Some(path.to_string()),
            payload: None,
        };
        self.put_json(&format!("/configs?force={force}"), &request)
            .await
    }

    pub async fn proxies(&self) -> Result<ProxiesSnapshot, ControllerError> {
        let response: ProxiesResponse = self.get_json("/proxies").await?;
        let snapshot = ProxiesSnapshot::from(response);
        if snapshot.groups.len().saturating_add(snapshot.proxies.len()) > MAX_CONTROLLER_PROXIES {
            return Err(ControllerError::PayloadLimit {
                resource: "proxy set",
                maximum: MAX_CONTROLLER_PROXIES,
            });
        }
        Ok(snapshot)
    }

    pub async fn providers(&self) -> Result<ProvidersSnapshot, ControllerError> {
        unsupported_provider_subsystem()
    }

    pub async fn rules(&self) -> Result<RulesSnapshot, ControllerError> {
        let snapshot: RulesSnapshot = self.get_json("/rules").await?;
        if snapshot.rules.len() > MAX_CONTROLLER_RULES {
            return Err(ControllerError::PayloadLimit {
                resource: "rule set",
                maximum: MAX_CONTROLLER_RULES,
            });
        }
        Ok(snapshot)
    }

    pub async fn proxy_providers(&self) -> Result<Vec<ProviderEntry>, ControllerError> {
        unsupported_provider_subsystem()
    }

    pub async fn rule_providers(&self) -> Result<Vec<ProviderEntry>, ControllerError> {
        unsupported_provider_subsystem()
    }

    pub async fn update_proxy_provider(&self, _name: &str) -> Result<(), ControllerError> {
        unsupported_provider_subsystem()
    }

    pub async fn update_rule_provider(&self, _name: &str) -> Result<(), ControllerError> {
        unsupported_provider_subsystem()
    }

    pub async fn health_check_proxy_provider(&self, _name: &str) -> Result<(), ControllerError> {
        // The pinned handler registers this operation as GET, not PUT. Its
        // provider lookup is nevertheless hard-coded to Not Found because the
        // strict 1.13.14 profile schema cannot construct a provider subsystem;
        // do not send a nominal GET and present the stub as a real capability.
        unsupported_provider_subsystem()
    }

    pub async fn update_all_proxy_providers(&self) -> Result<ProviderBatchResult, ControllerError> {
        unsupported_provider_subsystem()
    }

    pub async fn update_all_rule_providers(&self) -> Result<ProviderBatchResult, ControllerError> {
        unsupported_provider_subsystem()
    }

    pub async fn health_check_all_proxy_providers(
        &self,
    ) -> Result<ProviderBatchResult, ControllerError> {
        unsupported_provider_subsystem()
    }

    pub async fn select_proxy(&self, group: &str, proxy: &str) -> Result<(), ControllerError> {
        let path = format!("/proxies/{}", urlencoding::encode(group));
        self.put_json(&path, &SelectProxyRequest { name: proxy })
            .await
    }

    pub async fn proxy_delay(
        &self,
        proxy: &str,
        url: &str,
        timeout_ms: u16,
    ) -> Result<u32, ControllerError> {
        self.proxy_delay_at(
            &format!(
                "/proxies/{}/delay?url={}&timeout={}",
                urlencoding::encode(proxy),
                urlencoding::encode(url),
                timeout_ms
            ),
            timeout_ms,
        )
        .await
    }

    async fn proxy_delay_at(&self, path: &str, timeout_ms: u16) -> Result<u32, ControllerError> {
        // The controller blocks up to `timeout_ms` while probing the node, so
        // this request must outlive that window. The client-wide 2s timeout
        // would otherwise abort an honest-but-slow probe (timeout_ms > ~2000)
        // and mis-report a reachable node as an error, so derive a per-request
        // timeout from the caller's budget plus a round-trip buffer.
        let request_timeout = Duration::from_millis(u64::from(timeout_ms) + 2_000);
        let response = self
            .http
            .get(self.url(path)?)
            .timeout(request_timeout)
            .send()
            .await?;
        let delay: DelayResponse = decode_response(response).await?;
        Ok(delay.delay)
    }

    pub async fn proxy_delays(
        &self,
        proxies: Vec<String>,
        url: String,
        timeout_ms: u16,
        concurrency: usize,
    ) -> Vec<ProxyDelayResult> {
        let client = self.clone();
        let limit = concurrency.clamp(1, 32);
        stream::iter(proxies)
            .map(|name| {
                let client = client.clone();
                let url = url.clone();
                async move {
                    match client.proxy_delay(&name, &url, timeout_ms).await {
                        Ok(delay) => ProxyDelayResult {
                            name,
                            delay: Some(delay),
                            error_kind: None,
                            error: None,
                        },
                        Err(error) => ProxyDelayResult {
                            name,
                            delay: None,
                            error_kind: Some(ProxyDelayFailureKind::from(&error)),
                            error: Some(error.to_string()),
                        },
                    }
                }
            })
            .buffer_unordered(limit)
            .collect()
            .await
    }

    pub async fn connections(&self) -> Result<ConnectionsSnapshot, ControllerError> {
        let snapshot: ConnectionsSnapshot = self.get_json("/connections").await?;
        validate_connections(&snapshot)?;
        Ok(snapshot)
    }

    pub fn connections_stream_url(&self) -> Result<String, ControllerError> {
        self.endpoint.websocket_url("/connections", &[])
    }

    pub fn logs_stream_url(&self, level: &str) -> Result<String, ControllerError> {
        self.endpoint
            .websocket_url("/logs", &[("level", level), ("format", "structured")])
    }

    pub fn decode_connections_stream_message(
        raw: &str,
    ) -> Result<ConnectionsSnapshot, ControllerError> {
        let snapshot = serde_json::from_str(raw)?;
        validate_connections(&snapshot)?;
        Ok(snapshot)
    }

    pub fn decode_log_stream_message(raw: &str) -> Result<StructuredLogEntry, ControllerError> {
        let entry: StructuredLogEntry = serde_json::from_str(raw)?;
        if entry.fields.len() > MAX_CONTROLLER_LOG_FIELDS {
            return Err(ControllerError::PayloadLimit {
                resource: "structured log field set",
                maximum: MAX_CONTROLLER_LOG_FIELDS,
            });
        }
        Ok(entry)
    }

    pub async fn close_all_connections(&self) -> Result<(), ControllerError> {
        self.delete_empty("/connections").await
    }

    pub async fn close_connection(&self, id: &str) -> Result<(), ControllerError> {
        let path = format!("/connections/{}", urlencoding::encode(id));
        self.delete_empty(&path).await
    }

    pub async fn flush_fake_ip_cache(&self) -> Result<(), ControllerError> {
        self.post_empty("/cache/fakeip/flush").await
    }

    async fn get_json<T>(&self, path: &str) -> Result<T, ControllerError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response = self.http.get(self.url(path)?).send().await?;
        decode_response(response).await
    }

    async fn put_json<T>(&self, path: &str, body: &T) -> Result<(), ControllerError>
    where
        T: Serialize + ?Sized,
    {
        let response = self.http.put(self.url(path)?).json(body).send().await?;
        decode_empty(response).await
    }

    async fn post_empty(&self, path: &str) -> Result<(), ControllerError> {
        let response = self.http.post(self.url(path)?).send().await?;
        decode_empty(response).await
    }

    async fn patch_json<T>(&self, path: &str, body: &T) -> Result<(), ControllerError>
    where
        T: Serialize + ?Sized,
    {
        let response = self.http.patch(self.url(path)?).json(body).send().await?;
        decode_empty(response).await
    }

    async fn delete_empty(&self, path: &str) -> Result<(), ControllerError> {
        let response = self.http.delete(self.url(path)?).send().await?;
        decode_empty(response).await
    }

    fn url(&self, path: &str) -> Result<String, ControllerError> {
        Ok(format!("{}{}", self.endpoint.base_url()?, path))
    }
}

fn validate_connections(snapshot: &ConnectionsSnapshot) -> Result<(), ControllerError> {
    if snapshot.connections.len() > MAX_CONTROLLER_CONNECTIONS {
        return Err(ControllerError::PayloadLimit {
            resource: "connection set",
            maximum: MAX_CONTROLLER_CONNECTIONS,
        });
    }
    Ok(())
}

async fn decode_response<T>(response: reqwest::Response) -> Result<T, ControllerError>
where
    T: for<'de> Deserialize<'de>,
{
    let status = response.status();
    if !status.is_success() {
        let status = status.as_u16();
        let body = read_bounded_body(response, status, MAX_CONTROLLER_ERROR_BYTES).await?;
        let body = String::from_utf8_lossy(&body).into_owned();
        return Err(ControllerError::Status { status, body });
    }
    let status = status.as_u16();
    let body = read_bounded_body(response, status, MAX_CONTROLLER_JSON_BYTES).await?;
    Ok(serde_json::from_slice(&body)?)
}

async fn decode_empty(response: reqwest::Response) -> Result<(), ControllerError> {
    let status = response.status();
    let status_code = status.as_u16();
    let body = read_bounded_body(response, status_code, MAX_CONTROLLER_ERROR_BYTES).await?;
    if !status.is_success() {
        let body = String::from_utf8_lossy(&body).into_owned();
        let status = status_code;
        return Err(ControllerError::Status { status, body });
    }
    Ok(())
}

async fn read_bounded_body(
    response: reqwest::Response,
    status: u16,
    maximum: usize,
) -> Result<Vec<u8>, ControllerError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(ControllerError::ResponseTooLarge { status, maximum });
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|source| ControllerError::ResponseBodyRead { status, source })?;
        if body.len().saturating_add(chunk.len()) > maximum {
            return Err(ControllerError::ResponseTooLarge { status, maximum });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControllerSnapshot {
    pub config: ClashConfig,
    pub proxies: ProxiesSnapshot,
    pub connections: ConnectionsSnapshot,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RulesSnapshot {
    pub rules: Vec<RuleEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleEntry {
    pub index: Option<u32>,
    #[serde(rename = "type")]
    pub kind: String,
    pub payload: String,
    pub proxy: String,
    pub size: Option<i64>,
    #[serde(rename = "hitCount", alias = "hit_count")]
    pub hits: Option<u64>,
    pub provider: Option<String>,
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClashConfig {
    pub port: Option<u16>,
    #[serde(rename = "socks-port")]
    pub socks_port: Option<u16>,
    #[serde(rename = "redir-port")]
    pub redir_port: Option<u16>,
    #[serde(rename = "tproxy-port")]
    pub tproxy_port: Option<u16>,
    #[serde(rename = "mixed-port")]
    pub mixed_port: Option<u16>,
    #[serde(rename = "allow-lan")]
    pub allow_lan: Option<bool>,
    pub mode: Option<String>,
    #[serde(rename = "log-level")]
    pub log_level: Option<String>,
    pub ipv6: Option<bool>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ConfigPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "allow-lan", skip_serializing_if = "Option::is_none")]
    pub allow_lan: Option<bool>,
    #[serde(rename = "bind-address", skip_serializing_if = "Option::is_none")]
    pub bind_address: Option<String>,
    #[serde(rename = "log-level", skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerVersion {
    pub version: String,
    #[serde(default)]
    pub meta: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ConfigReloadRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxiesSnapshot {
    pub groups: Vec<ProxyGroup>,
    pub proxies: Vec<ProxyNode>,
}

impl From<ProxiesResponse> for ProxiesSnapshot {
    fn from(response: ProxiesResponse) -> Self {
        let mut groups = Vec::new();
        let mut proxies = Vec::new();

        for (name, entry) in response.proxies {
            if let Some(options) = entry.all.clone() {
                groups.push(ProxyGroup {
                    name,
                    kind: entry.kind,
                    now: entry.now,
                    options,
                    history: entry.history,
                });
            } else {
                proxies.push(ProxyNode {
                    name,
                    kind: entry.kind,
                    udp: entry.udp,
                    history: entry.history,
                });
            }
        }

        groups.sort_by(|left, right| left.name.cmp(&right.name));
        proxies.sort_by(|left, right| left.name.cmp(&right.name));
        Self { groups, proxies }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ProxiesResponse {
    proxies: HashMap<String, ProxyEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct ProxyEntry {
    #[serde(rename = "type")]
    kind: String,
    all: Option<Vec<String>>,
    now: Option<String>,
    udp: Option<bool>,
    history: Vec<DelayHistory>,
}

impl Default for ProxyEntry {
    fn default() -> Self {
        Self {
            kind: "Unknown".into(),
            all: None,
            now: None,
            udp: None,
            history: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyGroup {
    pub name: String,
    pub kind: String,
    pub now: Option<String>,
    pub options: Vec<String>,
    pub history: Vec<DelayHistory>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyNode {
    pub name: String,
    pub kind: String,
    pub udp: Option<bool>,
    pub history: Vec<DelayHistory>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DelayHistory {
    pub time: String,
    pub delay: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvidersSnapshot {
    pub proxy_providers: Vec<ProviderEntry>,
    pub rule_providers: Vec<ProviderEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderEntry {
    pub name: String,
    pub kind: String,
    pub vehicle_type: String,
    pub behavior: Option<String>,
    pub updated_at: Option<String>,
    pub proxies: Vec<String>,
    pub rules: Vec<String>,
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderBatchResult {
    pub action: String,
    pub requested: usize,
    pub succeeded: Vec<String>,
    pub failed: Vec<ProviderBatchFailure>,
}

impl ProviderBatchResult {
    pub fn is_complete_success(&self) -> bool {
        self.failed.is_empty() && self.succeeded.len() == self.requested
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderBatchFailure {
    pub name: String,
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionsSnapshot {
    #[serde(alias = "uploadTotal", alias = "upload_total")]
    pub upload: u64,
    #[serde(alias = "downloadTotal", alias = "download_total")]
    pub download: u64,
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub connections: Vec<Connection>,
}

fn null_as_empty_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

/// clash-rs emits ports as integers; mihomo often emits strings. Accept either.
fn string_or_number<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or number")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value.to_string())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value)
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value.to_string())
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value.to_string())
        }

        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.fract() == 0.0 && value >= 0.0 && value <= u64::MAX as f64 {
                Ok((value as u64).to_string())
            } else {
                Ok(value.to_string())
            }
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(String::new())
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(String::new())
        }
    }

    deserializer.deserialize_any(Visitor)
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Connection {
    pub id: String,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub chains: Vec<String>,
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
    pub metadata: ConnectionMetadata,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionMetadata {
    pub network: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "sourceIP", alias = "source_ip")]
    pub source_ip: String,
    #[serde(rename = "destinationIP", alias = "destination_ip")]
    pub destination_ip: String,
    #[serde(
        rename = "sourcePort",
        alias = "source_port",
        deserialize_with = "string_or_number"
    )]
    pub source_port: String,
    #[serde(
        rename = "destinationPort",
        alias = "destination_port",
        deserialize_with = "string_or_number"
    )]
    pub destination_port: String,
    pub host: String,
    #[serde(rename = "dnsMode", alias = "dns_mode")]
    pub dns_mode: String,
    #[serde(rename = "processPath", alias = "process_path")]
    pub process_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StructuredLogEntry {
    pub time: Option<String>,
    pub level: String,
    #[serde(alias = "msg")]
    pub message: String,
    pub fields: Vec<StructuredLogField>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for StructuredLogEntry {
    fn default() -> Self {
        Self {
            time: None,
            level: "info".into(),
            message: String::new(),
            fields: Vec::new(),
            extra: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct StructuredLogField {
    pub key: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SelectProxyRequest<'a> {
    name: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyDelayResult {
    pub name: String,
    pub delay: Option<u32>,
    pub error_kind: Option<ProxyDelayFailureKind>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyDelayFailureKind {
    Timeout,
    NotFound,
    ProbeFailed,
    Rejected,
    Transport,
    InvalidResponse,
    InvalidRequest,
    Unsupported,
}

impl From<&ControllerError> for ProxyDelayFailureKind {
    fn from(error: &ControllerError) -> Self {
        match error {
            ControllerError::Status { status: 504, .. } => Self::Timeout,
            ControllerError::Status { status: 404, .. } => Self::NotFound,
            ControllerError::Status { status: 503, .. } => Self::ProbeFailed,
            ControllerError::Status { .. } => Self::Rejected,
            ControllerError::Http(source) if source.is_timeout() => Self::Timeout,
            ControllerError::Http(source) if source.is_decode() || source.is_body() => {
                Self::InvalidResponse
            }
            ControllerError::Http(_) => Self::Transport,
            ControllerError::Json(_)
            | ControllerError::ResponseBodyRead { .. }
            | ControllerError::ResponseTooLarge { .. }
            | ControllerError::PayloadLimit { .. } => Self::InvalidResponse,
            ControllerError::InvalidEndpoint(_) => Self::InvalidRequest,
            ControllerError::UnsupportedByPinnedEngine { .. } => Self::Unsupported,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DelayResponse {
    delay: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[derive(Debug, Deserialize)]
    struct PinnedProxyProvidersResponse {
        providers: HashMap<String, serde_json::Value>,
    }

    #[derive(Debug, Deserialize)]
    struct PinnedRuleProvidersResponse {
        providers: Vec<String>,
    }

    #[test]
    fn endpoint_rejects_every_non_product_controller_address() {
        for endpoint in [
            ControllerEndpoint::new("", 9090, None),
            ControllerEndpoint::new("localhost", 9090, None),
            ControllerEndpoint::new("::1", 9090, None),
            ControllerEndpoint::new("192.0.2.1", 9090, None),
            ControllerEndpoint::new("127.0.0.1", 0, None),
        ] {
            assert!(endpoint.base_url().is_err());
            assert!(endpoint.websocket_url("/logs", &[]).is_err());
        }
    }

    #[test]
    fn controller_http_builder_disables_all_proxy_discovery() {
        let source = include_str!("lib.rs");
        let builder = source
            .split("let http = reqwest::Client::builder()")
            .nth(1)
            .expect("controller HTTP builder")
            .split(".build()?")
            .next()
            .expect("bounded controller HTTP builder");
        assert!(builder.contains(".no_proxy()"));
        assert!(builder.contains(".redirect(Policy::none())"));
    }

    #[tokio::test]
    async fn controller_never_follows_an_authenticated_redirect() {
        let _already_installed = rustls::crypto::ring::default_provider().install_default();
        let redirect_target = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect target");
        let target_address = redirect_target
            .local_addr()
            .expect("redirect target address");
        let controller = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind controller fixture");
        let controller_address = controller.local_addr().expect("controller address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = controller
                .accept()
                .await
                .expect("accept controller request");
            let mut request = [0_u8; 2048];
            let read = stream
                .read(&mut request)
                .await
                .expect("read controller request");
            assert!(
                String::from_utf8_lossy(&request[..read])
                    .to_ascii_lowercase()
                    .contains("authorization: bearer ")
            );
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{target_address}/version\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write redirect response");
        });

        let client = ControllerClient::new(ControllerEndpoint::new(
            controller_address.ip().to_string(),
            controller_address.port(),
            Some("must-not-cross-redirect".into()),
        ))
        .expect("controller client");
        let error = client
            .version()
            .await
            .expect_err("controller redirects must be rejected");
        assert!(matches!(error, ControllerError::Status { status: 302, .. }));
        server.await.expect("controller fixture completes");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), redirect_target.accept())
                .await
                .is_err(),
            "redirect target unexpectedly received the bearer request"
        );
    }

    #[test]
    fn endpoint_debug_redacts_the_controller_secret() {
        let endpoint = ControllerEndpoint::new("127.0.0.1", 9090, Some("app-owned".into()));
        let rendered = format!("{endpoint:?}");
        assert!(!rendered.contains("app-owned"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(format!("{:?}", ControllerEndpoint::new("127.0.0.1", 9090, None)).contains("None"));
    }

    #[test]
    fn endpoint_builds_clash_websocket_urls() {
        let endpoint = ControllerEndpoint::new("127.0.0.1", 9090, Some("secret value".into()));
        assert_eq!(
            endpoint
                .websocket_url("logs", &[("level", "info"), ("format", "structured")])
                .unwrap(),
            "ws://127.0.0.1:9090/logs?token=secret%20value&level=info&format=structured"
        );
    }

    #[test]
    fn proxies_response_splits_groups_and_nodes() {
        let raw = r#"
        {
          "proxies": {
            "Proxy": {"type":"Selector","all":["HK","DIRECT"],"now":"HK","history":[]},
            "HK": {"type":"Shadowsocks","udp":true,"history":[{"time":"now","delay":23}]}
          }
        }
        "#;
        let response: ProxiesResponse = serde_json::from_str(raw).unwrap();
        let snapshot = ProxiesSnapshot::from(response);
        assert_eq!(snapshot.groups.len(), 1);
        assert_eq!(snapshot.groups[0].options, vec!["HK", "DIRECT"]);
        assert_eq!(snapshot.proxies.len(), 1);
        assert_eq!(snapshot.proxies[0].history[0].delay, 23);
    }

    #[test]
    fn pinned_provider_golden_responses_are_stub_shapes() {
        // Exact bodies emitted by experimental/clashapi/provider.go and
        // ruleprovider.go in the pinned sing-box 1.13.14 source snapshot.
        let proxy: PinnedProxyProvidersResponse = serde_json::from_str(include_str!(
            "../tests/fixtures/sing-box-1.13.14-proxy-providers.json"
        ))
        .expect("pinned proxy-provider response");
        let rules: PinnedRuleProvidersResponse = serde_json::from_str(include_str!(
            "../tests/fixtures/sing-box-1.13.14-rule-providers.json"
        ))
        .expect("pinned rule-provider response");

        assert!(proxy.providers.is_empty());
        assert!(rules.providers.is_empty());
    }

    #[test]
    fn pinned_provider_capability_is_explicitly_unsupported() {
        let error = unsupported_provider_subsystem::<ProvidersSnapshot>()
            .expect_err("the strict pinned schema has no provider subsystem");
        assert!(matches!(
            error,
            ControllerError::UnsupportedByPinnedEngine {
                capability: "provider management"
            }
        ));
        assert_eq!(
            error.to_string(),
            "controller capability `provider management` is unsupported by pinned engine sing-box 1.13.14"
        );
    }

    #[test]
    fn rules_snapshot_decodes_controller_rules() {
        // The pinned handler serializes only type/payload/proxy. Absence of a
        // mihomo-only field must survive as None, never a fabricated 0 or -1.
        let snapshot: RulesSnapshot = serde_json::from_str(include_str!(
            "../tests/fixtures/sing-box-1.13.14-rules.json"
        ))
        .unwrap();
        assert_eq!(snapshot.rules.len(), 1);
        assert_eq!(snapshot.rules[0].index, None);
        assert_eq!(snapshot.rules[0].kind, "Default");
        assert_eq!(snapshot.rules[0].hits, None);
        assert_eq!(snapshot.rules[0].size, None);
        assert_eq!(snapshot.rules[0].provider, None);
        assert!(snapshot.rules[0].extra.is_empty());
    }

    #[test]
    fn delay_failures_keep_their_distinct_contract() {
        let cases = [
            (
                ControllerError::Status {
                    status: 504,
                    body: "timeout".into(),
                },
                ProxyDelayFailureKind::Timeout,
            ),
            (
                ControllerError::Status {
                    status: 404,
                    body: "not found".into(),
                },
                ProxyDelayFailureKind::NotFound,
            ),
            (
                ControllerError::Status {
                    status: 503,
                    body: "probe failed".into(),
                },
                ProxyDelayFailureKind::ProbeFailed,
            ),
            (
                ControllerError::Status {
                    status: 401,
                    body: "unauthorized".into(),
                },
                ProxyDelayFailureKind::Rejected,
            ),
            (
                ControllerError::InvalidEndpoint("bad target".into()),
                ProxyDelayFailureKind::InvalidRequest,
            ),
            (
                ControllerError::UnsupportedByPinnedEngine {
                    capability: "provider management",
                },
                ProxyDelayFailureKind::Unsupported,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(ProxyDelayFailureKind::from(&error), expected);
        }
    }

    #[tokio::test]
    async fn rejected_response_body_read_failure_preserves_the_status() {
        let _already_installed = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback fixture server");
        let address = listener.local_addr().expect("fixture server address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fixture request");
            let mut request = [0_u8; 1024];
            let _read = stream
                .read(&mut request)
                .await
                .expect("read fixture request");
            stream
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 32\r\nConnection: close\r\n\r\nshort",
                )
                .await
                .expect("write truncated fixture response");
        });

        let response = reqwest::Client::new()
            .get(format!("http://{address}/failure"))
            .send()
            .await
            .expect("receive fixture response headers");
        let error = decode_empty(response)
            .await
            .expect_err("a truncated rejected response body must fail");
        assert!(matches!(
            error,
            ControllerError::ResponseBodyRead { status: 500, .. }
        ));
        server.await.expect("fixture server completes");
    }

    #[tokio::test]
    async fn declared_oversized_controller_response_is_rejected_before_body_read() {
        let _already_installed = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind oversized-response server");
        let address = listener.local_addr().expect("fixture server address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fixture request");
            let mut request = [0_u8; 1024];
            let _read = stream
                .read(&mut request)
                .await
                .expect("read fixture request");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_CONTROLLER_JSON_BYTES + 1
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write oversized response headers");
        });

        let client = ControllerClient::new(ControllerEndpoint::new(
            address.ip().to_string(),
            address.port(),
            None,
        ))
        .expect("controller client");
        let error = client
            .version()
            .await
            .expect_err("oversized response must fail before allocation");
        assert_eq!(
            error.to_string(),
            format!(
                "controller HTTP 200 response exceeds the {MAX_CONTROLLER_JSON_BYTES}-byte limit"
            )
        );
        server.await.expect("fixture server completes");
    }

    #[tokio::test]
    async fn snapshot_fails_when_any_component_request_fails() {
        let _already_installed = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback snapshot server");
        let address = listener.local_addr().expect("snapshot server address");
        let server = tokio::spawn(async move {
            let mut handlers = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.expect("accept snapshot request");
                handlers.push(tokio::spawn(async move {
                    let mut request = [0_u8; 2048];
                    let read = stream
                        .read(&mut request)
                        .await
                        .expect("read snapshot request");
                    let request = String::from_utf8_lossy(&request[..read]);
                    let (status, body) = if request.starts_with("GET /configs ") {
                        ("200 OK", r#"{"mode":"rule"}"#)
                    } else if request.starts_with("GET /proxies ") {
                        ("200 OK", r#"{"proxies":{}}"#)
                    } else if request.starts_with("GET /connections ") {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        ("503 Service Unavailable", r#"{"message":"not ready"}"#)
                    } else {
                        ("404 Not Found", r#"{"message":"unexpected path"}"#)
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .expect("write snapshot response");
                }));
            }
            for handler in handlers {
                handler.await.expect("snapshot request handler completes");
            }
        });

        let client = ControllerClient::new(ControllerEndpoint::new(
            address.ip().to_string(),
            address.port(),
            None,
        ))
        .expect("snapshot client");
        let error = client
            .snapshot()
            .await
            .expect_err("a failed connections component must fail the full snapshot");
        assert!(matches!(error, ControllerError::Status { status: 503, .. }));
        server.await.expect("snapshot server completes");
    }

    #[test]
    fn connections_snapshot_accepts_clash_total_aliases() {
        let raw = r#"
        {
          "uploadTotal": 1024,
          "downloadTotal": 2048,
          "connections": [
            {
              "id": "1",
              "upload": 8,
              "download": 16,
              "start": "2026-05-13T01:02:03Z",
              "chains": ["Proxy"],
              "rule": "MATCH",
              "rulePayload": "",
              "metadata": {"host": "example.com", "processPath": "/Applications/Safari.app"}
            }
          ]
        }
        "#;
        let snapshot = ControllerClient::decode_connections_stream_message(raw).unwrap();
        assert_eq!(snapshot.upload, 1024);
        assert_eq!(snapshot.download, 2048);
        assert_eq!(
            snapshot.connections[0].metadata.process_path,
            "/Applications/Safari.app"
        );
    }

    #[test]
    fn connections_snapshot_treats_null_connections_as_empty() {
        let raw = r#"{"uploadTotal":0,"downloadTotal":0,"connections":null,"memory":0}"#;
        let snapshot = ControllerClient::decode_connections_stream_message(raw).unwrap();
        assert_eq!(snapshot.upload, 0);
        assert!(snapshot.connections.is_empty());
    }

    #[test]
    fn stream_collection_cardinality_is_bounded() {
        let oversized_connections = ConnectionsSnapshot {
            connections: vec![Connection::default(); MAX_CONTROLLER_CONNECTIONS + 1],
            ..ConnectionsSnapshot::default()
        };
        assert!(matches!(
            validate_connections(&oversized_connections),
            Err(ControllerError::PayloadLimit {
                resource: "connection set",
                maximum: MAX_CONTROLLER_CONNECTIONS,
            })
        ));

        let fields = (0..=MAX_CONTROLLER_LOG_FIELDS)
            .map(|index| serde_json::json!({"key": index.to_string(), "value": index}))
            .collect::<Vec<_>>();
        let log = serde_json::json!({"level": "info", "message": "bounded", "fields": fields});
        assert!(matches!(
            ControllerClient::decode_log_stream_message(&log.to_string()),
            Err(ControllerError::PayloadLimit {
                resource: "structured log field set",
                maximum: MAX_CONTROLLER_LOG_FIELDS,
            })
        ));
    }

    #[test]
    fn connections_snapshot_accepts_integer_ports_from_clash_rs() {
        let raw = r#"
        {
          "uploadTotal": 1,
          "downloadTotal": 2,
          "connections": [
            {
              "id": "1",
              "upload": 8,
              "download": 16,
              "start": "2026-07-21T12:03:07.517274Z",
              "chains": ["Proxy"],
              "rule": "MATCH",
              "rulePayload": "",
              "metadata": {
                "network": "Tcp",
                "type": "HttpConnect",
                "sourceIP": "127.0.0.1",
                "destinationIP": "",
                "sourcePort": 52724,
                "destinationPort": 443,
                "host": "example.com"
              }
            },
            {
              "id": "2",
              "upload": 1,
              "download": 2,
              "start": "2026-07-21T12:03:08Z",
              "chains": ["DIRECT"],
              "rule": "MATCH",
              "rulePayload": "",
              "metadata": {
                "network": "Udp",
                "type": "Socks5",
                "sourceIP": "127.0.0.1",
                "destinationIP": "1.1.1.1",
                "sourcePort": "12345",
                "destinationPort": "53",
                "host": "dns"
              }
            }
          ]
        }
        "#;
        let snapshot = ControllerClient::decode_connections_stream_message(raw).unwrap();
        assert_eq!(snapshot.connections[0].metadata.source_port, "52724");
        assert_eq!(snapshot.connections[0].metadata.destination_port, "443");
        assert_eq!(snapshot.connections[1].metadata.source_port, "12345");
        assert_eq!(snapshot.connections[1].metadata.destination_port, "53");
    }

    #[test]
    fn structured_logs_decode_request_fields() {
        let raw = r#"
        {
          "time": "2026-05-13T01:02:03Z",
          "level": "info",
          "message": "request accepted",
          "fields": [{"key": "rAddr", "value": "api.openai.com:443"}]
        }
        "#;
        let log = ControllerClient::decode_log_stream_message(raw).unwrap();
        assert_eq!(log.level, "info");
        assert_eq!(log.fields[0].key, "rAddr");
    }
}

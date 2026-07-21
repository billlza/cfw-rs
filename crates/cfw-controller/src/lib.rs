use std::collections::HashMap;
use std::time::Duration;

use futures_util::{StreamExt, stream};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerEndpoint {
    pub host: String,
    pub port: u16,
    pub secret: Option<String>,
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
        if self.host.trim().is_empty() {
            return Err(ControllerError::InvalidEndpoint("host is empty".into()));
        }
        Ok(format!("http://{}:{}", self.host, self.port))
    }

    pub fn websocket_url(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<String, ControllerError> {
        if self.host.trim().is_empty() {
            return Err(ControllerError::InvalidEndpoint("host is empty".into()));
        }

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

#[derive(Debug, Clone)]
pub struct ControllerClient {
    endpoint: ControllerEndpoint,
    http: reqwest::Client,
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
            .connect_timeout(Duration::from_millis(350))
            .timeout(Duration::from_secs(2))
            .pool_max_idle_per_host(4)
            .build()?;

        Ok(Self { endpoint, http })
    }

    pub async fn snapshot(&self) -> Result<ControllerSnapshot, ControllerError> {
        // Connections are best-effort: a brief TUN respawn must not wipe proxies.
        let (config, proxies) =
            futures_util::future::try_join(self.configs(), self.proxies()).await?;
        let connections = self.connections().await.unwrap_or_default();
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
        Ok(ProxiesSnapshot::from(response))
    }

    pub async fn providers(&self) -> Result<ProvidersSnapshot, ControllerError> {
        let (proxy_providers, rule_providers) =
            futures_util::future::try_join(self.proxy_providers(), self.rule_providers()).await?;
        Ok(ProvidersSnapshot {
            proxy_providers,
            rule_providers,
        })
    }

    pub async fn rules(&self) -> Result<RulesSnapshot, ControllerError> {
        self.get_json("/rules").await
    }

    pub async fn proxy_providers(&self) -> Result<Vec<ProviderEntry>, ControllerError> {
        let response: ProvidersResponse = self.get_json("/providers/proxies").await?;
        Ok(flatten_providers(response))
    }

    pub async fn rule_providers(&self) -> Result<Vec<ProviderEntry>, ControllerError> {
        let response: ProvidersResponse = self.get_json("/providers/rules").await?;
        Ok(flatten_providers(response))
    }

    pub async fn update_proxy_provider(&self, name: &str) -> Result<(), ControllerError> {
        self.put_empty(&provider_path("/providers/proxies", name, None))
            .await
    }

    pub async fn update_rule_provider(&self, name: &str) -> Result<(), ControllerError> {
        self.put_empty(&provider_path("/providers/rules", name, None))
            .await
    }

    pub async fn health_check_proxy_provider(&self, name: &str) -> Result<(), ControllerError> {
        self.put_empty(&provider_path(
            "/providers/proxies",
            name,
            Some("healthcheck"),
        ))
        .await
    }

    pub async fn update_all_proxy_providers(&self) -> Result<ProviderBatchResult, ControllerError> {
        let names = self
            .proxy_providers()
            .await?
            .into_iter()
            .map(|provider| provider.name)
            .collect::<Vec<_>>();
        let mut batch = ProviderBatchResult::new("update-proxy", names.len());
        for name in &names {
            batch.record(name, self.update_proxy_provider(name).await);
        }
        Ok(batch)
    }

    pub async fn update_all_rule_providers(&self) -> Result<ProviderBatchResult, ControllerError> {
        let names = self
            .rule_providers()
            .await?
            .into_iter()
            .map(|provider| provider.name)
            .collect::<Vec<_>>();
        let mut batch = ProviderBatchResult::new("update-rule", names.len());
        for name in &names {
            batch.record(name, self.update_rule_provider(name).await);
        }
        Ok(batch)
    }

    pub async fn health_check_all_proxy_providers(
        &self,
    ) -> Result<ProviderBatchResult, ControllerError> {
        let names = self
            .proxy_providers()
            .await?
            .into_iter()
            .map(|provider| provider.name)
            .collect::<Vec<_>>();
        let mut batch = ProviderBatchResult::new("health-check-proxy", names.len());
        for name in &names {
            batch.record(name, self.health_check_proxy_provider(name).await);
        }
        Ok(batch)
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
        match self
            .proxy_delay_at(
                &format!(
                    "/proxies/{}/delay?url={}&timeout={}",
                    urlencoding::encode(proxy),
                    urlencoding::encode(url),
                    timeout_ms
                ),
                timeout_ms,
            )
            .await
        {
            Ok(delay) => Ok(delay),
            // mihomo ≥1.19.28 no longer merges provider nodes into /proxies;
            // CFW falls back to /providers/proxies/{provider}/{name}/healthcheck.
            Err(ControllerError::Status { status: 404, .. }) => {
                self.proxy_delay_via_provider(proxy, url, timeout_ms).await
            }
            Err(error) => Err(error),
        }
    }

    async fn proxy_delay_via_provider(
        &self,
        proxy: &str,
        url: &str,
        timeout_ms: u16,
    ) -> Result<u32, ControllerError> {
        let provider = self
            .find_provider_name_for_proxy(proxy)
            .await?
            .ok_or_else(|| ControllerError::Status {
                status: 404,
                body: format!("proxy `{proxy}` not found in /proxies or providers"),
            })?;
        self.proxy_delay_at(
            &format!(
                "/providers/proxies/{}/{}/healthcheck?url={}&timeout={}",
                urlencoding::encode(&provider),
                urlencoding::encode(proxy),
                urlencoding::encode(url),
                timeout_ms
            ),
            timeout_ms,
        )
        .await
    }

    async fn find_provider_name_for_proxy(
        &self,
        proxy: &str,
    ) -> Result<Option<String>, ControllerError> {
        let raw: serde_json::Value = self.get_json("/providers/proxies").await?;
        let Some(providers) = raw.get("providers").and_then(|value| value.as_object()) else {
            return Ok(None);
        };
        for (provider_name, payload) in providers {
            let Some(list) = payload.get("proxies").and_then(|value| value.as_array()) else {
                continue;
            };
            for item in list {
                let name = item
                    .get("name")
                    .and_then(|value| value.as_str())
                    .or_else(|| item.as_str());
                if name == Some(proxy) {
                    return Ok(Some(provider_name.clone()));
                }
            }
        }
        Ok(None)
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
                            error: None,
                        },
                        Err(error) => ProxyDelayResult {
                            name,
                            delay: Some(0),
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
        self.get_json("/connections").await
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
        Ok(serde_json::from_str(raw)?)
    }

    pub fn decode_log_stream_message(raw: &str) -> Result<StructuredLogEntry, ControllerError> {
        Ok(serde_json::from_str(raw)?)
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

    async fn put_empty(&self, path: &str) -> Result<(), ControllerError> {
        let response = self.http.put(self.url(path)?).send().await?;
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

fn provider_path(prefix: &str, name: &str, suffix: Option<&str>) -> String {
    let mut path = format!("{}/{}", prefix, urlencoding::encode(name));
    if let Some(suffix) = suffix {
        path.push('/');
        path.push_str(suffix);
    }
    path
}

async fn decode_response<T>(response: reqwest::Response) -> Result<T, ControllerError>
where
    T: for<'de> Deserialize<'de>,
{
    let status = response.status();
    if !status.is_success() {
        return Err(ControllerError::Status {
            status: status.as_u16(),
            body: response.text().await.unwrap_or_default(),
        });
    }
    Ok(response.json::<T>().await?)
}

async fn decode_empty(response: reqwest::Response) -> Result<(), ControllerError> {
    let status = response.status();
    if !status.is_success() {
        return Err(ControllerError::Status {
            status: status.as_u16(),
            body: response.text().await.unwrap_or_default(),
        });
    }
    Ok(())
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleEntry {
    pub index: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub payload: String,
    pub proxy: String,
    pub size: i64,
    pub provider: Option<String>,
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for RuleEntry {
    fn default() -> Self {
        Self {
            index: 0,
            kind: String::new(),
            payload: String::new(),
            proxy: String::new(),
            size: -1,
            provider: None,
            extra: HashMap::new(),
        }
    }
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
struct ProvidersResponse {
    providers: HashMap<String, ProviderPayload>,
}

fn flatten_providers(response: ProvidersResponse) -> Vec<ProviderEntry> {
    let mut providers = response
        .providers
        .into_iter()
        .map(|(name, payload)| ProviderEntry {
            name,
            kind: payload.kind,
            vehicle_type: payload.vehicle_type,
            behavior: payload.behavior,
            updated_at: payload.updated_at,
            proxies: payload.proxies,
            rules: payload.rules,
            extra: payload.extra,
        })
        .collect::<Vec<_>>();
    providers.sort_by(|left, right| left.name.cmp(&right.name));
    providers
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct ProviderPayload {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "vehicleType", alias = "vehicle_type")]
    vehicle_type: String,
    pub behavior: Option<String>,
    #[serde(rename = "updatedAt", alias = "updated_at")]
    updated_at: Option<String>,
    pub proxies: Vec<String>,
    pub rules: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for ProviderPayload {
    fn default() -> Self {
        Self {
            kind: "Unknown".into(),
            vehicle_type: "Unknown".into(),
            behavior: None,
            updated_at: None,
            proxies: Vec::new(),
            rules: Vec::new(),
            extra: HashMap::new(),
        }
    }
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
    fn new(action: impl Into<String>, requested: usize) -> Self {
        Self {
            action: action.into(),
            requested,
            succeeded: Vec::with_capacity(requested),
            failed: Vec::new(),
        }
    }

    fn record(&mut self, name: &str, result: Result<(), ControllerError>) {
        match result {
            Ok(()) => self.succeeded.push(name.to_string()),
            Err(error) => self.failed.push(ProviderBatchFailure {
                name: name.to_string(),
                error: error.to_string(),
            }),
        }
    }

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
    #[serde(rename = "sourcePort", alias = "source_port")]
    pub source_port: String,
    #[serde(rename = "destinationPort", alias = "destination_port")]
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
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DelayResponse {
    delay: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_rejects_empty_host() {
        let endpoint = ControllerEndpoint::new("", 9090, None);
        assert!(endpoint.base_url().is_err());
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
    fn providers_response_flattens_names() {
        let raw = r#"
        {
          "providers": {
            "airport": {"type":"Proxy","vehicleType":"HTTP","updatedAt":"2026-05-13T01:02:03Z","proxies":["HK","JP"]},
            "apple": {"type":"Rule","vehicleType":"HTTP","behavior":"domain","rules":["DOMAIN-SUFFIX,apple.com"]}
          }
        }
        "#;
        let response: ProvidersResponse = serde_json::from_str(raw).unwrap();
        let providers = flatten_providers(response);
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0].name, "airport");
        assert_eq!(providers[0].proxies.len(), 2);
        assert_eq!(providers[1].behavior.as_deref(), Some("domain"));
    }

    #[test]
    fn provider_action_paths_are_percent_encoded() {
        assert_eq!(
            provider_path("/providers/proxies", "Airport HK", Some("healthcheck")),
            "/providers/proxies/Airport%20HK/healthcheck"
        );
        assert_eq!(
            provider_path("/providers/rules", "Apple/Rule", None),
            "/providers/rules/Apple%2FRule"
        );
    }

    #[test]
    fn provider_batch_result_keeps_partial_failures() {
        let mut batch = ProviderBatchResult::new("update-proxy", 2);
        batch.record("airport-a", Ok(()));
        batch.record(
            "airport-b",
            Err(ControllerError::Status {
                status: 500,
                body: "provider failed".into(),
            }),
        );

        assert!(!batch.is_complete_success());
        assert_eq!(batch.requested, 2);
        assert_eq!(batch.succeeded, vec!["airport-a"]);
        assert_eq!(batch.failed.len(), 1);
        assert_eq!(batch.failed[0].name, "airport-b");
        assert!(batch.failed[0].error.contains("HTTP 500"));
    }

    #[test]
    fn rules_snapshot_decodes_controller_rules() {
        let raw = r#"
        {
          "rules": [
            {
              "index": 7,
              "type": "DomainSuffix",
              "payload": "example.com",
              "proxy": "Proxy",
              "size": -1,
              "extra": {"hitCount": 3}
            }
          ]
        }
        "#;
        let snapshot: RulesSnapshot = serde_json::from_str(raw).unwrap();
        assert_eq!(snapshot.rules.len(), 1);
        assert_eq!(snapshot.rules[0].index, 7);
        assert_eq!(snapshot.rules[0].kind, "DomainSuffix");
        assert_eq!(
            snapshot.rules[0].extra.get("hitCount"),
            Some(&serde_json::json!(3))
        );
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

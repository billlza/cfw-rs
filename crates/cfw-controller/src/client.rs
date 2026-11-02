//! The HTTP client of the Clash-compatible controller API.

use std::fmt;
use std::time::Duration;

use futures_util::{StreamExt, stream};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};

use crate::config::ConfigReloadRequest;
use crate::error::unsupported_provider_subsystem;
use crate::proxies::{DelayResponse, ProxiesResponse, SelectProxyRequest};
use crate::response::{decode_empty, decode_response, validate_connections};
use crate::{
    ClashConfig, ConfigPatch, ConnectionsSnapshot, ControllerEndpoint, ControllerError,
    ControllerSnapshot, ControllerVersion, MAX_CONTROLLER_LOG_FIELDS, MAX_CONTROLLER_PROXIES,
    MAX_CONTROLLER_RULES, ProviderBatchResult, ProviderEntry, ProvidersSnapshot, ProxiesSnapshot,
    ProxyDelayFailureKind, ProxyDelayResult, RulesSnapshot, StructuredLogEntry,
};

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

        // reqwest's workspace TLS feature requires a provider even for HTTP.
        // Configure this client explicitly instead of depending on host-global
        // initialization. Controller URLs are HTTP and redirects are refused;
        // an empty trust store also gives this client no external TLS authority.
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|error| ControllerError::InvalidEndpoint(error.to_string()))?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
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
        // strict 1.14.4 profile schema cannot construct a provider subsystem;
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
        self.proxy_delay_matching(proxy, url, timeout_ms, "").await
    }

    pub async fn proxy_delay_matching(
        &self,
        proxy: &str,
        url: &str,
        timeout_ms: u16,
        expected_status: &str,
    ) -> Result<u32, ControllerError> {
        self.proxy_delay_at(
            &format!(
                "/proxies/{}/delay?url={}&timeout={}&expected={}",
                urlencoding::encode(proxy),
                urlencoding::encode(url),
                timeout_ms,
                urlencoding::encode(expected_status)
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

#[cfg(test)]
mod tests;

//! Fixed HTTPS destinations, no redirects, ambient proxy, cookie jar or retry.
use super::types::{
    HttpObservation, IpInformation, Observation, Route, ServiceObservation, Trace, validate_text,
};
use reqwest::{Client, Response};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub(super) const BODY_LIMIT: usize = 32 * 1024;

pub(super) fn client(route: Route) -> Result<Client, String> {
    let mut builder = crate::transport_security::external_https_client_builder()
        .map_err(|error| error.to_string())?
        .no_proxy()
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .pool_max_idle_per_host(0)
        .referer(false)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .user_agent(concat!(
            "Clash-for-Mac/",
            env!("CARGO_PKG_VERSION"),
            " ConnectionDiagnostics"
        ));
    if let Route::EngineProxy { port } = route {
        // Remote DNS is intentional: this measures the engine's domain rules
        // and DNS policy, not the host's independent DNS path.
        builder = builder.proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
                .map_err(|_| "diagnostic proxy could not be configured")?,
        );
    }
    builder
        .build()
        .map_err(|_| "diagnostic HTTPS client could not be created".into())
}

fn transport_failure(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection_failed"
    } else {
        "request_failed"
    }
}

pub(super) async fn body(mut response: Response) -> Result<Vec<u8>, &'static str> {
    if !response.status().is_success() {
        return Err("http_refused");
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|value| value != "identity")
    {
        return Err("unsupported_encoding");
    }
    if response
        .content_length()
        .is_some_and(|size| size > BODY_LIMIT as u64)
    {
        return Err("response_too_large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| transport_failure(&error))?
    {
        if chunk.len() > BODY_LIMIT - bytes.len() {
            return Err("response_too_large");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(super) async fn get(client: &Client, url: &str) -> Result<Vec<u8>, &'static str> {
    body(
        client
            .get(url)
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(|error| transport_failure(&error))?,
    )
    .await
}

pub(super) fn parse_trace(bytes: &[u8]) -> Result<Trace, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid_response")?;
    let mut ip = None;
    let mut country = None;
    let mut colo = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "ip" => {
                if ip.is_some() {
                    return Err("invalid_response");
                }
                ip = Some(value.parse::<IpAddr>().map_err(|_| "invalid_response")?);
            }
            "loc" if value.len() == 2 && value.bytes().all(|b| b.is_ascii_uppercase()) => {
                country = Some(value.to_owned())
            }
            "colo" if value.len() == 3 && value.bytes().all(|b| b.is_ascii_uppercase()) => {
                colo = Some(value.to_owned())
            }
            _ => {}
        }
    }
    Ok(Trace {
        ip: ip.ok_or("invalid_response")?,
        country,
        colo,
    })
}

pub(super) async fn trace(client: &Client, url: &str) -> Observation<Trace> {
    match get(client, url).await {
        Ok(bytes) => parse_trace(&bytes).into(),
        Err(reason) => Observation::Failed { reason },
    }
}

pub(super) async fn ip_echo(client: &Client, url: &str, ipv6: bool) -> Observation<IpAddr> {
    async {
        let bytes = get(client, url).await?;
        let ip: IpAddr = std::str::from_utf8(&bytes)
            .map_err(|_| "invalid_response")?
            .trim()
            .parse()
            .map_err(|_| "invalid_response")?;
        if ip.is_ipv6() != ipv6 {
            return Err("wrong_address_family");
        }
        Ok(ip)
    }
    .await
    .into()
}

async fn service(
    client: &Client,
    name: &'static str,
    host: &'static str,
    url: &'static str,
    trace_url: Option<&str>,
) -> ServiceObservation {
    let started = Instant::now();
    let response = match client.head(url).send().await {
        Ok(response) => Observation::Observed {
            value: HttpObservation {
                http_status: response.status().as_u16(),
                elapsed_ms: started.elapsed().as_millis() as u64,
            },
        },
        Err(error) => Observation::Failed {
            reason: transport_failure(&error),
        },
    };
    let egress = match trace_url {
        Some(url) => Some(trace(client, url).await),
        None => None,
    };
    ServiceObservation {
        name,
        host,
        response,
        egress,
    }
}

pub(super) async fn services(client: &Client) -> Vec<ServiceObservation> {
    let (claude, chatgpt, anthropic, cloudflare) = tokio::join!(
        service(
            client,
            "Claude",
            "claude.ai",
            "https://claude.ai/",
            Some("https://claude.ai/cdn-cgi/trace")
        ),
        service(
            client,
            "ChatGPT",
            "chatgpt.com",
            "https://chatgpt.com/",
            Some("https://chatgpt.com/cdn-cgi/trace")
        ),
        service(
            client,
            "Anthropic",
            "www.anthropic.com",
            "https://www.anthropic.com/",
            None
        ),
        service(
            client,
            "Cloudflare",
            "www.cloudflare.com",
            "https://www.cloudflare.com/",
            None
        ),
    );
    vec![claude, chatgpt, anthropic, cloudflare]
}

pub(crate) async fn lookup_ip(route: Route, ip: IpAddr) -> Result<IpInformation, &'static str> {
    let client = client(route).map_err(|_| "client_unavailable")?;
    let response = client
        .get(format!("https://api.ipapi.is/?q={ip}"))
        .send()
        .await
        .map_err(|error| transport_failure(&error))?;
    // Respect provider quotas. The command gate blocks further attempts for a
    // day on either refusal, and the UI never retries a lookup automatically.
    if matches!(response.status().as_u16(), 403 | 429) {
        return Err("provider_rate_limited");
    }
    parse_ip_information(&body(response).await?, ip)
}

pub(super) fn parse_ip_information(
    bytes: &[u8],
    expected: IpAddr,
) -> Result<IpInformation, &'static str> {
    let value: IpInformation = serde_json::from_slice(bytes).map_err(|_| "invalid_response")?;
    if value.ip != expected
        || [
            &value.company,
            &value.asn,
            &value.city,
            &value.region,
            &value.country,
            &value.timezone,
        ]
        .into_iter()
        .flatten()
        .any(|text| !validate_text(text))
    {
        return Err("invalid_response");
    }
    Ok(value)
}

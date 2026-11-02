//! A Clash proxy's `network` and its option mapping, as the typed transport.

use serde_json::Value;

use super::{ProxyFields, normalize_v2ray_http_method, transport_from_parts};

/// Maps `network` plus its option mapping onto the typed transport shape.
pub(super) fn collect_transport(fields: &mut ProxyFields) -> Result<Option<Value>, String> {
    let network = fields.take_string("network")?.unwrap_or_default();
    let ws_opts = fields.take("ws-opts");
    let grpc_opts = fields.take("grpc-opts");
    let h2_opts = fields.take("h2-opts");
    let http_opts = fields.take("http-opts");
    let http_upgrade_opts = fields.take("http-upgrade-opts");
    if ws_opts.is_some() && network != "ws" {
        return Err(format!(
            "{} declares ws-opts without network: ws",
            fields.context()
        ));
    }
    if grpc_opts.is_some() && network != "grpc" {
        return Err(format!(
            "{} declares grpc-opts without network: grpc",
            fields.context()
        ));
    }
    if h2_opts.is_some() && !matches!(network.as_str(), "h2" | "http") {
        return Err(format!(
            "{} declares h2-opts without network: h2",
            fields.context()
        ));
    }
    if http_opts.is_some() && network != "http" {
        return Err(format!(
            "{} declares http-opts without network: http",
            fields.context()
        ));
    }
    if http_upgrade_opts.is_some() && !matches!(network.as_str(), "httpupgrade" | "http-upgrade") {
        return Err(format!(
            "{} declares http-upgrade-opts without network: httpupgrade",
            fields.context()
        ));
    }
    match network.as_str() {
        "" | "tcp" => Ok(None),
        "h2" => {
            let (path, host) = match h2_opts {
                None => (None, None),
                Some(value) => {
                    let mut options = ProxyFields::from_nested(value, fields, "h2-opts")?;
                    let path = take_single_transport_value(&mut options, "path")?;
                    let host = options
                        .take_string_or_list("host")?
                        .map(|hosts| hosts.join(","));
                    options.reject_leftovers()?;
                    (path, host)
                }
            };
            transport_from_parts("http", path, host, None, None)
        }
        "http" => {
            if http_opts.is_some() && h2_opts.is_some() {
                return Err(format!(
                    "{} declares both http-opts and h2-opts for network: http",
                    fields.context()
                ));
            }
            let (path, host, method) = if let Some(value) = http_opts {
                let mut options = ProxyFields::from_nested(value, fields, "http-opts")?;
                let path = take_single_transport_value(&mut options, "path")?;
                let method = options
                    .take_string("method")?
                    .filter(|value| !value.is_empty())
                    .map(|value| normalize_v2ray_http_method(&value, "Mihomo HTTP method"))
                    .transpose()?
                    .or_else(|| Some("GET".to_owned()));
                let host = match options.take("headers") {
                    None => None,
                    Some(headers) => {
                        let mut headers = ProxyFields::from_nested(headers, &options, "headers")?;
                        let upper = headers.take_string_or_list("Host")?;
                        let lower = headers.take_string_or_list("host")?;
                        let host = match (upper, lower) {
                            (Some(a), Some(b)) if a != b => {
                                return Err(format!(
                                    "{} declares conflicting Host header values",
                                    headers.context()
                                ));
                            }
                            (a, b) => a.or(b).map(|values| values.join(",")),
                        };
                        headers.reject_leftovers()?;
                        host
                    }
                };
                options.reject_leftovers()?;
                (path, host, method)
            } else {
                let (path, host) = match h2_opts {
                    None => (None, None),
                    Some(value) => {
                        let mut options = ProxyFields::from_nested(value, fields, "h2-opts")?;
                        let path = take_single_transport_value(&mut options, "path")?;
                        let host = options
                            .take_string_or_list("host")?
                            .map(|hosts| hosts.join(","));
                        options.reject_leftovers()?;
                        (path, host)
                    }
                };
                (path, host, Some("GET".to_owned()))
            };
            transport_from_parts("http", path, host, None, method)
        }
        "ws" => {
            let (path, host) = match ws_opts {
                None => (None, None),
                Some(value) => {
                    let mut options = ProxyFields::from_nested(value, fields, "ws-opts")?;
                    let path = options.take_string("path")?;
                    let host = match options.take("headers") {
                        None => None,
                        Some(headers) => {
                            let mut headers =
                                ProxyFields::from_nested(headers, &options, "headers")?;
                            let host = match (
                                headers.take_string("Host")?,
                                headers.take_string("host")?,
                            ) {
                                (Some(a), Some(b)) if a != b => {
                                    return Err(format!(
                                        "{} declares conflicting Host header values",
                                        headers.context()
                                    ));
                                }
                                (a, b) => a.or(b),
                            };
                            headers.reject_leftovers()?;
                            host
                        }
                    };
                    options.reject_leftovers()?;
                    (path, host)
                }
            };
            transport_from_parts("ws", path, host, None, None)
        }
        "grpc" => {
            let service_name = match grpc_opts {
                None => None,
                Some(value) => {
                    let mut options = ProxyFields::from_nested(value, fields, "grpc-opts")?;
                    let service_name = options.take_string("grpc-service-name")?;
                    options.reject_leftovers()?;
                    service_name
                }
            };
            transport_from_parts("grpc", None, None, service_name, None)
        }
        "quic" => transport_from_parts("quic", None, None, None, None),
        "httpupgrade" | "http-upgrade" => {
            let (path, host) = match http_upgrade_opts {
                None => (None, None),
                Some(value) => {
                    let mut options = ProxyFields::from_nested(value, fields, "http-upgrade-opts")?;
                    let path = options.take_string("path")?;
                    let host = options.take_string("host")?;
                    options.reject_leftovers()?;
                    (path, host)
                }
            };
            transport_from_parts("httpupgrade", path, host, None, None)
        }
        other => transport_from_parts(other, None, None, None, None),
    }
}

pub(super) fn take_single_transport_value(
    fields: &mut ProxyFields,
    key: &str,
) -> Result<Option<String>, String> {
    let Some(values) = fields.take_string_or_list(key)? else {
        return Ok(None);
    };
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(value.clone())),
        _ => Err(format!(
            "{}.{key} declares multiple alternatives that cannot be projected deterministically",
            fields.context()
        )),
    }
}

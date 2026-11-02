//! Hysteria2 share links, and the port hopping and congestion options every
//! Hysteria2 source shares.

use reqwest::Url;

pub(super) fn parse_hysteria2_share_url(entry: &str) -> Result<(Url, Option<Vec<String>>), String> {
    let scheme_end = entry
        .find("://")
        .ok_or_else(|| "subscription Hysteria2 URI is invalid".to_owned())?;
    if !matches!(
        entry[..scheme_end].to_ascii_lowercase().as_str(),
        "hysteria2" | "hy2"
    ) {
        return Err("subscription Hysteria2 URI is invalid".to_owned());
    }
    let authority_start = scheme_end + 3;
    let authority_end = entry[authority_start..]
        .find(['/', '?', '#'])
        .map(|offset| authority_start + offset)
        .unwrap_or(entry.len());
    let authority = &entry[authority_start..authority_end];
    let host_port_start = authority.rfind('@').map(|index| index + 1).unwrap_or(0);
    let host_port = &authority[host_port_start..];
    let port_start = if host_port.starts_with('[') {
        let close = host_port
            .find(']')
            .ok_or_else(|| "subscription Hysteria2 URI is invalid".to_owned())?;
        match host_port[close + 1..].strip_prefix(':') {
            Some(_) => Some(close + 2),
            None if close + 1 == host_port.len() => None,
            None => return Err("subscription Hysteria2 URI is invalid".to_owned()),
        }
    } else {
        match host_port.rfind(':') {
            Some(index) if !host_port[..index].contains(':') => Some(index + 1),
            Some(_) => return Err("subscription Hysteria2 IPv6 host must be bracketed".to_owned()),
            None => None,
        }
    };
    let Some(port_start) = port_start else {
        return Url::parse(entry)
            .map(|url| (url, None))
            .map_err(|_| "subscription Hysteria2 URI is invalid".to_owned());
    };
    let port_text = &host_port[port_start..];
    if !port_text.contains([',', '-']) {
        return Url::parse(entry)
            .map(|url| (url, None))
            .map_err(|_| "subscription Hysteria2 URI is invalid".to_owned());
    }

    let server_ports = normalize_hysteria2_server_ports(port_text, "Hysteria2 URI port set")?;
    let first_port = server_ports[0]
        .split_once(':')
        .map(|(start, _end)| start)
        .unwrap_or(&server_ports[0]);
    let absolute_port_start = authority_start + host_port_start + port_start;
    let normalized = format!(
        "{}{first_port}{}",
        &entry[..absolute_port_start],
        &entry[authority_end..]
    );
    Url::parse(&normalized)
        .map(|url| (url, Some(server_ports)))
        .map_err(|_| "subscription Hysteria2 URI is invalid".to_owned())
}

pub(super) fn normalize_hysteria2_server_ports(
    value: &str,
    label: &str,
) -> Result<Vec<String>, String> {
    const MAX_ITEMS: usize = 64;
    let parse_port = |value: &str| {
        value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0 && port.to_string() == value)
    };
    let mut normalized = Vec::new();
    let mut intervals = Vec::new();
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() || normalized.len() == MAX_ITEMS {
            return Err(format!("{label} has an invalid item count"));
        }
        let range = match (item.split_once('-'), item.split_once(':')) {
            (Some(range), None) | (None, Some(range)) => Some(range),
            (None, None) => None,
            _ => return Err(format!("{label} has an invalid range")),
        };
        let (canonical, interval) = match range {
            Some((start, end)) => match (parse_port(start), parse_port(end)) {
                (Some(start), Some(end)) if start < end => (format!("{start}:{end}"), (start, end)),
                _ => return Err(format!("{label} has an invalid range")),
            },
            None => match parse_port(item) {
                Some(port) => (port.to_string(), (port, port)),
                None => return Err(format!("{label} has an invalid port")),
            },
        };
        if intervals
            .iter()
            .any(|(start, end)| interval.0 <= *end && *start <= interval.1)
        {
            return Err(format!("{label} has overlapping items"));
        }
        normalized.push(canonical);
        intervals.push(interval);
    }
    // `split` yields at least one item and an empty item is refused, so the
    // list is never empty here.
    Ok(normalized)
}

pub(super) fn parse_hysteria2_hop_interval_seconds(
    value: &str,
    label: &str,
) -> Result<u32, String> {
    let value = value.strip_suffix('s').unwrap_or(value);
    value
        .parse::<u32>()
        .ok()
        .filter(|seconds| (1..=3_600).contains(seconds) && seconds.to_string() == value)
        .ok_or_else(|| format!("{label} must be a canonical 1..=3600 second value"))
}

/// Parses a Hysteria2 hop interval written as `N` or as Mihomo's `N-M` range.
/// Bounds and ordering are left to the profile model, which names the field.
pub(super) fn parse_hysteria2_hop_interval_range(
    value: &str,
    label: &str,
) -> Result<(u32, Option<u32>), String> {
    match value.split_once('-') {
        None => Ok((parse_hysteria2_hop_interval_seconds(value, label)?, None)),
        Some((minimum, maximum)) => {
            let minimum = parse_hysteria2_hop_interval_seconds(minimum, label)?;
            let maximum = parse_hysteria2_hop_interval_seconds(maximum, label)?;
            Ok((minimum, (maximum != minimum).then_some(maximum)))
        }
    }
}

pub(super) fn parse_hysteria2_bbr_profile(
    value: &str,
    label: &str,
) -> Result<&'static str, String> {
    match value {
        "standard" => Ok("standard"),
        "conservative" => Ok("conservative"),
        "aggressive" => Ok("aggressive"),
        _ => Err(format!(
            "{label} must be standard, conservative or aggressive"
        )),
    }
}

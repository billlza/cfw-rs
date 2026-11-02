//! Hysteria2 port hopping and obfuscation bounds.

use super::unsupported_shape;
use crate::ConfigError;
use crate::profile::{Hysteria2Obfs, Hysteria2ObfsType};

const MAX_HYSTERIA2_SERVER_PORT_ITEMS: usize = 64;
// The pinned sing-quic refuses to dial a hop interval below five seconds.
const MIN_HYSTERIA2_HOP_INTERVAL_SECONDS: u32 = 5;
const MAX_HYSTERIA2_HOP_INTERVAL_SECONDS: u32 = 3_600;
// sing-quic's gecko defaults and its on-wire packet bound.
const GECKO_DEFAULT_MIN_PACKET_SIZE: u16 = 512;
const GECKO_DEFAULT_MAX_PACKET_SIZE: u16 = 1_200;
const GECKO_MAX_PACKET_SIZE: u16 = 2_048;

pub(super) fn validate_hysteria2_hop_interval(
    has_server_ports: bool,
    minimum: Option<u32>,
    maximum: Option<u32>,
    path: &str,
) -> Result<(), ConfigError> {
    let hopping = MIN_HYSTERIA2_HOP_INTERVAL_SECONDS..=MAX_HYSTERIA2_HOP_INTERVAL_SECONDS;
    if let Some(minimum) = minimum {
        if !has_server_ports {
            return Err(unsupported_shape(
                format!("{path}.hop_interval_seconds"),
                "hop interval requires server_ports",
            ));
        }
        if !hopping.contains(&minimum) {
            return Err(unsupported_shape(
                format!("{path}.hop_interval_seconds"),
                "hop interval must be between 5 and 3600 seconds",
            ));
        }
    }
    if let Some(maximum) = maximum {
        let Some(minimum) = minimum else {
            return Err(unsupported_shape(
                format!("{path}.hop_interval_max_seconds"),
                "hop interval maximum requires hop_interval_seconds",
            ));
        };
        if !(minimum..=MAX_HYSTERIA2_HOP_INTERVAL_SECONDS).contains(&maximum) {
            return Err(unsupported_shape(
                format!("{path}.hop_interval_max_seconds"),
                "hop interval maximum must be between hop_interval_seconds and 3600 seconds",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_hysteria2_obfs_packet_sizes(
    obfs: &Hysteria2Obfs,
    path: &str,
) -> Result<(), ConfigError> {
    let sized = obfs.min_packet_size.is_some() || obfs.max_packet_size.is_some();
    match obfs.kind {
        Hysteria2ObfsType::Salamander if sized => Err(unsupported_shape(
            format!("{path}.obfs"),
            "packet sizes apply only to gecko obfs",
        )),
        Hysteria2ObfsType::Salamander => Ok(()),
        Hysteria2ObfsType::Gecko => {
            let minimum = obfs
                .min_packet_size
                .unwrap_or(GECKO_DEFAULT_MIN_PACKET_SIZE);
            let maximum = obfs
                .max_packet_size
                .unwrap_or(GECKO_DEFAULT_MAX_PACKET_SIZE);
            if minimum == 0 || minimum > maximum || maximum > GECKO_MAX_PACKET_SIZE {
                return Err(unsupported_shape(
                    format!("{path}.obfs"),
                    "gecko packet sizes must satisfy 1 <= min <= max <= 2048 (defaults 512 and 1200)",
                ));
            }
            Ok(())
        }
    }
}

pub(super) fn validate_hysteria2_server_ports(
    server_ports: Option<&[String]>,
    path: &str,
) -> Result<(), ConfigError> {
    let Some(server_ports) = server_ports else {
        return Ok(());
    };
    if server_ports.is_empty() || server_ports.len() > MAX_HYSTERIA2_SERVER_PORT_ITEMS {
        return Err(unsupported_shape(
            format!("{path}.server_ports"),
            "server_ports must contain between 1 and 64 canonical items",
        ));
    }
    let mut intervals = Vec::with_capacity(server_ports.len());
    for (index, item) in server_ports.iter().enumerate() {
        let parse_port = |value: &str| {
            value
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0 && port.to_string() == value)
        };
        let interval = match item.split_once(':') {
            Some((start, end)) => match (parse_port(start), parse_port(end)) {
                (Some(start), Some(end)) if start < end => (start, end),
                _ => {
                    return Err(unsupported_shape(
                        format!("{path}.server_ports[{index}]"),
                        "port range must use canonical start:end syntax",
                    ));
                }
            },
            None => match parse_port(item) {
                Some(port) => (port, port),
                None => {
                    return Err(unsupported_shape(
                        format!("{path}.server_ports[{index}]"),
                        "port must be a canonical nonzero decimal integer",
                    ));
                }
            },
        };
        if intervals
            .iter()
            .any(|(start, end)| interval.0 <= *end && *start <= interval.1)
        {
            return Err(unsupported_shape(
                format!("{path}.server_ports[{index}]"),
                "server port items must not overlap",
            ));
        }
        intervals.push(interval);
    }
    Ok(())
}

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, TcpListener};

use cfw_platform::{MacOsPlatformService, NetworkProxyProtocolObservation};
use cfw_singbox_config::{DEFAULT_CLASH_API_PORT, DEFAULT_MIXED_PORT, EngineSettings};
use thiserror::Error;

const CANDIDATE_COUNT: u16 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndpointRole {
    Mixed,
    Controller,
}

impl std::fmt::Display for EndpointRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Mixed => "mixed proxy",
            Self::Controller => "controller",
        })
    }
}

#[derive(Debug, Error)]
pub(super) enum EndpointSelectionError {
    #[error("failed to observe current System Proxy ownership: {0}")]
    Observation(String),
    #[error("an enabled {protocol} proxy has no complete endpoint")]
    IncompleteExternalProxy { protocol: &'static str },
    #[error("failed to test 127.0.0.1:{port} for the {role}: {source}")]
    Probe {
        role: EndpointRole,
        port: u16,
        #[source]
        source: io::Error,
    },
    #[error("no bounded loopback TCP port is available for the {role}")]
    Exhausted { role: EndpointRole },
}

pub(super) fn select_process_engine_settings(
    settings: EngineSettings,
) -> Result<EngineSettings, EndpointSelectionError> {
    let services = MacOsPlatformService
        .observe_network_services()
        .map_err(|error| EndpointSelectionError::Observation(error.to_string()))?;
    select_settings_with(settings, &services, probe_loopback_tcp)
}

fn select_settings_with(
    mut settings: EngineSettings,
    services: &[cfw_platform::NetworkServiceObservation],
    mut probe: impl FnMut(u16) -> io::Result<()>,
) -> Result<EngineSettings, EndpointSelectionError> {
    let reserved = reserved_external_proxy_ports(services)?;
    let mixed_candidates = candidate_ports(DEFAULT_MIXED_PORT);
    let controller_candidates = candidate_ports(DEFAULT_CLASH_API_PORT);
    settings.mixed_port = select_port(
        EndpointRole::Mixed,
        &mixed_candidates,
        &reserved,
        &mut probe,
    )?;
    let mut controller_reserved = reserved;
    controller_reserved.insert(settings.mixed_port);
    settings.controller_port = select_port(
        EndpointRole::Controller,
        &controller_candidates,
        &controller_reserved,
        &mut probe,
    )?;
    Ok(settings)
}

fn candidate_ports(preferred: u16) -> [u16; CANDIDATE_COUNT as usize] {
    std::array::from_fn(|index| {
        preferred
            .checked_add(u16::try_from(index).expect("candidate index is bounded"))
            .expect("fixed endpoint candidate range fits in u16")
    })
}

fn reserved_external_proxy_ports(
    services: &[cfw_platform::NetworkServiceObservation],
) -> Result<BTreeSet<u16>, EndpointSelectionError> {
    let mut reserved = BTreeSet::new();
    for service in services {
        for (protocol, observation) in [
            ("HTTP", &service.web),
            ("HTTPS", &service.secure_web),
            ("SOCKS", &service.socks),
        ] {
            reserve_external_proxy_port(&mut reserved, protocol, observation)?;
        }
    }
    Ok(reserved)
}

fn reserve_external_proxy_port(
    reserved: &mut BTreeSet<u16>,
    protocol: &'static str,
    observation: &NetworkProxyProtocolObservation,
) -> Result<(), EndpointSelectionError> {
    if !observation.enabled {
        return Ok(());
    }
    let (Some(server), Some(port)) = (observation.server.as_deref(), observation.port) else {
        return Err(EndpointSelectionError::IncompleteExternalProxy { protocol });
    };
    if is_loopback_server(server) {
        reserved.insert(port);
    }
    Ok(())
}

fn is_loopback_server(server: &str) -> bool {
    let normalized = server.trim().trim_end_matches('.');
    normalized.eq_ignore_ascii_case("localhost")
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn select_port(
    role: EndpointRole,
    candidates: &[u16],
    reserved: &BTreeSet<u16>,
    mut probe: impl FnMut(u16) -> io::Result<()>,
) -> Result<u16, EndpointSelectionError> {
    for &port in candidates {
        if port == 0 || reserved.contains(&port) {
            continue;
        }
        match probe(port) {
            Ok(()) => return Ok(port),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(source) => return Err(EndpointSelectionError::Probe { role, port, source }),
        }
    }
    Err(EndpointSelectionError::Exhausted { role })
}

fn probe_loopback_tcp(port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))?;
    drop(listener);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_platform::{NetworkProxyProtocolObservation, NetworkServiceObservation};
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn service(protocol: NetworkProxyProtocolObservation) -> NetworkServiceObservation {
        NetworkServiceObservation {
            service_id: "service-id".into(),
            display_name: "Wi-Fi".into(),
            order: 0,
            web: protocol,
            secure_web: NetworkProxyProtocolObservation::default(),
            socks: NetworkProxyProtocolObservation::default(),
            pac_enabled: false,
            wpad_enabled: false,
        }
    }

    #[test]
    fn external_loopback_proxy_port_is_reserved_even_without_a_listener() {
        let reserved = reserved_external_proxy_ports(&[service(NetworkProxyProtocolObservation {
            enabled: true,
            server: Some("localhost.".into()),
            port: Some(7890),
        })])
        .expect("external proxy observation");
        let mut probed = Vec::new();
        let selected = select_port(EndpointRole::Mixed, &[7890, 7891], &reserved, |port| {
            probed.push(port);
            Ok(())
        })
        .expect("fallback port");
        assert_eq!(selected, 7891);
        assert_eq!(probed, [7891]);
    }

    #[test]
    fn process_settings_select_mixed_and_controller_from_one_bounded_policy() {
        let services = [service(NetworkProxyProtocolObservation {
            enabled: true,
            server: Some("127.0.0.1".into()),
            port: Some(DEFAULT_MIXED_PORT),
        })];
        let mut probed = Vec::new();
        let selected = select_settings_with(EngineSettings::default(), &services, |port| {
            probed.push(port);
            if port == DEFAULT_CLASH_API_PORT {
                Err(io::Error::from(io::ErrorKind::AddrInUse))
            } else {
                Ok(())
            }
        })
        .expect("bounded endpoint tuple");
        assert_eq!(selected.mixed_port, DEFAULT_MIXED_PORT + 1);
        assert_eq!(selected.controller_port, DEFAULT_CLASH_API_PORT + 1);
        assert_eq!(
            probed,
            [
                DEFAULT_MIXED_PORT + 1,
                DEFAULT_CLASH_API_PORT,
                DEFAULT_CLASH_API_PORT + 1
            ]
        );
    }

    #[test]
    fn enabled_proxy_requires_a_complete_endpoint() {
        let error = reserved_external_proxy_ports(&[service(NetworkProxyProtocolObservation {
            enabled: true,
            server: Some("127.0.0.1".into()),
            port: None,
        })])
        .expect_err("incomplete proxy must fail closed");
        assert!(matches!(
            error,
            EndpointSelectionError::IncompleteExternalProxy { .. }
        ));
    }

    #[test]
    fn address_in_use_is_the_only_probe_error_that_advances() {
        let mut probes = Vec::new();
        let selected = select_port(
            EndpointRole::Mixed,
            &[7890, 7891],
            &BTreeSet::new(),
            |port| {
                probes.push(port);
                if port == 7890 {
                    Err(io::Error::from(io::ErrorKind::AddrInUse))
                } else {
                    Ok(())
                }
            },
        )
        .expect("second candidate");
        assert_eq!(selected, 7891);
        assert_eq!(probes, [7890, 7891]);

        let error = select_port(EndpointRole::Mixed, &[7890, 7891], &BTreeSet::new(), |_| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .expect_err("unexpected probe failure");
        assert!(matches!(
            error,
            EndpointSelectionError::Probe { port: 7890, .. }
        ));
    }

    #[test]
    fn exhausted_candidates_return_a_typed_failure() {
        let error = select_port(
            EndpointRole::Controller,
            &[9090, 9091],
            &BTreeSet::new(),
            |_| Err(io::Error::from(io::ErrorKind::AddrInUse)),
        )
        .expect_err("all candidates are occupied");
        assert!(matches!(
            error,
            EndpointSelectionError::Exhausted {
                role: EndpointRole::Controller
            }
        ));
    }

    #[test]
    fn real_tcp_listener_is_not_disturbed_and_next_candidate_is_selected() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("occupied listener");
        let occupied_port = occupied.local_addr().expect("occupied address").port();
        let available = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("candidate listener");
        let available_port = available.local_addr().expect("candidate address").port();
        drop(available);

        let selected = select_port(
            EndpointRole::Mixed,
            &[occupied_port, available_port],
            &BTreeSet::new(),
            probe_loopback_tcp,
        )
        .expect("available real port");
        assert_eq!(selected, available_port);
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, occupied_port))
            .expect("foreign listener still accepts connections");
        let (mut accepted, _) = occupied.accept().expect("accept foreign connection");
        client.write_all(b"x").expect("write foreign connection");
        let mut byte = [0_u8; 1];
        accepted
            .read_exact(&mut byte)
            .expect("read foreign connection");
        assert_eq!(byte, *b"x");
        let rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, selected))
            .expect("successful probe releases the selected candidate");
        assert_eq!(
            rebound.local_addr().expect("selected address").port(),
            selected
        );
    }

    #[test]
    fn mixed_exhaustion_never_probes_the_controller_range() {
        let mut probes = Vec::new();
        let error = select_settings_with(EngineSettings::default(), &[], |port| {
            probes.push(port);
            Err(io::Error::from(io::ErrorKind::AddrInUse))
        })
        .expect_err("mixed candidates are exhausted first");
        assert!(matches!(
            error,
            EndpointSelectionError::Exhausted {
                role: EndpointRole::Mixed
            }
        ));
        assert_eq!(probes, candidate_ports(DEFAULT_MIXED_PORT));
    }
}

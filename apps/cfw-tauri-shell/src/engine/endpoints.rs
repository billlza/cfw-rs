use std::collections::BTreeSet;
use std::net::IpAddr;

use cfw_platform::{MacOsPlatformService, NetworkProxyProtocolObservation};
use cfw_singbox_config::{DEFAULT_CLASH_API_PORT, DEFAULT_MIXED_PORT, EngineSettings};
use thiserror::Error;

pub(super) const CANDIDATE_COUNT: usize = 8;

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
    #[error(
        "the configured local proxy port {0} is already reserved; choose a different port or automatic selection"
    )]
    ConfiguredPortUnavailable(u16),
    #[error("persisted {role} port {port} is outside the fixed candidate range")]
    InvalidPersistedPort { role: EndpointRole, port: u16 },
    #[error("no bounded loopback TCP port is available for the {role}")]
    Exhausted { role: EndpointRole },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EndpointCandidateCursor {
    settings: EngineSettings,
    mixed_index: usize,
    controller_index: usize,
    fixed_mixed_port: Option<u16>,
}

pub(super) fn select_configured_engine_settings(
    settings: EngineSettings,
    preferred_port: Option<u16>,
) -> Result<(EngineSettings, EndpointCandidateCursor), EndpointSelectionError> {
    let services = MacOsPlatformService
        .observe_network_services()
        .map_err(|error| EndpointSelectionError::Observation(error.to_string()))?;
    EndpointCandidateCursor::configured(settings, preferred_port, &services)
}

#[cfg(test)]
fn select_settings_with(
    settings: EngineSettings,
    services: &[cfw_platform::NetworkServiceObservation],
) -> Result<(EngineSettings, EndpointCandidateCursor), EndpointSelectionError> {
    EndpointCandidateCursor::initial(settings, services)
}

impl EndpointCandidateCursor {
    #[cfg(test)]
    fn initial(
        settings: EngineSettings,
        services: &[cfw_platform::NetworkServiceObservation],
    ) -> Result<(EngineSettings, Self), EndpointSelectionError> {
        let mut cursor = Self {
            settings,
            mixed_index: 0,
            controller_index: 0,
            fixed_mixed_port: None,
        };
        cursor.refresh_from_observation(services)?;
        Ok((cursor.settings.clone(), cursor))
    }

    pub(super) fn from_persisted(settings: EngineSettings) -> Result<Self, EndpointSelectionError> {
        if settings.mixed_port < 1024 {
            return Err(EndpointSelectionError::InvalidPersistedPort {
                role: EndpointRole::Mixed,
                port: settings.mixed_port,
            });
        }
        let mixed_index = candidate_index(DEFAULT_MIXED_PORT, settings.mixed_port);
        let fixed_mixed_port = mixed_index.is_none().then_some(settings.mixed_port);
        let mixed_index = mixed_index.unwrap_or(0);
        let controller_index = candidate_index(DEFAULT_CLASH_API_PORT, settings.controller_port)
            .ok_or(EndpointSelectionError::InvalidPersistedPort {
                role: EndpointRole::Controller,
                port: settings.controller_port,
            })?;
        Ok(Self {
            settings,
            mixed_index,
            controller_index,
            fixed_mixed_port,
        })
    }

    pub(super) fn with_runtime_preferences(
        &self,
        settings: EngineSettings,
        preferred_port: Option<u16>,
    ) -> Result<(EngineSettings, Self), EndpointSelectionError> {
        if settings.mixed_port == self.settings.mixed_port && preferred_port.is_some()
            || preferred_port == self.fixed_mixed_port
        {
            let mut next = self.clone();
            next.settings = settings;
            next.fixed_mixed_port = preferred_port;
            return Ok((next.settings.clone(), next));
        }
        let services = MacOsPlatformService
            .observe_network_services()
            .map_err(|error| EndpointSelectionError::Observation(error.to_string()))?;
        Self::configured(settings, preferred_port, &services)
    }

    fn configured(
        settings: EngineSettings,
        preferred_port: Option<u16>,
        services: &[cfw_platform::NetworkServiceObservation],
    ) -> Result<(EngineSettings, Self), EndpointSelectionError> {
        let mut cursor = Self {
            settings,
            mixed_index: 0,
            controller_index: 0,
            fixed_mixed_port: preferred_port,
        };
        cursor.refresh_from_observation(services)?;
        Ok((cursor.settings.clone(), cursor))
    }

    pub(super) fn advance(
        &self,
        role: EndpointRole,
    ) -> Result<(EngineSettings, Self), EndpointSelectionError> {
        let services = MacOsPlatformService
            .observe_network_services()
            .map_err(|error| EndpointSelectionError::Observation(error.to_string()))?;
        self.advance_with_services(role, &services)
    }

    fn advance_with_services(
        &self,
        role: EndpointRole,
        services: &[cfw_platform::NetworkServiceObservation],
    ) -> Result<(EngineSettings, Self), EndpointSelectionError> {
        let mut next = self.clone();
        match role {
            EndpointRole::Mixed => {
                if let Some(port) = self.fixed_mixed_port {
                    return Err(EndpointSelectionError::ConfiguredPortUnavailable(port));
                }
                next.mixed_index =
                    next.mixed_index
                        .checked_add(1)
                        .ok_or(EndpointSelectionError::Exhausted {
                            role: EndpointRole::Mixed,
                        })?;
            }
            EndpointRole::Controller => {
                next.controller_index = next.controller_index.checked_add(1).ok_or(
                    EndpointSelectionError::Exhausted {
                        role: EndpointRole::Controller,
                    },
                )?;
            }
        }
        next.refresh_from_observation(services)?;
        Ok((next.settings.clone(), next))
    }

    fn refresh_from_observation(
        &mut self,
        services: &[cfw_platform::NetworkServiceObservation],
    ) -> Result<(), EndpointSelectionError> {
        let mut reserved = reserved_external_proxy_ports(services)?;
        if let Some(lan) = &self.settings.lan_proxy {
            reserved.insert(lan.port);
        }
        let mixed_candidates = candidate_ports(DEFAULT_MIXED_PORT);
        let controller_candidates = candidate_ports(DEFAULT_CLASH_API_PORT);
        if let Some(port) = self.fixed_mixed_port {
            if port < 1024 || reserved.contains(&port) {
                return Err(EndpointSelectionError::ConfiguredPortUnavailable(port));
            }
            self.settings.mixed_port = port;
        } else {
            self.mixed_index = select_index(
                EndpointRole::Mixed,
                &mixed_candidates,
                self.mixed_index,
                &reserved,
            )?;
            self.settings.mixed_port = mixed_candidates[self.mixed_index];
        }
        let mut controller_reserved = reserved;
        controller_reserved.insert(self.settings.mixed_port);
        self.controller_index = select_index(
            EndpointRole::Controller,
            &controller_candidates,
            self.controller_index,
            &controller_reserved,
        )?;
        self.settings.controller_port = controller_candidates[self.controller_index];
        Ok(())
    }
}

fn candidate_ports(preferred: u16) -> [u16; CANDIDATE_COUNT] {
    std::array::from_fn(|index| {
        preferred
            .checked_add(u16::try_from(index).expect("candidate index is bounded"))
            .expect("fixed endpoint candidate range fits in u16")
    })
}

fn candidate_index(preferred: u16, selected: u16) -> Option<usize> {
    candidate_ports(preferred)
        .iter()
        .position(|candidate| *candidate == selected)
}

fn reserved_external_proxy_ports(
    services: &[cfw_platform::NetworkServiceObservation],
) -> Result<BTreeSet<u16>, EndpointSelectionError> {
    let mut reserved = BTreeSet::new();
    for service in services {
        // PAC/WPAD is an OS proxy policy, not a claim on a local TCP port.
        // Reserve observable fixed endpoints here; the native bind result
        // remains authoritative for collisions hidden behind automatic policy.
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
    if port == 0 {
        return Err(EndpointSelectionError::IncompleteExternalProxy { protocol });
    }
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

fn select_index(
    role: EndpointRole,
    candidates: &[u16],
    start_index: usize,
    reserved: &BTreeSet<u16>,
) -> Result<usize, EndpointSelectionError> {
    for (index, &port) in candidates.iter().enumerate().skip(start_index) {
        if port == 0 || reserved.contains(&port) {
            continue;
        }
        return Ok(index);
    }
    Err(EndpointSelectionError::Exhausted { role })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_platform::{NetworkProxyProtocolObservation, NetworkServiceObservation};

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
    fn external_loopback_proxy_port_is_reserved_without_probing_a_listener() {
        let reserved = reserved_external_proxy_ports(&[service(NetworkProxyProtocolObservation {
            enabled: true,
            server: Some("localhost.".into()),
            port: Some(DEFAULT_MIXED_PORT),
        })])
        .expect("external proxy observation");
        let selected = select_index(
            EndpointRole::Mixed,
            &candidate_ports(DEFAULT_MIXED_PORT),
            0,
            &reserved,
        )
        .expect("fallback candidate");
        assert_eq!(selected, 1);
    }

    #[test]
    fn process_settings_select_one_bounded_tuple_from_the_observed_proxy_state() {
        let services = [service(NetworkProxyProtocolObservation {
            enabled: true,
            server: Some("127.0.0.1".into()),
            port: Some(DEFAULT_MIXED_PORT),
        })];
        let (selected, cursor) =
            select_settings_with(EngineSettings::default(), &services).expect("bounded tuple");
        assert_eq!(selected.mixed_port, DEFAULT_MIXED_PORT + 1);
        assert_eq!(selected.controller_port, DEFAULT_CLASH_API_PORT);
        assert_eq!(cursor.settings, selected);
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

        let error = reserved_external_proxy_ports(&[service(NetworkProxyProtocolObservation {
            enabled: true,
            server: Some("127.0.0.1".into()),
            port: Some(0),
        })])
        .expect_err("zero is not a usable enabled proxy port");
        assert!(matches!(
            error,
            EndpointSelectionError::IncompleteExternalProxy { .. }
        ));
    }

    #[test]
    fn automatic_proxy_policy_does_not_block_local_endpoint_selection() {
        for is_pac in [true, false] {
            let mut source = service(NetworkProxyProtocolObservation {
                enabled: true,
                server: Some("127.0.0.1".into()),
                port: Some(DEFAULT_MIXED_PORT),
            });
            source.pac_enabled = is_pac;
            source.wpad_enabled = !is_pac;
            let (settings, cursor) =
                select_settings_with(EngineSettings::default(), &[source]).unwrap();
            assert_eq!(settings.mixed_port, DEFAULT_MIXED_PORT + 1);
            assert_eq!(cursor.settings, settings);
        }
    }

    #[test]
    fn typed_conflict_advances_only_its_monotonic_cursor() {
        let (_, cursor) =
            select_settings_with(EngineSettings::default(), &[]).expect("initial tuple");
        let (mixed, cursor) = cursor
            .advance_with_services(EndpointRole::Mixed, &[])
            .expect("next mixed candidate");
        assert_eq!(mixed.mixed_port, DEFAULT_MIXED_PORT + 1);
        assert_eq!(mixed.controller_port, DEFAULT_CLASH_API_PORT);

        let (controller, _) = cursor
            .advance_with_services(EndpointRole::Controller, &[])
            .expect("next controller candidate");
        assert_eq!(controller.mixed_port, DEFAULT_MIXED_PORT + 1);
        assert_eq!(controller.controller_port, DEFAULT_CLASH_API_PORT + 1);
    }

    #[test]
    fn every_bounded_retry_tuple_is_unique_and_the_sixteenth_is_rejected() {
        let (initial, mut cursor) =
            select_settings_with(EngineSettings::default(), &[]).expect("initial tuple");
        let mut tuples = BTreeSet::from([(initial.mixed_port, initial.controller_port)]);
        for _ in 1..CANDIDATE_COUNT {
            let (settings, next) = cursor
                .advance_with_services(EndpointRole::Mixed, &[])
                .expect("bounded mixed advance");
            assert!(tuples.insert((settings.mixed_port, settings.controller_port)));
            cursor = next;
        }
        for _ in 1..CANDIDATE_COUNT {
            let (settings, next) = cursor
                .advance_with_services(EndpointRole::Controller, &[])
                .expect("bounded controller advance");
            assert!(tuples.insert((settings.mixed_port, settings.controller_port)));
            cursor = next;
        }
        assert_eq!(tuples.len(), CANDIDATE_COUNT * 2 - 1);
        let error = cursor
            .advance_with_services(EndpointRole::Controller, &[])
            .expect_err("controller cursor is exhausted");
        assert!(matches!(
            error,
            EndpointSelectionError::Exhausted {
                role: EndpointRole::Controller
            }
        ));
    }

    #[test]
    fn fresh_observation_skips_newly_reserved_ports_without_rewinding() {
        let (_, cursor) =
            select_settings_with(EngineSettings::default(), &[]).expect("initial tuple");
        let services = [service(NetworkProxyProtocolObservation {
            enabled: true,
            server: Some("127.0.0.1".into()),
            port: Some(DEFAULT_CLASH_API_PORT),
        })];
        let (settings, _) = cursor
            .advance_with_services(EndpointRole::Mixed, &services)
            .expect("freshly observed tuple");
        assert_eq!(settings.mixed_port, DEFAULT_MIXED_PORT + 1);
        assert_eq!(settings.controller_port, DEFAULT_CLASH_API_PORT + 1);
    }

    #[test]
    fn all_reserved_candidates_return_a_typed_exhaustion() {
        let candidates = candidate_ports(DEFAULT_CLASH_API_PORT);
        let error = select_index(
            EndpointRole::Controller,
            &candidates,
            0,
            &BTreeSet::from(candidates),
        )
        .expect_err("all controller candidates are reserved");
        assert!(matches!(
            error,
            EndpointSelectionError::Exhausted {
                role: EndpointRole::Controller
            }
        ));
    }

    #[test]
    fn persisted_privileged_ports_are_rejected() {
        let settings = EngineSettings {
            mixed_port: 80,
            ..EngineSettings::default()
        };
        let error = EndpointCandidateCursor::from_persisted(settings)
            .expect_err("privileged persisted mixed endpoint");
        assert!(matches!(
            error,
            EndpointSelectionError::InvalidPersistedPort {
                role: EndpointRole::Mixed,
                ..
            }
        ));
    }
    #[test]
    fn configured_ports_stay_exact_and_keep_the_controller_separate() {
        let (settings, cursor) =
            EndpointCandidateCursor::configured(EngineSettings::default(), Some(9090), &[])
                .unwrap();
        assert_eq!(settings.mixed_port, 9090);
        assert_eq!(settings.controller_port, 9091);
        assert!(matches!(
            cursor.advance_with_services(EndpointRole::Mixed, &[]),
            Err(EndpointSelectionError::ConfiguredPortUnavailable(9090))
        ));
        let recovered = EndpointCandidateCursor::from_persisted(EngineSettings {
            mixed_port: 8890,
            ..EngineSettings::default()
        })
        .unwrap();
        assert_eq!(recovered.fixed_mixed_port, Some(8890));
        let services = [service(NetworkProxyProtocolObservation {
            enabled: true,
            server: Some("127.0.0.1".into()),
            port: Some(8890),
        })];
        assert!(matches!(
            EndpointCandidateCursor::configured(EngineSettings::default(), Some(8890), &services),
            Err(EndpointSelectionError::ConfiguredPortUnavailable(8890))
        ));
    }
}

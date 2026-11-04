use std::cell::RefCell;

use objc2_core_foundation::CFNumber;

use super::*;

#[derive(Clone)]
struct FakeService {
    enabled: bool,
    interface: Option<(Option<String>, Option<String>)>,
    identifier: Option<String>,
}

impl FakeService {
    fn physical(kind: &str, name: &str, identifier: &str) -> Self {
        Self {
            enabled: true,
            interface: Some((Some(kind.to_owned()), Some(name.to_owned()))),
            identifier: Some(identifier.to_owned()),
        }
    }
}

impl NetworkService for FakeService {
    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn physical_interface(&self) -> Option<ServiceInterface> {
        self.interface
            .clone()
            .map(|(kind, bsd_name)| ServiceInterface { kind, bsd_name })
    }

    fn identifier(&self) -> Option<String> {
        self.identifier.clone()
    }
}

/// SystemConfiguration and CoreWLAN in memory.
#[derive(Default)]
struct FakeNetwork {
    services: Vec<FakeService>,
    state: Vec<(String, CFRetained<CFType>)>,
    unreadable: Option<String>,
    wifi: Vec<(&'static str, Option<&'static str>)>,
    wifi_lookups: RefCell<Vec<String>>,
}

impl FakeNetwork {
    fn with_services(services: Vec<FakeService>) -> Self {
        Self {
            services,
            ..Self::default()
        }
    }

    fn with_state(mut self, key: &str, value: CFRetained<CFType>) -> Self {
        self.state.push((key.to_owned(), value));
        self
    }

    fn primary(self, family: &str, interface: &str) -> Self {
        self.with_state(
            &format!("State:/Network/Global/{family}"),
            dictionary(&[("PrimaryInterface", text(interface))]),
        )
    }

    fn addresses(self, service: &str, family: &str, values: &[&str]) -> Self {
        self.with_state(
            &format!("State:/Network/Service/{service}/{family}"),
            dictionary(&[("Addresses", addresses(values))]),
        )
    }

    fn wifi(mut self, interface: &'static str, name: Option<&'static str>) -> Self {
        self.wifi.push((interface, name));
        self
    }
}

impl NetworkSystem for FakeNetwork {
    type Service = FakeService;

    fn services(&self) -> Result<Vec<FakeService>> {
        Ok(self.services.clone())
    }

    fn state(&self, key: &str) -> Result<Option<CFRetained<CFType>>> {
        if self.unreadable.as_deref() == Some(key) {
            bail!("fake dynamic store refused {key}")
        }
        Ok(self
            .state
            .iter()
            .find(|(existing, _)| existing == key)
            .map(|(_, value)| value.clone()))
    }

    fn wifi_name(&self, interface: &str) -> Option<Option<String>> {
        self.wifi_lookups.borrow_mut().push(interface.to_owned());
        self.wifi
            .iter()
            .find(|(name, _)| *name == interface)
            .map(|(_, ssid)| ssid.map(str::to_owned))
    }
}

fn text(value: &str) -> CFRetained<CFType> {
    CFString::from_str(value).into()
}

fn dictionary(entries: &[(&str, CFRetained<CFType>)]) -> CFRetained<CFType> {
    let keys = entries
        .iter()
        .map(|(key, _)| CFString::from_str(key))
        .collect::<Vec<_>>();
    let keys = keys.iter().map(|key| &**key).collect::<Vec<_>>();
    let values = entries
        .iter()
        .map(|(_, value)| &**value)
        .collect::<Vec<_>>();
    let typed = CFDictionary::<CFString, CFType>::from_slices(&keys, &values);
    CFRetained::<CFDictionary>::from(&*typed).into()
}

fn addresses(values: &[&str]) -> CFRetained<CFType> {
    let values = values
        .iter()
        .map(|value| CFString::from_str(value))
        .collect::<Vec<_>>();
    let typed = CFArray::<CFString>::from_retained_objects(&values);
    CFRetained::<CFArray>::from(&*typed).into()
}

fn context(
    interface: &str,
    kind: NetworkKind,
    ssid: Option<&str>,
    addresses: &[&str],
) -> NetworkContext {
    NetworkContext {
        interface: interface.into(),
        kind,
        ssid: ssid.map(str::to_owned),
        addresses: addresses.iter().map(|value| (*value).to_owned()).collect(),
    }
}

/// A Wi-Fi service on en0 and an Ethernet service on en5, both addressed.
fn wifi_and_ethernet() -> FakeNetwork {
    FakeNetwork::with_services(vec![
        FakeService::physical("IEEE80211", "en0", "wifi"),
        FakeService::physical("Ethernet", "en5", "ethernet"),
    ])
    .addresses("wifi", "IPv4", &["192.168.1.5"])
    .addresses("ethernet", "IPv4", &["10.0.0.5"])
    .wifi("en0", Some("Home"))
}

fn error(network: &FakeNetwork) -> String {
    current_context(network)
        .expect_err("the observation must fail")
        .to_string()
}

#[test]
fn the_primary_physical_interface_is_the_current_network() {
    let ethernet = context("en5", NetworkKind::Wired, None, &["10.0.0.5"]);
    let wifi = context("en0", NetworkKind::Wifi, Some("Home"), &["192.168.1.5"]);
    assert_eq!(
        current_context(&wifi_and_ethernet().primary("IPv4", "en5")).expect("observed"),
        Some(ethernet.clone())
    );
    // The IPv6 primary decides when IPv4 has none.
    assert_eq!(
        current_context(&wifi_and_ethernet().primary("IPv6", "en5")).expect("observed"),
        Some(ethernet)
    );
    // The IPv4 primary wins over the IPv6 one.
    assert_eq!(
        current_context(
            &wifi_and_ethernet()
                .primary("IPv4", "en0")
                .primary("IPv6", "en5")
        )
        .expect("observed"),
        Some(wifi.clone())
    );
    // Without a primary interface, or with a virtual one, the first name wins.
    assert_eq!(
        current_context(&wifi_and_ethernet()).expect("observed"),
        Some(wifi.clone())
    );
    assert_eq!(
        current_context(&wifi_and_ethernet().primary("IPv4", "utun4")).expect("observed"),
        Some(wifi)
    );
}

#[test]
fn only_enabled_physical_services_with_a_usable_address_qualify() {
    let network = FakeNetwork::with_services(vec![
        FakeService {
            enabled: false,
            ..FakeService::physical("Ethernet", "en1", "disabled")
        },
        FakeService {
            interface: None,
            ..FakeService::physical("Ethernet", "en2", "no-interface")
        },
        FakeService::physical("Bridge", "bridge0", "bridge"),
        FakeService::physical("PPP", "ppp0", "ppp"),
        FakeService::physical("Ethernet", "en3", "loopback-only"),
        FakeService::physical("Ethernet", "en4", "no-state"),
        FakeService::physical("Ethernet", "en6", "no-addresses"),
    ])
    .addresses("disabled", "IPv4", &["10.0.0.1"])
    .addresses("bridge", "IPv4", &["10.0.0.2"])
    .addresses("ppp", "IPv4", &["10.0.0.3"])
    .addresses("loopback-only", "IPv4", &["127.0.0.1", "0.0.0.0"])
    .addresses("loopback-only", "IPv6", &["::1", "::"])
    .with_state(
        "State:/Network/Service/no-addresses/IPv4",
        dictionary(&[("Router", text("10.0.0.254"))]),
    );
    assert_eq!(current_context(&network).expect("observed"), None);
    // CoreWLAN is asked only about a candidate.
    assert!(network.wifi_lookups.borrow().is_empty());
}

#[test]
fn addresses_from_both_families_are_sorted_and_deduplicated_without_loopback() {
    let network =
        FakeNetwork::with_services(vec![FakeService::physical("Ethernet", "en7", "ethernet")])
            .addresses(
                "ethernet",
                "IPv4",
                &["192.168.1.5", "127.0.0.1", "192.168.1.5"],
            )
            .addresses("ethernet", "IPv6", &["fe80::1", "::1", "2001:db8::5"]);
    assert_eq!(
        current_context(&network).expect("observed"),
        Some(context(
            "en7",
            NetworkKind::Wired,
            None,
            &["192.168.1.5", "2001:db8::5", "fe80::1"]
        ))
    );
    assert_eq!(*network.wifi_lookups.borrow(), ["en7"]);
}

#[test]
fn a_wifi_interface_without_a_visible_name_is_still_wifi() {
    let network =
        FakeNetwork::with_services(vec![FakeService::physical("IEEE80211", "en0", "wifi")])
            .addresses("wifi", "IPv4", &["192.168.1.5"])
            .wifi("en0", None);
    assert_eq!(
        current_context(&network).expect("observed"),
        Some(context("en0", NetworkKind::Wifi, None, &["192.168.1.5"]))
    );
}

#[test]
fn a_service_set_beyond_the_bound_is_refused() {
    let network = FakeNetwork::with_services(
        (0..=MAX_ENTRIES)
            .map(|_| FakeService::physical("Ethernet", "en0", "ethernet"))
            .collect(),
    );
    assert_eq!(
        error(&network),
        "network service count exceeds its observation bound"
    );
}

#[test]
fn an_incomplete_or_malformed_physical_service_is_refused() {
    for (service, message) in [
        (
            FakeService {
                interface: Some((None, Some("en0".into()))),
                ..FakeService::physical("Ethernet", "en0", "ethernet")
            },
            "network interface type is unavailable",
        ),
        (
            FakeService {
                interface: Some((Some("Ethernet".into()), None)),
                ..FakeService::physical("Ethernet", "en0", "ethernet")
            },
            "physical network interface name is unavailable",
        ),
        (
            FakeService::physical("Ethernet", "en0:1", "ethernet"),
            "physical interface name is invalid",
        ),
        (
            FakeService {
                identifier: None,
                ..FakeService::physical("Ethernet", "en0", "ethernet")
            },
            "network service identity is unavailable",
        ),
    ] {
        assert_eq!(error(&FakeNetwork::with_services(vec![service])), message);
    }
    assert_eq!(
        error(&FakeNetwork::with_services(vec![FakeService::physical(
            "Ethernet",
            &"e".repeat(65),
            "ethernet"
        )])),
        "physical interface name is invalid"
    );
}

#[test]
fn malformed_network_state_is_refused() {
    let ethernet =
        || FakeNetwork::with_services(vec![FakeService::physical("Ethernet", "en5", "ethernet")]);
    for (network, message) in [
        (
            ethernet().with_state("State:/Network/Global/IPv4", text("en5")),
            "network state has an invalid type",
        ),
        (
            ethernet().with_state(
                "State:/Network/Global/IPv4",
                dictionary(&[("PrimaryInterface", CFNumber::new_i32(5).into())]),
            ),
            "network field has an invalid type",
        ),
        (
            ethernet().with_state(
                "State:/Network/Service/ethernet/IPv4",
                dictionary(&[("Addresses", text("10.0.0.5"))]),
            ),
            "network addresses have an invalid type",
        ),
        (
            ethernet().addresses("ethernet", "IPv6", &["2001:db8::1"; MAX_ENTRIES + 1]),
            "network address count exceeds its observation bound",
        ),
        (
            ethernet().addresses("ethernet", "IPv4", &["10.0.0.5", "10.0.0.256"]),
            "network address is invalid",
        ),
    ] {
        assert_eq!(error(&network), message);
    }
}

#[test]
fn a_wifi_name_is_at_most_32_bytes() {
    let longest = "a-network-name-of-thirty-two-byt";
    assert_eq!(longest.len(), 32);
    let network =
        FakeNetwork::with_services(vec![FakeService::physical("IEEE80211", "en0", "wifi")])
            .addresses("wifi", "IPv4", &["192.168.1.5"])
            .wifi("en0", Some(longest));
    assert_eq!(
        current_context(&network).expect("observed"),
        Some(context(
            "en0",
            NetworkKind::Wifi,
            Some(longest),
            &["192.168.1.5"]
        ))
    );

    let network = wifi_and_ethernet().wifi("en5", Some("a-network-name-of-thirty-three-by"));
    assert_eq!(network.wifi[1].1.map(str::len), Some(33));
    assert_eq!(error(&network), "observed Wi-Fi name exceeds 32 bytes");
}

#[test]
fn an_unreadable_store_fails_the_observation() {
    for key in [
        "State:/Network/Global/IPv4",
        "State:/Network/Global/IPv6",
        "State:/Network/Service/ethernet/IPv6",
    ] {
        let network = FakeNetwork {
            unreadable: Some(key.to_owned()),
            ..wifi_and_ethernet().primary("IPv4", "en5")
        };
        assert_eq!(error(&network), format!("fake dynamic store refused {key}"));
    }
}

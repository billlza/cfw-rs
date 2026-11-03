use cfw_platform::MacOsPlatformService;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_CAPTURED_ROUTES: usize = 4096;
const LEGACY_IPV4: &str = "198.18.0.1";
const LEGACY_IPV4_NETMASK: &str = "0xfffffffc";
const LEGACY_IPV6: &str = "fdfe:dcba:9876::1";
const LEGACY_IPV6_PREFIX: &str = "126";
const LEGACY_DNS_IPV4: &str = "198.18.0.2";
const LEGACY_DNS_IPV6: &str = "fdfe:dcba:9876::2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyNetworkJournalIdentity {
    pub(super) interface: String,
    pub(super) route_digest: String,
    pub(super) route_count: usize,
    pub(super) scoped_dns_resolvers: usize,
}

impl LegacyNetworkJournalIdentity {
    pub(super) fn validate(&self) -> Result<(), String> {
        if !valid_utun_interface(&self.interface)
            || self.route_count == 0
            || self.route_count > MAX_CAPTURED_ROUTES
            || self.scoped_dns_resolvers > 256
            || self.route_digest.len() != 64
            || !self
                .route_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("journaled legacy TUN fingerprint identity is invalid".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LegacyNetworkFingerprint {
    identity: LegacyNetworkJournalIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyAddressState {
    Complete,
    Partial,
}

impl LegacyAddressState {
    fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete address",
            Self::Partial => "partial or route-only",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyInterfaceMatch {
    interface: String,
    address_state: LegacyAddressState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyNetworkObservation {
    interfaces: String,
    ipv4_routes: String,
    ipv6_routes: String,
    dns: String,
}

impl LegacyNetworkObservation {
    fn capture() -> Result<Self, String> {
        let observation = MacOsPlatformService
            .observe_network_routing()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            interfaces: observation.interfaces,
            ipv4_routes: observation.ipv4_routes,
            ipv6_routes: observation.ipv6_routes,
            dns: observation.dns,
        })
    }

    fn route_rows(&self, interface: &str) -> Result<Vec<String>, String> {
        route_rows_for_interface(&self.ipv4_routes, &self.ipv6_routes, interface)
    }

    fn scoped_dns_resolvers(&self, interface: &str) -> Result<usize, String> {
        scoped_dns_resolver_count(&self.dns, interface)
    }
}

impl LegacyNetworkFingerprint {
    pub(super) fn verify_absent() -> Result<(), String> {
        Self::verify_absent_in(&LegacyNetworkObservation::capture()?)
    }

    pub(super) fn journal_identity(&self) -> LegacyNetworkJournalIdentity {
        self.identity.clone()
    }

    pub(super) fn for_recovery(identity: LegacyNetworkJournalIdentity) -> Result<Self, String> {
        identity.validate()?;
        Ok(Self { identity })
    }

    pub(super) fn capture() -> Result<Self, String> {
        Self::from_observation(&LegacyNetworkObservation::capture()?)
    }

    fn verify_absent_in(observation: &LegacyNetworkObservation) -> Result<(), String> {
        let matches = legacy_interface_matches(observation)?;
        if matches.is_empty() {
            return Ok(());
        }
        Err(format!(
            "legacy TUN address, route, or scoped DNS evidence remains on {}; fresh-install absence is not proven",
            describe_matches(observation, &matches)?
        ))
    }

    fn from_observation(observation: &LegacyNetworkObservation) -> Result<Self, String> {
        let matches = legacy_interface_matches(observation)?;
        let interface = match matches.as_slice() {
            [candidate] if candidate.address_state == LegacyAddressState::Complete => {
                candidate.interface.clone()
            }
            [candidate] => {
                return Err(format!(
                    "legacy TUN ownership cannot be proven: partial address fingerprint on {}; the existing VPN was not changed",
                    describe_matches(observation, std::slice::from_ref(candidate))?
                ));
            }
            [] => {
                return Err(
                    "legacy TUN ownership cannot be proven: no interface has the exact 198.18.0.1/30 and fdfe:dcba:9876::1/126 fingerprint; the existing VPN was not changed"
                        .into(),
                );
            }
            _ => {
                return Err(format!(
                    "legacy TUN ownership is ambiguous across {}; the existing VPN was not changed",
                    describe_matches(observation, &matches)?
                ));
            }
        };
        let route_rows = observation.route_rows(&interface)?;
        if route_rows.is_empty() {
            return Err(format!(
                "legacy TUN interface {interface} has no attributable routes; the existing VPN was not changed"
            ));
        }
        let scoped_dns_resolvers = observation.scoped_dns_resolvers(&interface)?;
        let identity = LegacyNetworkJournalIdentity {
            interface,
            route_digest: route_rows_digest(&route_rows),
            route_count: route_rows.len(),
            scoped_dns_resolvers,
        };
        identity.validate()?;
        Ok(Self { identity })
    }

    pub(super) fn verify_removed(&self) -> Result<(), String> {
        let observation = LegacyNetworkObservation::capture()?;
        if interface_names(&observation.interfaces)
            .iter()
            .any(|name| name == &self.identity.interface)
        {
            return Err(format!(
                "legacy TUN interface {} remains after the managed core stopped; no unrelated interface was removed",
                self.identity.interface
            ));
        }
        let routes = route_rows_for_interface(
            &observation.ipv4_routes,
            &observation.ipv6_routes,
            &self.identity.interface,
        )?;
        if !routes.is_empty() {
            return Err(format!(
                "{} legacy routes still reference {} after retirement",
                routes.len(),
                self.identity.interface
            ));
        }
        let remaining_dns = scoped_dns_resolver_count(&observation.dns, &self.identity.interface)?;
        if remaining_dns != 0 {
            return Err(format!(
                "{remaining_dns} DNS resolvers still reference legacy interface {} after retirement",
                self.identity.interface
            ));
        }
        Ok(())
    }

    pub(super) fn verify_still_present(&self) -> Result<(), String> {
        self.verify_observation(&LegacyNetworkObservation::capture()?)
    }

    fn verify_observation(&self, observation: &LegacyNetworkObservation) -> Result<(), String> {
        let current = Self::from_observation(observation)?;
        if current == *self {
            Ok(())
        } else {
            Err("legacy TUN fingerprint changed after preparation".into())
        }
    }
}

fn interface_blocks(input: &str) -> Vec<(&str, Vec<&str>)> {
    let mut blocks = Vec::<(&str, Vec<&str>)>::new();
    for line in input.lines() {
        if !line.starts_with(char::is_whitespace)
            && let Some((name, _)) = line.split_once(':')
        {
            blocks.push((name, vec![line]));
        } else if let Some((_, lines)) = blocks.last_mut() {
            lines.push(line);
        }
    }
    blocks
}

fn interface_names(input: &str) -> Vec<String> {
    interface_blocks(input)
        .into_iter()
        .map(|(name, _)| name.to_owned())
        .collect()
}

fn legacy_interface_matches(
    observation: &LegacyNetworkObservation,
) -> Result<Vec<LegacyInterfaceMatch>, String> {
    let mut matches = legacy_address_matches(&observation.interfaces);
    // A route naming the legacy address is only attributable when it dangles:
    // no live interface carries that name any more, so nothing can still own it
    // and it can only be retirement residue. A route whose Netif is a live
    // interface belongs to whatever currently holds that interface, and in the
    // shared benchmarking range that is routinely a foreign product.
    let live_interfaces = interface_names(&observation.interfaces);
    for interface in legacy_route_interfaces(&observation.ipv4_routes, &observation.ipv6_routes)? {
        if live_interfaces.contains(&interface) {
            continue;
        }
        if !matches
            .iter()
            .any(|candidate| candidate.interface == interface)
        {
            matches.push(LegacyInterfaceMatch {
                interface,
                address_state: LegacyAddressState::Partial,
            });
        }
    }
    for interface in legacy_dns_interfaces(&observation.dns)? {
        if !matches
            .iter()
            .any(|candidate| candidate.interface == interface)
        {
            matches.push(LegacyInterfaceMatch {
                interface,
                address_state: LegacyAddressState::Partial,
            });
        }
    }
    matches.sort_unstable_by(|left, right| left.interface.cmp(&right.interface));
    Ok(matches)
}

fn legacy_address_matches(input: &str) -> Vec<LegacyInterfaceMatch> {
    interface_blocks(input)
        .into_iter()
        .filter_map(|(name, lines)| {
            let ipv4 =
                legacy_address_rows(&lines, "inet", LEGACY_IPV4, "netmask", LEGACY_IPV4_NETMASK);
            let ipv6 = legacy_address_rows(
                &lines,
                "inet6",
                LEGACY_IPV6,
                "prefixlen",
                LEGACY_IPV6_PREFIX,
            );
            // 198.18.0.0/15 is the RFC2544 benchmarking range that the whole
            // Clash tool family uses for TUN, so the bare address is shared with
            // foreign products. Only an exact qualifier -- the /30 netmask or the
            // /126 prefix this product itself writes -- attributes an address to
            // the retired network. A row that carries the address with a
            // different qualifier belongs to something else and is not evidence.
            if !ipv4.contains(&true) && !ipv6.contains(&true) {
                return None;
            }
            let valid_utun = valid_utun_interface(name);
            let address_state =
                if valid_utun && ipv4.as_slice() == [true] && ipv6.as_slice() == [true] {
                    LegacyAddressState::Complete
                } else {
                    LegacyAddressState::Partial
                };
            Some(LegacyInterfaceMatch {
                interface: name.to_owned(),
                address_state,
            })
        })
        .collect()
}

fn valid_utun_interface(value: &str) -> bool {
    value.strip_prefix("utun").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn legacy_address_rows(
    lines: &[&str],
    family: &str,
    address: &str,
    qualifier: &str,
    expected_qualifier: &str,
) -> Vec<bool> {
    lines
        .iter()
        .filter_map(|line| {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            (fields.first() == Some(&family) && fields.get(1) == Some(&address)).then(|| {
                fields
                    .windows(2)
                    .any(|pair| pair == [qualifier, expected_qualifier])
            })
        })
        .collect()
}

fn legacy_route_interfaces(ipv4_routes: &str, ipv6_routes: &str) -> Result<Vec<String>, String> {
    let mut interfaces = Vec::new();
    for (family, output) in [("inet", ipv4_routes), ("inet6", ipv6_routes)] {
        let mut destination_index = None;
        let mut gateway_index = None;
        let mut netif_index = None;
        let mut observed_header = false;
        for line in output.lines() {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if let (Some(destination), Some(gateway), Some(netif)) = (
                fields.iter().position(|field| *field == "Destination"),
                fields.iter().position(|field| *field == "Gateway"),
                fields.iter().position(|field| *field == "Netif"),
            ) {
                destination_index = Some(destination);
                gateway_index = Some(gateway);
                netif_index = Some(netif);
                observed_header = true;
                continue;
            }
            let (Some(destination), Some(gateway), Some(netif)) =
                (destination_index, gateway_index, netif_index)
            else {
                continue;
            };
            let related = [fields.get(destination), fields.get(gateway)]
                .into_iter()
                .flatten()
                .any(|field| legacy_route_address(field));
            if !related {
                continue;
            }
            let interface = fields.get(netif).ok_or_else(|| {
                format!(
                    "{family} legacy-related route has no Netif value; ownership is unverifiable"
                )
            })?;
            if interface.is_empty() {
                return Err(format!(
                    "{family} legacy-related route has an empty Netif value; ownership is unverifiable"
                ));
            }
            interfaces.push((*interface).to_owned());
        }
        if !observed_header {
            return Err(format!(
                "{family} route table has no Destination, Gateway, and Netif columns; legacy route ownership is unverifiable"
            ));
        }
    }
    interfaces.sort_unstable();
    interfaces.dedup();
    Ok(interfaces)
}

fn legacy_route_address(value: &str) -> bool {
    let address = value.split_once('%').map_or(value, |(address, _)| address);
    let address = address
        .split_once('/')
        .map_or(address, |(address, _)| address);
    address == LEGACY_IPV4 || address == LEGACY_IPV6
}

fn route_rows_for_interface(
    ipv4_routes: &str,
    ipv6_routes: &str,
    interface: &str,
) -> Result<Vec<String>, String> {
    let mut routes = Vec::new();
    for (family, output) in [("inet", ipv4_routes), ("inet6", ipv6_routes)] {
        let mut netif_index = None;
        let mut observed_header = false;
        for line in output.lines() {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if let Some(index) = fields.iter().position(|field| *field == "Netif") {
                netif_index = Some(index);
                observed_header = true;
                continue;
            }
            let Some(index) = netif_index else {
                continue;
            };
            if fields.get(index) == Some(&interface) {
                if routes.len() >= MAX_CAPTURED_ROUTES {
                    return Err("legacy route fingerprint exceeded 4096 rows".into());
                }
                // `Expire` follows `Netif` and is a volatile countdown. The
                // ownership fingerprint includes every stable field through
                // the exact interface while deliberately excluding that
                // non-identity column.
                routes.push(format!("{family}:{}", fields[..=index].join(" ")));
            }
        }
        if !observed_header {
            return Err(format!(
                "{family} route table has no Netif column; legacy route ownership is unverifiable"
            ));
        }
    }
    routes.sort_unstable();
    Ok(routes)
}

fn route_rows_digest(rows: &[String]) -> String {
    let mut digest = Sha256::new();
    for row in rows {
        digest.update((row.len() as u64).to_be_bytes());
        digest.update(row.as_bytes());
    }
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn describe_matches(
    observation: &LegacyNetworkObservation,
    matches: &[LegacyInterfaceMatch],
) -> Result<String, String> {
    matches
        .iter()
        .map(|candidate| {
            let routes = observation.route_rows(&candidate.interface)?.len();
            let scoped_dns = observation.scoped_dns_resolvers(&candidate.interface)?;
            Ok(format!(
                "{} ({} fingerprint, {routes} routes, {scoped_dns} scoped DNS resolvers)",
                candidate.interface,
                candidate.address_state.label()
            ))
        })
        .collect::<Result<Vec<_>, String>>()
        .map(|descriptions| descriptions.join(", "))
}

fn scoped_dns_resolver_count(input: &str, interface: &str) -> Result<usize, String> {
    if input.trim() == "No DNS configuration available" {
        return Ok(0);
    }
    let marker = format!("({interface})");
    let mut resolver_count = 0;
    let mut observed_resolver = false;
    for resolver in input.split("resolver #").skip(1) {
        let mut lines = resolver.lines();
        let ordinal = lines.next().map(str::trim).unwrap_or_default();
        if ordinal.parse::<usize>().is_err() {
            return Err("scutil --dns returned an invalid resolver ordinal".into());
        }
        observed_resolver = true;
        if lines.any(|line| line.trim_start().starts_with("if_index") && line.contains(&marker)) {
            resolver_count += 1;
        }
    }
    if !observed_resolver {
        return Err("scutil --dns output has no verifiable resolver records".into());
    }
    Ok(resolver_count)
}

fn legacy_dns_interfaces(input: &str) -> Result<Vec<String>, String> {
    if input.trim() == "No DNS configuration available" {
        return Ok(Vec::new());
    }
    let mut interfaces = Vec::new();
    let mut observed_resolver = false;
    for resolver in input.split("resolver #").skip(1) {
        let mut lines = resolver.lines();
        let ordinal = lines.next().map(str::trim).unwrap_or_default();
        if ordinal.parse::<usize>().is_err() {
            return Err("scutil --dns returned an invalid resolver ordinal".into());
        }
        observed_resolver = true;
        let rows = lines.collect::<Vec<_>>();
        let related = rows.iter().any(|line| {
            line.trim_start().starts_with("nameserver[")
                && line.split_once(':').is_some_and(|(_, value)| {
                    matches!(value.trim(), LEGACY_DNS_IPV4 | LEGACY_DNS_IPV6)
                })
        });
        if !related {
            continue;
        }
        let scoped = rows
            .iter()
            .filter_map(|line| {
                let value = line.trim_start().strip_prefix("if_index")?;
                let (_, value) = value.split_once(':')?;
                let (_, interface) = value.trim().split_once('(')?;
                interface.strip_suffix(')')
            })
            .collect::<Vec<_>>();
        match scoped.as_slice() {
            [interface] if valid_utun_interface(interface) => {
                interfaces.push((*interface).to_owned());
            }
            _ => {
                return Err(
                    "legacy DNS resolver has no unique valid utun scope; ownership is unverifiable"
                        .into(),
                );
            }
        }
    }
    if !observed_resolver {
        return Err("scutil --dns output has no verifiable resolver records".into());
    }
    interfaces.sort_unstable();
    interfaces.dedup();
    Ok(interfaces)
}

#[cfg(test)]
mod tests;

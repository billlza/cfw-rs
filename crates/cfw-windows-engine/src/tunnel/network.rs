//! SYSTEM applies a `TunnelNetworkPlan` to its own adapter and reads every
//! setting back. Each address, route, resolver and interface option names that
//! adapter's LUID or GUID; no other interface, the global route table, proxy
//! settings or firewall policy is written. Removing the adapter therefore
//! removes everything applied here, which is what retirement proves.
//!
//! Interface options follow the decisions recorded for the SYSTEM-hosted
//! adapter: no router discovery, duplicate-address detection, forwarding,
//! stateful configuration, dynamic DNS registration or NetBIOS. Families the
//! plan routes get interface metric zero so their default routes win over a
//! physical default route; the engine binds its own sockets to the physical
//! interface instead of following these routes.
use super::{
    Adapter, Error, Result, TunnelNetworkPlan, interface_identity,
    plan::{Ipv4Prefix, Ipv6Prefix},
};
use serde::Serialize;
use std::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::{null, null_mut},
};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, WIN32_ERROR},
        NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
        Networking::WinSock::*,
        System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD,
            REG_OPTION_NON_VOLATILE, RRF_RT_REG_DWORD, RegCloseKey, RegCreateKeyExW, RegGetValueW,
            RegOpenKeyExW, RegSetValueExW,
        },
    },
    core::GUID,
};

/// NetbiosOptions 2 disables NetBIOS over TCP/IP on one interface.
const NETBIOS_DISABLED: u32 = 2;
/// Native tables enumerated here are bounded before any row is read.
const MAXIMUM_TABLE_ROWS: usize = 65_536;
/// An infinite address or route lifetime.
const INFINITE_LIFETIME: u32 = u32::MAX;
/// Longest resolver list text read back from Windows.
const MAXIMUM_RESOLVER_TEXT: usize = 4096;

/// How far a tunnel adapter is configured. `Link` carries the interface
/// options and addresses only, so nothing is routed into an adapter whose
/// endpoint the engine is not yet serving; `Routed` adds the routes and the
/// resolvers once it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPhase {
    Link,
    Routed,
}

/// What SYSTEM applied and read back, for the Authority's diagnostics. It
/// is an observation of this adapter only, never evidence of global Off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkReceipt {
    pub interface_luid: u64,
    pub phase: NetworkPhase,
    pub mtu: u16,
    pub ipv4_routes: usize,
    pub ipv6_routes: Option<usize>,
    pub dns_registration_disabled: bool,
    pub netbios_disabled: bool,
}

/// Configure the link of `adapter`, whose interface GUID must be `guid`.
/// Windows keeps static addresses, routes and resolvers of an interface GUID
/// across adapter instances, so this owner first removes every address,
/// network-management route and resolver its adapter still carries. A
/// failure leaves settings on this adapter only; retiring it removes them.
pub(crate) fn configure_link(
    adapter: &Adapter<'_>,
    guid: uuid::Uuid,
    plan: &TunnelNetworkPlan,
) -> Result<NetworkReceipt> {
    let luid = adapter.luid();
    if interface_identity(luid, adapter.name())? != guid {
        return Err("tunnel adapter GUID differs from its owner".into());
    }
    // NetBT reads the interface option when it binds an address, so it is
    // written before the first address is assigned.
    disable_netbios(guid)?;
    let ipv6_interface = interface_row(luid, AF_INET6)?.is_some();
    let routed_ipv6 = plan.ipv6().is_some();
    if routed_ipv6 && !ipv6_interface {
        return Err("tunnel adapter has no IPv6 interface for its IPv6 plan".into());
    }
    flush_routes(luid)?;
    flush_addresses(luid)?;
    set_dns(guid, DnsFamily::V4, None)?;
    if ipv6_interface {
        set_dns(guid, DnsFamily::V6, None)?;
    }
    configure_interface(luid, AF_INET, plan.mtu(), true)?;
    if ipv6_interface {
        configure_interface(luid, AF_INET6, plan.mtu(), routed_ipv6)?;
    }
    let ipv4 = plan.ipv4();
    add_address(luid, IpAddr::V4(ipv4.address), ipv4.prefix_length)?;
    if let Some(ipv6) = plan.ipv6() {
        add_address(luid, IpAddr::V6(ipv6.address), ipv6.prefix_length)?;
    }
    verify(luid, guid, plan, NetworkPhase::Link)
}

/// Install the plan's routes and resolvers on a configured link.
pub(crate) fn route(
    luid: u64,
    guid: uuid::Uuid,
    plan: &TunnelNetworkPlan,
) -> Result<NetworkReceipt> {
    verify(luid, guid, plan, NetworkPhase::Link)?;
    let ipv4 = plan.ipv4();
    for route in &ipv4.routes {
        add_route(luid, IpAddr::V4(route.network()), route.length())?;
    }
    if let Some(ipv6) = plan.ipv6() {
        for route in &ipv6.routes {
            add_route(luid, IpAddr::V6(route.network()), route.length())?;
        }
    }
    set_dns(guid, DnsFamily::V4, Some(IpAddr::V4(ipv4.dns_peer)))?;
    if let Some(ipv6) = plan.ipv6() {
        set_dns(guid, DnsFamily::V6, Some(IpAddr::V6(ipv6.dns_peer)))?;
    }
    verify(luid, guid, plan, NetworkPhase::Routed)
}

/// Read back every setting of `phase`, without changing anything.
pub(crate) fn verify(
    luid: u64,
    guid: uuid::Uuid,
    plan: &TunnelNetworkPlan,
    phase: NetworkPhase,
) -> Result<NetworkReceipt> {
    let routed = phase == NetworkPhase::Routed;
    verify_interface(luid, AF_INET, plan.mtu(), true)?;
    let ipv6_interface = interface_row(luid, AF_INET6)?.is_some();
    if ipv6_interface {
        verify_interface(luid, AF_INET6, plan.mtu(), plan.ipv6().is_some())?;
    }
    verify_addresses(luid, plan)?;
    verify_routes(luid, plan, routed)?;
    let ipv4 = plan.ipv4();
    verify_dns(
        guid,
        DnsFamily::V4,
        routed.then_some(IpAddr::V4(ipv4.dns_peer)),
    )?;
    if ipv6_interface {
        verify_dns(
            guid,
            DnsFamily::V6,
            plan.ipv6()
                .filter(|_| routed)
                .map(|ipv6| IpAddr::V6(ipv6.dns_peer)),
        )?;
    }
    if netbios_option(guid)? != NETBIOS_DISABLED {
        return Err("tunnel adapter NetBIOS option was not applied".into());
    }
    Ok(NetworkReceipt {
        interface_luid: luid,
        phase,
        mtu: plan.mtu(),
        ipv4_routes: if routed { ipv4.routes.len() } else { 0 },
        ipv6_routes: plan
            .ipv6()
            .map(|family| if routed { family.routes.len() } else { 0 }),
        dns_registration_disabled: true,
        netbios_disabled: true,
    })
}

fn status(code: WIN32_ERROR, operation: &'static str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Native {
            operation,
            source: std::io::Error::from_raw_os_error(code as i32),
        })
    }
}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(ip) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ip.octets()),
                    },
                },
                ..Default::default()
            },
        },
        IpAddr::V6(ip) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: ip.octets() },
                },
                ..Default::default()
            },
        },
    }
}

fn address_of(native: &SOCKADDR_INET) -> Option<IpAddr> {
    unsafe {
        match native.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                native.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(native.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

fn interface_row(luid: u64, family: ADDRESS_FAMILY) -> Result<Option<MIB_IPINTERFACE_ROW>> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family;
    row.InterfaceLuid = NET_LUID_LH { Value: luid };
    let code = unsafe { GetIpInterfaceEntry(&mut row) };
    if code == ERROR_NOT_FOUND || code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    status(code, "observe tunnel interface options")?;
    if unsafe { row.InterfaceLuid.Value } != luid || row.Family != family {
        return Err("tunnel interface observation changed its identity".into());
    }
    Ok(Some(row))
}

fn configure_interface(luid: u64, family: ADDRESS_FAMILY, mtu: u16, routed: bool) -> Result<()> {
    let mut row = interface_row(luid, family)?.ok_or("tunnel interface family is absent")?;
    row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    row.DadTransmits = 0;
    row.ForwardingEnabled = false;
    row.AdvertisingEnabled = false;
    row.ManagedAddressConfigurationSupported = false;
    row.OtherStatefulConfigurationSupported = false;
    row.NlMtu = u32::from(mtu);
    if routed {
        row.UseAutomaticMetric = false;
        row.Metric = 0;
    }
    if family == AF_INET {
        // SetIpInterfaceEntry rejects a nonzero IPv4 site prefix length.
        row.SitePrefixLength = 0;
    }
    status(
        unsafe { SetIpInterfaceEntry(&mut row) },
        "apply tunnel interface options",
    )?;
    verify_interface(luid, family, mtu, routed)
}

fn verify_interface(luid: u64, family: ADDRESS_FAMILY, mtu: u16, routed: bool) -> Result<()> {
    let row = interface_row(luid, family)?.ok_or("tunnel interface family is absent")?;
    if row.RouterDiscoveryBehavior != RouterDiscoveryDisabled
        || row.DadTransmits != 0
        || row.ForwardingEnabled
        || row.AdvertisingEnabled
        || row.ManagedAddressConfigurationSupported
        || row.OtherStatefulConfigurationSupported
        || row.NlMtu != u32::from(mtu)
        || (routed && (row.UseAutomaticMetric || row.Metric != 0))
    {
        return Err(format!(
            "tunnel interface options were not applied for address family {family}"
        )
        .into());
    }
    Ok(())
}

fn add_address(luid: u64, ip: IpAddr, prefix_length: u8) -> Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.Address = sockaddr(ip);
    row.InterfaceLuid = NET_LUID_LH { Value: luid };
    row.OnLinkPrefixLength = prefix_length;
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    row.ValidLifetime = INFINITE_LIFETIME;
    row.PreferredLifetime = INFINITE_LIFETIME;
    row.DadState = IpDadStatePreferred;
    status(
        unsafe { CreateUnicastIpAddressEntry(&row) },
        "assign tunnel adapter address",
    )
}

fn add_route(luid: u64, network: IpAddr, length: u8) -> Result<()> {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = NET_LUID_LH { Value: luid };
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr(network),
        PrefixLength: length,
    };
    // An unspecified next hop of the destination's family: on-link.
    row.NextHop = sockaddr(match network {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    });
    row.SitePrefixLength = 0;
    row.ValidLifetime = INFINITE_LIFETIME;
    row.PreferredLifetime = INFINITE_LIFETIME;
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Loopback = false;
    row.AutoconfigureAddress = false;
    row.Publish = false;
    row.Immortal = false;
    status(
        unsafe { CreateIpForwardEntry2(&row) },
        "add tunnel adapter route",
    )
}

struct Table(*mut c_void);
impl Drop for Table {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeMibTable(self.0) };
        }
    }
}

fn unicast_rows(luid: u64) -> Result<Vec<MIB_UNICASTIPADDRESS_ROW>> {
    let mut pointer = null_mut();
    status(
        unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut pointer) },
        "enumerate tunnel adapter addresses",
    )?;
    if pointer.is_null() {
        return Err("native address table is null".into());
    }
    let _table = Table(pointer.cast());
    let count = unsafe { (*pointer).NumEntries } as usize;
    if count > MAXIMUM_TABLE_ROWS {
        return Err("native address table exceeds its bound".into());
    }
    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*pointer).Table).cast::<MIB_UNICASTIPADDRESS_ROW>(),
            count,
        )
    };
    Ok(rows
        .iter()
        .filter(|row| unsafe { row.InterfaceLuid.Value } == luid)
        .copied()
        .collect())
}

/// Addresses this owner manages: everything except the IPv6 link-local
/// address Windows keeps on every IPv6 interface.
fn managed_addresses(luid: u64) -> Result<Vec<(IpAddr, u8, MIB_UNICASTIPADDRESS_ROW)>> {
    let mut managed = Vec::new();
    for row in unicast_rows(luid)? {
        let ip = address_of(&row.Address).ok_or("native address row has an unknown family")?;
        if !matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local()) {
            managed.push((ip, row.OnLinkPrefixLength, row));
        }
    }
    Ok(managed)
}

fn flush_addresses(luid: u64) -> Result<()> {
    for (_, _, row) in managed_addresses(luid)? {
        status(
            unsafe { DeleteUnicastIpAddressEntry(&row) },
            "remove a residual tunnel adapter address",
        )?;
    }
    if !managed_addresses(luid)?.is_empty() {
        return Err("residual tunnel adapter addresses remain".into());
    }
    Ok(())
}

fn verify_addresses(luid: u64, plan: &TunnelNetworkPlan) -> Result<()> {
    let mut expected = vec![(IpAddr::V4(plan.ipv4().address), plan.ipv4().prefix_length)];
    if let Some(ipv6) = plan.ipv6() {
        expected.push((IpAddr::V6(ipv6.address), ipv6.prefix_length));
    }
    let mut observed: Vec<_> = managed_addresses(luid)?
        .into_iter()
        .map(|(ip, length, _)| (ip, length))
        .collect();
    observed.sort();
    expected.sort();
    if observed != expected {
        return Err(format!(
            "tunnel adapter addresses differ from the plan: {observed:?} != {expected:?}"
        )
        .into());
    }
    Ok(())
}

/// Network-management routes on this adapter. Windows adds its own local and
/// on-link routes for each address; only these rows are this owner's.
fn owned_routes(luid: u64) -> Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut pointer = null_mut();
    status(
        unsafe { GetIpForwardTable2(AF_UNSPEC, &mut pointer) },
        "enumerate tunnel adapter routes",
    )?;
    if pointer.is_null() {
        return Err("native route table is null".into());
    }
    let _table = Table(pointer.cast());
    let count = unsafe { (*pointer).NumEntries } as usize;
    if count > MAXIMUM_TABLE_ROWS {
        return Err("native route table exceeds its bound".into());
    }
    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*pointer).Table).cast::<MIB_IPFORWARD_ROW2>(),
            count,
        )
    };
    Ok(rows
        .iter()
        .filter(|row| {
            let owner = unsafe { row.InterfaceLuid.Value };
            owner == luid && row.Protocol == MIB_IPPROTO_NETMGMT
        })
        .copied()
        .collect())
}

fn flush_routes(luid: u64) -> Result<()> {
    for row in owned_routes(luid)? {
        status(
            unsafe { DeleteIpForwardEntry2(&row) },
            "remove a residual tunnel adapter route",
        )?;
    }
    if !owned_routes(luid)?.is_empty() {
        return Err("residual tunnel adapter routes remain".into());
    }
    Ok(())
}

fn verify_routes(luid: u64, plan: &TunnelNetworkPlan, routed: bool) -> Result<()> {
    let mut observed = Vec::new();
    for row in owned_routes(luid)? {
        let network = address_of(&row.DestinationPrefix.Prefix)
            .ok_or("native route row has an unknown family")?;
        let next_hop =
            address_of(&row.NextHop).ok_or("native route next hop has an unknown family")?;
        if row.Metric != 0 || !next_hop.is_unspecified() {
            return Err(format!(
                "tunnel route {network}/{} has metric {} or next hop {next_hop}",
                row.DestinationPrefix.PrefixLength, row.Metric
            )
            .into());
        }
        observed.push((network, row.DestinationPrefix.PrefixLength));
    }
    let mut expected = Vec::new();
    if routed {
        expected.extend(
            plan.ipv4()
                .routes
                .iter()
                .map(|route: &Ipv4Prefix| (IpAddr::V4(route.network()), route.length())),
        );
        if let Some(ipv6) = plan.ipv6() {
            expected.extend(
                ipv6.routes
                    .iter()
                    .map(|route: &Ipv6Prefix| (IpAddr::V6(route.network()), route.length())),
            );
        }
    }
    observed.sort();
    expected.sort();
    if observed != expected {
        return Err(format!(
            "tunnel adapter routes differ from the plan ({} observed, {} planned)",
            observed.len(),
            expected.len()
        )
        .into());
    }
    Ok(())
}

fn native_guid(guid: uuid::Uuid) -> GUID {
    let (data1, data2, data3, data4) = guid.as_fields();
    GUID {
        data1,
        data2,
        data3,
        data4: *data4,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DnsFamily {
    V4,
    V6,
}
impl DnsFamily {
    fn flag(self) -> u64 {
        match self {
            Self::V4 => 0,
            Self::V6 => u64::from(DNS_SETTING_IPV6),
        }
    }
    fn admits(self, peer: IpAddr) -> bool {
        matches!(
            (self, peer),
            (Self::V4, IpAddr::V4(_)) | (Self::V6, IpAddr::V6(_))
        )
    }
}

/// `None` clears the family's resolvers; registration stays disabled.
fn set_dns(guid: uuid::Uuid, family: DnsFamily, peer: Option<IpAddr>) -> Result<()> {
    if peer.is_some_and(|peer| !family.admits(peer)) {
        return Err("tunnel resolver differs from its address family".into());
    }
    let mut server: Vec<u16> = peer
        .map(|peer| peer.to_string())
        .unwrap_or_default()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: family.flag()
            | u64::from(
                DNS_SETTING_NAMESERVER
                    | DNS_SETTING_REGISTRATION_ENABLED
                    | DNS_SETTING_REGISTER_ADAPTER_NAME,
            ),
        NameServer: server.as_mut_ptr(),
        RegistrationEnabled: 0,
        RegisterAdapterName: 0,
        ..Default::default()
    };
    status(
        unsafe { SetInterfaceDnsSettings(native_guid(guid), &settings) },
        "apply tunnel adapter resolvers",
    )
}

fn verify_dns(guid: uuid::Uuid, family: DnsFamily, peer: Option<IpAddr>) -> Result<()> {
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: family.flag(),
        ..Default::default()
    };
    status(
        unsafe { GetInterfaceDnsSettings(native_guid(guid), &mut settings) },
        "observe tunnel adapter resolvers",
    )?;
    let servers = wide_text(settings.NameServer);
    let (registration, adapter_name) = (settings.RegistrationEnabled, settings.RegisterAdapterName);
    unsafe { FreeInterfaceDnsSettings(&mut settings) };
    let servers = servers?;
    let listed: Vec<&str> = servers
        .split([',', ' '])
        .filter(|entry| !entry.is_empty())
        .collect();
    let expected: Vec<String> = peer.map(|peer| peer.to_string()).into_iter().collect();
    if listed != expected || registration != 0 || adapter_name != 0 {
        return Err(format!(
            "tunnel adapter resolvers differ from the plan: [{servers}], registration {registration}, adapter name {adapter_name}"
        )
        .into());
    }
    Ok(())
}

fn wide_text(pointer: windows_sys::core::PWSTR) -> Result<String> {
    if pointer.is_null() {
        return Ok(String::new());
    }
    let mut length = 0usize;
    while unsafe { *pointer.add(length) } != 0 {
        length += 1;
        if length > MAXIMUM_RESOLVER_TEXT {
            return Err("native resolver list exceeds its bound".into());
        }
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, length) })
        .map_err(|error| Error::Contract(error.to_string()))
}

fn netbios_key(guid: uuid::Uuid) -> Vec<u16> {
    format!(
        "SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_{{{}}}",
        guid.hyphenated()
    )
    .encode_utf16()
    .chain(Some(0))
    .collect()
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn netbios_value_name() -> Vec<u16> {
    "NetbiosOptions".encode_utf16().chain(Some(0)).collect()
}

/// NetBT may not have bound the new interface yet; the option key is created
/// under NetBT's own interface list, inheriting that list's protection.
fn disable_netbios(guid: uuid::Uuid) -> Result<()> {
    let path = netbios_key(guid);
    let mut key = null_mut();
    status(
        unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                null(),
                &mut key,
                null_mut(),
            )
        },
        "open the tunnel adapter NetBIOS options for writing",
    )?;
    let key = Key(key);
    let value = NETBIOS_DISABLED.to_le_bytes();
    status(
        unsafe {
            RegSetValueExW(
                key.0,
                netbios_value_name().as_ptr(),
                0,
                REG_DWORD,
                value.as_ptr(),
                value.len() as u32,
            )
        },
        "disable NetBIOS on the tunnel adapter",
    )
}

fn netbios_option(guid: uuid::Uuid) -> Result<u32> {
    let path = netbios_key(guid);
    let mut key = null_mut();
    status(
        unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut key,
            )
        },
        "open the tunnel adapter NetBIOS options",
    )?;
    let key = Key(key);
    let mut value = 0u32;
    let mut bytes = std::mem::size_of::<u32>() as u32;
    status(
        unsafe {
            RegGetValueW(
                key.0,
                null(),
                netbios_value_name().as_ptr(),
                RRF_RT_REG_DWORD,
                null_mut(),
                (&mut value as *mut u32).cast(),
                &mut bytes,
            )
        },
        "observe the tunnel adapter NetBIOS option",
    )?;
    if bytes as usize != std::mem::size_of::<u32>() {
        return Err("tunnel adapter NetBIOS option has an unexpected size".into());
    }
    Ok(value)
}

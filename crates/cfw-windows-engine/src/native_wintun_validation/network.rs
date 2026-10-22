//! Disposable address/route ownership for the packet probes only. No default
//! route, DNS option or firewall rule is changed. Every mutation names the
//! retained adapter's native LUID, alias and creation GUID. Both IP families
//! get the probe MTU, so the stack cannot hand the session a larger packet.
//! An IPv6 fixture also turns off duplicate-address detection and router
//! discovery on its own adapter: a point-to-point tunnel has no neighbours.
use super::{Result, library};
use crate::tunnel::Adapter;
use std::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::null_mut,
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND},
    NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
    Networking::WinSock::*,
};

pub(super) const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
pub(super) const REMOTE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 123);
/// RFC 3849 documentation addresses, outside the tunnel address plan.
pub(super) const LOCAL6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x10);
pub(super) const REMOTE6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x123);
const FIXTURE_ADDRESSES: [IpAddr; 4] = [
    IpAddr::V4(LOCAL),
    IpAddr::V4(REMOTE),
    IpAddr::V6(LOCAL6),
    IpAddr::V6(REMOTE6),
];
const FIXTURE_ROUTES: [IpAddr; 2] = [IpAddr::V4(REMOTE), IpAddr::V6(REMOTE6)];

fn status(code: u32, operation: &str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{operation}: {}",
            std::io::Error::from_raw_os_error(code as i32)
        ))
    }
}
fn address(ip: IpAddr) -> SOCKADDR_INET {
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
fn same_address(native: &SOCKADDR_INET, ip: IpAddr) -> bool {
    unsafe {
        match ip {
            IpAddr::V4(ip) => {
                native.si_family == AF_INET
                    && native.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes() == ip.octets()
            }
            IpAddr::V6(ip) => {
                native.si_family == AF_INET6 && native.Ipv6.sin6_addr.u.Byte == ip.octets()
            }
        }
    }
}
fn host_prefix(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}
fn unspecified(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    }
}
struct Table(*mut c_void);
impl Drop for Table {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.0) };
    }
}

pub(super) fn require_unused_addresses_and_route() -> Result<()> {
    let mut pointer = null_mut();
    status(
        unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut pointer) },
        "enumerate fixture address conflicts",
    )?;
    if pointer.is_null() {
        return Err("native address table is null".into());
    }
    let _addresses = Table(pointer.cast());
    let count = unsafe { (*pointer).NumEntries } as usize;
    if count > 65536 {
        return Err("native address table exceeds its bound".into());
    }
    let entries = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*pointer).Table).cast::<MIB_UNICASTIPADDRESS_ROW>(),
            count,
        )
    };
    if entries.iter().any(|row| {
        FIXTURE_ADDRESSES
            .iter()
            .any(|ip| same_address(&row.Address, *ip))
    }) {
        return Err("fixture address is already assigned to an interface".into());
    }
    let mut pointer = null_mut();
    status(
        unsafe { GetIpForwardTable2(AF_UNSPEC, &mut pointer) },
        "enumerate fixture route conflicts",
    )?;
    if pointer.is_null() {
        return Err("native route table is null".into());
    }
    let _routes = Table(pointer.cast());
    let count = unsafe { (*pointer).NumEntries } as usize;
    if count > 65536 {
        return Err("native route table exceeds its bound".into());
    }
    let entries = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*pointer).Table).cast::<MIB_IPFORWARD_ROW2>(),
            count,
        )
    };
    if entries.iter().any(|row| {
        FIXTURE_ROUTES.iter().any(|ip| {
            row.DestinationPrefix.PrefixLength == host_prefix(*ip)
                && same_address(&row.DestinationPrefix.Prefix, *ip)
        })
    }) {
        return Err("fixture host route already exists".into());
    }
    Ok(())
}

/// The IPv6 interface settings a probe changed, kept to restore them exactly.
#[derive(Clone, Copy)]
pub(super) struct Ipv6Interface {
    pub(super) mtu: u32,
    pub(super) dad_transmits: u32,
    pub(super) router_discovery: NL_ROUTER_DISCOVERY_BEHAVIOR,
}

pub(super) struct OwnedNetwork<'a> {
    adapter: &'a Adapter<'a>,
    id: uuid::Uuid,
    mtu: u16,
    ipv6_fixture: bool,
    original_mtu: u32,
    mtu_changed: bool,
    original_ipv6: Option<Ipv6Interface>,
    ipv6_changed: bool,
    addresses: Vec<(IpAddr, MIB_UNICASTIPADDRESS_ROW)>,
    routes: Vec<(IpAddr, MIB_IPFORWARD_ROW2)>,
}
impl<'a> OwnedNetwork<'a> {
    /// 192.0.2.10 with a host route to 192.0.2.123 and, for an IPv6 fixture,
    /// 2001:db8:1::10 with a host route to 2001:db8:1::123, all on this adapter.
    pub(super) fn configure(
        adapter: &'a Adapter<'a>,
        id: uuid::Uuid,
        mtu: u16,
        ipv6: bool,
    ) -> Result<Self> {
        require_unused_addresses_and_route()?;
        let mut value = Self {
            adapter,
            id,
            mtu,
            ipv6_fixture: ipv6,
            original_mtu: 0,
            mtu_changed: false,
            original_ipv6: None,
            ipv6_changed: false,
            addresses: Vec::new(),
            routes: Vec::new(),
        };
        value.require_owner()?;
        let mut interface = value.interface()?;
        value.original_mtu = interface.NlMtu;
        let result = (|| {
            interface.NlMtu = u32::from(mtu);
            // Required by SetIpInterfaceEntry for IPv4; other fields came from
            // this exact interface, not InitializeIpInterfaceEntry defaults.
            interface.SitePrefixLength = 0;
            status(
                unsafe { SetIpInterfaceEntry(&mut interface) },
                "set owned adapter MTU",
            )?;
            value.mtu_changed = true;
            if value.interface()?.NlMtu != u32::from(mtu) {
                return Err("adapter MTU readback differs".into());
            }
            match value.interface_for(AF_INET6)? {
                Some(mut ipv6_interface) => {
                    let original = Ipv6Interface {
                        mtu: ipv6_interface.NlMtu,
                        dad_transmits: ipv6_interface.DadTransmits,
                        router_discovery: ipv6_interface.RouterDiscoveryBehavior,
                    };
                    value.original_ipv6 = Some(original);
                    let wanted = value.wanted_ipv6(original);
                    ipv6_interface.NlMtu = wanted.mtu;
                    ipv6_interface.DadTransmits = wanted.dad_transmits;
                    ipv6_interface.RouterDiscoveryBehavior = wanted.router_discovery;
                    status(
                        unsafe { SetIpInterfaceEntry(&mut ipv6_interface) },
                        "set owned adapter IPv6 interface",
                    )?;
                    value.ipv6_changed = true;
                    value.require_ipv6(wanted, "adapter IPv6 interface readback differs")?;
                }
                None if ipv6 => return Err("owned adapter has no IPv6 interface".into()),
                None => {}
            }
            value.add_address(LOCAL.into())?;
            value.add_route(REMOTE.into())?;
            if ipv6 {
                value.add_address(LOCAL6.into())?;
                value.add_route(REMOTE6.into())?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            return match value.restore() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!("{error}; network cleanup: {cleanup}")),
            };
        }
        Ok(value)
    }

    fn wanted_ipv6(&self, original: Ipv6Interface) -> Ipv6Interface {
        if self.ipv6_fixture {
            Ipv6Interface {
                mtu: u32::from(self.mtu),
                dad_transmits: 0,
                router_discovery: RouterDiscoveryDisabled,
            }
        } else {
            Ipv6Interface {
                mtu: u32::from(self.mtu),
                ..original
            }
        }
    }

    fn require_ipv6(&self, expected: Ipv6Interface, message: &str) -> Result<()> {
        let observed = self
            .interface_for(AF_INET6)?
            .ok_or("owned adapter lost its IPv6 interface")?;
        if observed.NlMtu != expected.mtu
            || observed.DadTransmits != expected.dad_transmits
            || observed.RouterDiscoveryBehavior != expected.router_discovery
        {
            return Err(message.into());
        }
        Ok(())
    }

    fn add_address(&mut self, local: IpAddr) -> Result<()> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid = NET_LUID_LH {
            Value: self.adapter.luid(),
        };
        row.Address = address(local);
        row.OnLinkPrefixLength = host_prefix(local);
        row.PrefixOrigin = IpPrefixOriginManual;
        row.SuffixOrigin = IpSuffixOriginManual;
        self.require_owner()?;
        status(
            unsafe { CreateUnicastIpAddressEntry(&row) },
            "create owned fixture address",
        )?;
        self.addresses.push((local, row));
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let mut observed = row;
            status(
                unsafe { GetUnicastIpAddressEntry(&mut observed) },
                "observe fixture address readiness",
            )?;
            if observed.DadState == IpDadStatePreferred {
                return Ok(());
            }
            if observed.DadState != IpDadStateTentative || Instant::now() >= deadline {
                return Err(format!(
                    "fixture address {local} did not become usable: DAD {}",
                    observed.DadState
                ));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn add_route(&mut self, remote: IpAddr) -> Result<()> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid = NET_LUID_LH {
            Value: self.adapter.luid(),
        };
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: address(remote),
            PrefixLength: host_prefix(remote),
        };
        row.NextHop = address(unspecified(remote));
        row.Metric = 0;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        self.require_owner()?;
        status(
            unsafe { CreateIpForwardEntry2(&row) },
            "create owned fixture host route",
        )?;
        self.routes.push((remote, row));
        self.verify_route(remote, &row)
    }

    fn require_owner(&self) -> Result<()> {
        let current = library::interface_identity(self.adapter.luid(), self.adapter.name())
            .map_err(|error| error.to_string())?;
        if current != self.id {
            return Err("fixture adapter no longer has its creation GUID".into());
        }
        Ok(())
    }
    fn interface(&self) -> Result<MIB_IPINTERFACE_ROW> {
        self.interface_for(AF_INET)?
            .ok_or_else(|| "owned adapter has no IPv4 interface".into())
    }
    /// None only when the family is not bound to the adapter at all.
    fn interface_for(&self, family: ADDRESS_FAMILY) -> Result<Option<MIB_IPINTERFACE_ROW>> {
        self.require_owner()?;
        let mut row = MIB_IPINTERFACE_ROW {
            Family: family,
            InterfaceLuid: NET_LUID_LH {
                Value: self.adapter.luid(),
            },
            ..Default::default()
        };
        let code = unsafe { GetIpInterfaceEntry(&mut row) };
        if family == AF_INET6 && code == ERROR_NOT_FOUND {
            return Ok(None);
        }
        status(code, "read owned IP interface")?;
        if unsafe { row.InterfaceLuid.Value } != self.adapter.luid() {
            return Err("IP interface changed its requested LUID".into());
        }
        Ok(Some(row))
    }
    fn verify_route(&self, remote: IpAddr, expected: &MIB_IPFORWARD_ROW2) -> Result<()> {
        self.require_owner()?;
        let mut observed = *expected;
        status(
            unsafe { GetIpForwardEntry2(&mut observed) },
            "read owned fixture route",
        )?;
        if unsafe { observed.InterfaceLuid.Value } != self.adapter.luid()
            || observed.DestinationPrefix.PrefixLength != host_prefix(remote)
            || !same_address(&observed.DestinationPrefix.Prefix, remote)
            || !same_address(&observed.NextHop, unspecified(remote))
            || observed.Metric != 0
            || observed.Protocol != MIB_IPPROTO_NETMGMT
        {
            return Err("fixture route no longer matches its ownership record".into());
        }
        Ok(())
    }
    pub(super) fn original_mtu(&self) -> u32 {
        self.original_mtu
    }
    /// The adapter's IPv6 interface before this probe, when IPv6 was bound to it.
    pub(super) fn original_ipv6(&self) -> Option<Ipv6Interface> {
        self.original_ipv6
    }
    pub(super) fn restore(&mut self) -> Result<()> {
        self.require_owner()?;
        while let Some(&(remote, row)) = self.routes.last() {
            self.verify_route(remote, &row)?;
            status(
                unsafe { DeleteIpForwardEntry2(&row) },
                "remove owned fixture route",
            )?;
            self.routes.pop();
            let mut query = row;
            let code = unsafe { GetIpForwardEntry2(&mut query) };
            if code != ERROR_NOT_FOUND && code != ERROR_FILE_NOT_FOUND {
                return Err(format!(
                    "removed fixture route is not proven absent: {code}"
                ));
            }
        }
        while let Some(&(local, row)) = self.addresses.last() {
            self.require_owner()?;
            let mut observed = row;
            status(
                unsafe { GetUnicastIpAddressEntry(&mut observed) },
                "read owned fixture address",
            )?;
            if unsafe { observed.InterfaceLuid.Value } != self.adapter.luid()
                || !same_address(&observed.Address, local)
                || observed.OnLinkPrefixLength != host_prefix(local)
                || observed.PrefixOrigin != IpPrefixOriginManual
                || observed.SuffixOrigin != IpSuffixOriginManual
            {
                return Err("fixture address no longer matches its ownership record".into());
            }
            status(
                unsafe { DeleteUnicastIpAddressEntry(&row) },
                "remove owned fixture address",
            )?;
            self.addresses.pop();
            let mut query = row;
            let code = unsafe { GetUnicastIpAddressEntry(&mut query) };
            if code != ERROR_NOT_FOUND && code != ERROR_FILE_NOT_FOUND {
                return Err(format!(
                    "removed fixture address is not proven absent: {code}"
                ));
            }
        }
        if self.mtu_changed {
            let mut interface = self.interface()?;
            if interface.NlMtu != u32::from(self.mtu) {
                return Err("fixture MTU changed before restoration".into());
            }
            interface.NlMtu = self.original_mtu;
            interface.SitePrefixLength = 0;
            status(
                unsafe { SetIpInterfaceEntry(&mut interface) },
                "restore owned adapter MTU",
            )?;
            if self.interface()?.NlMtu != self.original_mtu {
                return Err("original MTU was not restored".into());
            }
            self.mtu_changed = false;
        }
        if self.ipv6_changed {
            let original = self
                .original_ipv6
                .ok_or("IPv6 interface change has no original value")?;
            self.require_ipv6(
                self.wanted_ipv6(original),
                "fixture IPv6 interface changed before restoration",
            )?;
            let mut interface = self
                .interface_for(AF_INET6)?
                .ok_or("owned adapter lost its IPv6 interface before restoration")?;
            interface.NlMtu = original.mtu;
            interface.DadTransmits = original.dad_transmits;
            interface.RouterDiscoveryBehavior = original.router_discovery;
            status(
                unsafe { SetIpInterfaceEntry(&mut interface) },
                "restore owned adapter IPv6 interface",
            )?;
            self.require_ipv6(original, "original IPv6 interface was not restored")?;
            self.ipv6_changed = false;
        }
        Ok(())
    }
}
impl Drop for OwnedNetwork<'_> {
    fn drop(&mut self) {
        if (!self.routes.is_empty()
            || !self.addresses.is_empty()
            || self.mtu_changed
            || self.ipv6_changed)
            && let Err(error) = self.restore()
        {
            eprintln!("Wintun packet fixture cleanup failed: {error}");
        }
    }
}

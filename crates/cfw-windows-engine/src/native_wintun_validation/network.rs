//! Disposable address/route ownership for the packet probes only. No default
//! route, DNS option or firewall rule is changed. Every mutation names the
//! retained adapter's native LUID, alias and creation GUID. Both IP families
//! get the probe MTU, so the stack cannot hand the session a larger packet.
use super::{Result, library};
use crate::tunnel::Adapter;
use std::{
    ffi::c_void,
    net::Ipv4Addr,
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
fn address(ip: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(ip.octets()),
                },
            },
            ..Default::default()
        },
    }
}
fn same_address(native: &SOCKADDR_INET, ip: Ipv4Addr) -> bool {
    unsafe {
        native.si_family == AF_INET && native.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes() == ip.octets()
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
        unsafe { GetUnicastIpAddressTable(AF_INET, &mut pointer) },
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
    if entries
        .iter()
        .any(|row| same_address(&row.Address, LOCAL) || same_address(&row.Address, REMOTE))
    {
        return Err("fixture address is already assigned to an interface".into());
    }
    let mut pointer = null_mut();
    status(
        unsafe { GetIpForwardTable2(AF_INET, &mut pointer) },
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
        row.DestinationPrefix.PrefixLength == 32
            && same_address(&row.DestinationPrefix.Prefix, REMOTE)
    }) {
        return Err("fixture host route already exists".into());
    }
    Ok(())
}

pub(super) struct OwnedNetwork<'a> {
    adapter: &'a Adapter<'a>,
    id: uuid::Uuid,
    original_mtu: u32,
    original_ipv6_mtu: Option<u32>,
    mtu: u16,
    mtu_changed: bool,
    ipv6_mtu_changed: bool,
    address: Option<MIB_UNICASTIPADDRESS_ROW>,
    route: Option<MIB_IPFORWARD_ROW2>,
}
impl<'a> OwnedNetwork<'a> {
    pub(super) fn configure(adapter: &'a Adapter<'a>, id: uuid::Uuid, mtu: u16) -> Result<Self> {
        require_unused_addresses_and_route()?;
        let mut value = Self {
            adapter,
            id,
            original_mtu: 0,
            original_ipv6_mtu: None,
            mtu,
            mtu_changed: false,
            ipv6_mtu_changed: false,
            address: None,
            route: None,
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
            if let Some(mut ipv6) = value.interface_for(AF_INET6)? {
                value.original_ipv6_mtu = Some(ipv6.NlMtu);
                ipv6.NlMtu = u32::from(mtu);
                status(
                    unsafe { SetIpInterfaceEntry(&mut ipv6) },
                    "set owned adapter IPv6 MTU",
                )?;
                value.ipv6_mtu_changed = true;
                if value.interface_for(AF_INET6)?.map(|row| row.NlMtu) != Some(u32::from(mtu)) {
                    return Err("adapter IPv6 MTU readback differs".into());
                }
            }
            let mut row = MIB_UNICASTIPADDRESS_ROW::default();
            unsafe { InitializeUnicastIpAddressEntry(&mut row) };
            row.InterfaceLuid = NET_LUID_LH {
                Value: adapter.luid(),
            };
            row.Address = address(LOCAL);
            row.OnLinkPrefixLength = 32;
            row.PrefixOrigin = IpPrefixOriginManual;
            row.SuffixOrigin = IpSuffixOriginManual;
            value.require_owner()?;
            status(
                unsafe { CreateUnicastIpAddressEntry(&row) },
                "create owned fixture address",
            )?;
            value.address = Some(row);
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                let mut observed = row;
                status(
                    unsafe { GetUnicastIpAddressEntry(&mut observed) },
                    "observe fixture address readiness",
                )?;
                if observed.DadState == IpDadStatePreferred {
                    break;
                }
                if observed.DadState != IpDadStateTentative || Instant::now() >= deadline {
                    return Err(format!(
                        "fixture address did not become usable: DAD {}",
                        observed.DadState
                    ));
                }
                thread::sleep(Duration::from_millis(100));
            }
            let mut row = MIB_IPFORWARD_ROW2::default();
            unsafe { InitializeIpForwardEntry(&mut row) };
            row.InterfaceLuid = NET_LUID_LH {
                Value: adapter.luid(),
            };
            row.DestinationPrefix = IP_ADDRESS_PREFIX {
                Prefix: address(REMOTE),
                PrefixLength: 32,
            };
            row.NextHop = address(Ipv4Addr::UNSPECIFIED);
            row.Metric = 0;
            row.Protocol = MIB_IPPROTO_NETMGMT;
            value.require_owner()?;
            status(
                unsafe { CreateIpForwardEntry2(&row) },
                "create owned fixture host route",
            )?;
            value.route = Some(row);
            value.verify_route(&row)?;
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
    fn verify_route(&self, expected: &MIB_IPFORWARD_ROW2) -> Result<()> {
        self.require_owner()?;
        let mut observed = *expected;
        status(
            unsafe { GetIpForwardEntry2(&mut observed) },
            "read owned fixture route",
        )?;
        if unsafe { observed.InterfaceLuid.Value } != self.adapter.luid()
            || observed.DestinationPrefix.PrefixLength != 32
            || !same_address(&observed.DestinationPrefix.Prefix, REMOTE)
            || !same_address(&observed.NextHop, Ipv4Addr::UNSPECIFIED)
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
    /// The adapter's IPv6 MTU before this probe, when IPv6 was bound to it.
    pub(super) fn original_ipv6_mtu(&self) -> Option<u32> {
        self.original_ipv6_mtu
    }
    pub(super) fn restore(&mut self) -> Result<()> {
        self.require_owner()?;
        if let Some(row) = self.route {
            self.verify_route(&row)?;
            status(
                unsafe { DeleteIpForwardEntry2(&row) },
                "remove owned fixture route",
            )?;
            self.route = None;
            let mut query = row;
            let code = unsafe { GetIpForwardEntry2(&mut query) };
            if code != ERROR_NOT_FOUND && code != ERROR_FILE_NOT_FOUND {
                return Err(format!(
                    "removed fixture route is not proven absent: {code}"
                ));
            }
        }
        if let Some(row) = self.address {
            self.require_owner()?;
            let mut observed = row;
            status(
                unsafe { GetUnicastIpAddressEntry(&mut observed) },
                "read owned fixture address",
            )?;
            if unsafe { observed.InterfaceLuid.Value } != self.adapter.luid()
                || !same_address(&observed.Address, LOCAL)
                || observed.OnLinkPrefixLength != 32
                || observed.PrefixOrigin != IpPrefixOriginManual
                || observed.SuffixOrigin != IpSuffixOriginManual
            {
                return Err("fixture address no longer matches its ownership record".into());
            }
            status(
                unsafe { DeleteUnicastIpAddressEntry(&row) },
                "remove owned fixture address",
            )?;
            self.address = None;
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
        if self.ipv6_mtu_changed {
            let original = self
                .original_ipv6_mtu
                .ok_or("IPv6 MTU change has no original value")?;
            let mut interface = self
                .interface_for(AF_INET6)?
                .ok_or("owned adapter lost its IPv6 interface before restoration")?;
            if interface.NlMtu != u32::from(self.mtu) {
                return Err("fixture IPv6 MTU changed before restoration".into());
            }
            interface.NlMtu = original;
            status(
                unsafe { SetIpInterfaceEntry(&mut interface) },
                "restore owned adapter IPv6 MTU",
            )?;
            if self.interface_for(AF_INET6)?.map(|row| row.NlMtu) != Some(original) {
                return Err("original IPv6 MTU was not restored".into());
            }
            self.ipv6_mtu_changed = false;
        }
        Ok(())
    }
}
impl Drop for OwnedNetwork<'_> {
    fn drop(&mut self) {
        if (self.route.is_some()
            || self.address.is_some()
            || self.mtu_changed
            || self.ipv6_mtu_changed)
            && let Err(error) = self.restore()
        {
            eprintln!("Wintun packet fixture cleanup failed: {error}");
        }
    }
}

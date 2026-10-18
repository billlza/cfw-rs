//! Read physical interfaces without changing proxy, route or DNS state. Calls
//! belong on the shell's native observation worker, never its UI thread.
use crate::{NetworkContext, NetworkKind};
use anyhow::{Context, bail};
use std::{
    collections::BTreeSet,
    mem::{align_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::{null, null_mut},
};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA},
        NetworkManagement::{
            IpHelper::{
                GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
                GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetIfEntry2,
                IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH,
                IP_ADAPTER_GATEWAY_ADDRESS_LH, IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IF_ROW2,
            },
            Ndis::{IfOperStatusUp, MediaConnectStateConnected},
        },
        Networking::WinSock::{
            AF_INET, AF_INET6, AF_UNSPEC, IpDadStateDeprecated as IP_DAD_STATE_DEPRECATED,
            IpDadStateDuplicate as IP_DAD_STATE_DUPLICATE,
            IpDadStateInvalid as IP_DAD_STATE_INVALID,
            IpDadStatePreferred as IP_DAD_STATE_PREFERRED,
            IpDadStateTentative as IP_DAD_STATE_TENTATIVE, SOCKADDR_IN, SOCKADDR_IN6,
            SOCKET_ADDRESS,
        },
        UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
    },
    core::GUID,
};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_ADAPTERS: usize = 128;

fn native(status: u32, operation: &'static str) -> anyhow::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(status as i32)).context(operation)
    }
}

struct Buffer(Vec<u64>);
// Only these plain native output layouts may be borrowed from the API buffer.
trait NativeRecord: Copy {}
impl NativeRecord for u16 {}
impl NativeRecord for SOCKADDR_IN {}
impl NativeRecord for SOCKADDR_IN6 {}
impl NativeRecord for IP_ADAPTER_ADDRESSES_LH {}
impl NativeRecord for IP_ADAPTER_UNICAST_ADDRESS_LH {}
impl NativeRecord for IP_ADAPTER_GATEWAY_ADDRESS_LH {}
impl Buffer {
    fn read<T: NativeRecord>(&self, pointer: *const T) -> anyhow::Result<&T> {
        let start = self.0.as_ptr() as usize;
        let offset = (pointer as usize)
            .checked_sub(start)
            .context("network record precedes its native buffer")?;
        let end = offset
            .checked_add(size_of::<T>())
            .context("network record size overflow")?;
        if pointer.is_null()
            || !(pointer as usize).is_multiple_of(align_of::<T>())
            || end > self.0.len() * 8
        {
            bail!("network record escapes its native buffer");
        }
        // The API's output buffer is initialized, retained and aligned; the
        // closed native layouts used here contain only scalar fields/pointers.
        Ok(unsafe { &*pointer })
    }

    fn address(&self, socket: &SOCKET_ADDRESS) -> anyhow::Result<IpAddr> {
        let family = *self.read(socket.lpSockaddr.cast::<u16>())?;
        match family {
            AF_INET => {
                if socket.iSockaddrLength != size_of::<SOCKADDR_IN>() as i32 {
                    bail!("invalid IPv4 address size");
                }
                let value = self.read(socket.lpSockaddr.cast::<SOCKADDR_IN>())?;
                Ok(Ipv4Addr::from(unsafe { value.sin_addr.S_un.S_addr }.to_ne_bytes()).into())
            }
            AF_INET6 => {
                if socket.iSockaddrLength != size_of::<SOCKADDR_IN6>() as i32 {
                    bail!("invalid IPv6 address size");
                }
                let value = self.read(socket.lpSockaddr.cast::<SOCKADDR_IN6>())?;
                Ok(Ipv6Addr::from(unsafe { value.sin6_addr.u.Byte }).into())
            }
            _ => bail!("unexpected family in native unicast address"),
        }
    }

    fn unicast_addresses(
        &self,
        mut pointer: *const IP_ADAPTER_UNICAST_ADDRESS_LH,
    ) -> anyhow::Result<Vec<IpAddr>> {
        let mut addresses = Vec::new();
        let mut seen = BTreeSet::new();
        while !pointer.is_null() {
            if seen.len() >= 64 || !seen.insert(pointer as usize) {
                bail!("unicast enumeration is cyclic or too large");
            }
            let value = self.read(pointer)?;
            if unsafe { value.Anonymous.Anonymous.Length }
                < size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>() as u32
            {
                bail!("Windows unicast record is truncated");
            }
            pointer = value.Next;
            match value.DadState {
                IP_DAD_STATE_INVALID | IP_DAD_STATE_TENTATIVE | IP_DAD_STATE_DUPLICATE => continue,
                IP_DAD_STATE_PREFERRED | IP_DAD_STATE_DEPRECATED => {}
                _ => bail!("Windows unicast address has an unknown readiness state"),
            }
            let address = self.address(&value.Address)?;
            if usable_address(address) {
                addresses.push(address);
            }
        }
        addresses.sort();
        addresses.dedup();
        Ok(addresses)
    }

    fn has_gateway(
        &self,
        mut pointer: *const IP_ADAPTER_GATEWAY_ADDRESS_LH,
    ) -> anyhow::Result<bool> {
        let mut seen = BTreeSet::new();
        let mut present = false;
        while !pointer.is_null() {
            if seen.len() >= 64 || !seen.insert(pointer as usize) {
                bail!("gateway enumeration is cyclic or too large");
            }
            let value = self.read(pointer)?;
            if unsafe { value.Anonymous.Anonymous.Length }
                < size_of::<IP_ADAPTER_GATEWAY_ADDRESS_LH>() as u32
            {
                bail!("Windows gateway record is truncated");
            }
            present |= usable_address(self.address(&value.Address)?);
            pointer = value.Next;
        }
        Ok(present)
    }
}

fn usable_address(address: IpAddr) -> bool {
    !address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(value) if value.is_broadcast())
}

fn adapters() -> anyhow::Result<Option<Buffer>> {
    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_INCLUDE_GATEWAYS;
    let mut requested = 16 * 1024;
    for _ in 0..3 {
        if !(size_of::<IP_ADAPTER_ADDRESSES_LH>()..=MAX_BYTES).contains(&requested) {
            bail!("Windows adapter enumeration exceeds its memory bound");
        }
        let mut buffer = Buffer(vec![0; requested.div_ceil(8)]);
        let mut size = (buffer.0.len() * 8) as u32;
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                null(),
                buffer.0.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status == ERROR_NO_DATA {
            return Ok(None);
        }
        if status == ERROR_BUFFER_OVERFLOW {
            requested = size as usize;
            continue;
        }
        native(status, "observe Windows adapter addresses")?;
        return Ok(Some(buffer));
    }
    bail!("Windows adapters changed during all three bounded reads")
}

fn physical_kind(row: &MIB_IF_ROW2) -> Option<NetworkKind> {
    // HardwareInterface must be set. Filter, unauthenticated, disconnected,
    // paused, low-power and endpoint interfaces are not physical triggers.
    let flags = row.InterfaceAndOperStatusFlags._bitfield;
    if flags & 1 == 0
        || flags & 0b1111_1010 != 0
        || row.OperStatus != IfOperStatusUp
        || row.MediaConnectState != MediaConnectStateConnected
    {
        return None;
    }
    match row.Type {
        IF_TYPE_ETHERNET_CSMACD => Some(NetworkKind::Wired),
        IF_TYPE_IEEE80211 => Some(NetworkKind::Wifi),
        _ => None,
    }
}

struct Candidate {
    context: NetworkContext,
    guid: GUID,
    rank: (bool, u32, u32, u16, u16, [u8; 8]),
}

pub(crate) fn current_network_context() -> anyhow::Result<Option<NetworkContext>> {
    let Some(buffer) = adapters()? else {
        return Ok(None);
    };
    let mut seen = BTreeSet::new();
    let mut pointer = buffer.0.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut candidates = Vec::new();
    while !pointer.is_null() {
        if seen.len() >= MAX_ADAPTERS || !seen.insert(pointer as usize) {
            bail!("adapter enumeration is cyclic or too large");
        }
        let adapter = buffer.read(pointer)?;
        if unsafe { adapter.Anonymous1.Anonymous.Length }
            < size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32
        {
            bail!("Windows adapter record is truncated");
        }
        pointer = adapter.Next;
        if !matches!(adapter.IfType, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211) {
            continue;
        }
        let mut row = MIB_IF_ROW2 {
            InterfaceLuid: adapter.Luid,
            ..MIB_IF_ROW2::default()
        };
        native(
            unsafe { GetIfEntry2(&mut row) },
            "observe native interface ownership",
        )?;
        if row.Type != adapter.IfType {
            bail!("Windows interface identity changed during observation");
        }
        let Some(kind) = physical_kind(&row) else {
            continue;
        };
        let name_end = row
            .Alias
            .iter()
            .position(|unit| *unit == 0)
            .filter(|size| *size > 0)
            .context("physical interface name is missing or unterminated")?;
        let interface = String::from_utf16(&row.Alias[..name_end])
            .context("physical interface name is not valid UTF-16")?;
        let addresses = buffer.unicast_addresses(adapter.FirstUnicastAddress)?;
        if addresses.is_empty() {
            continue;
        }
        let has_v4 = addresses.iter().any(IpAddr::is_ipv4);
        let has_v6 = addresses.iter().any(IpAddr::is_ipv6);
        let metric = match (has_v4, has_v6) {
            (true, true) => adapter.Ipv4Metric.min(adapter.Ipv6Metric),
            (true, false) => adapter.Ipv4Metric,
            (false, true) => adapter.Ipv6Metric,
            (false, false) => unreachable!("validated addresses are IPv4 or IPv6"),
        };
        let has_gateway = buffer.has_gateway(adapter.FirstGatewayAddress)?;
        let guid = row.InterfaceGuid;
        candidates.push(Candidate {
            context: NetworkContext {
                interface,
                kind,
                ssid: None,
                addresses: addresses.iter().map(ToString::to_string).collect(),
            },
            guid,
            rank: (
                !has_gateway,
                metric,
                guid.data1,
                guid.data2,
                guid.data3,
                guid.data4,
            ),
        });
    }
    // Select a physical gateway-bearing interface first, then its configured IP
    // metric. The GUID provides stable tie-breaking; a TUN default route never
    // turns a virtual interface into an automation trigger.
    candidates.sort_by_key(|candidate| candidate.rank);
    let Some(mut selected) = candidates.into_iter().next() else {
        return Ok(None);
    };
    if selected.context.kind == NetworkKind::Wifi {
        selected.context.ssid = Some(wifi_name(&selected.guid)?);
    }
    Ok(Some(selected.context))
}

pub(crate) fn request_wifi_name_access() -> anyhow::Result<()> {
    let uri: Vec<u16> = "ms-settings:privacy-location\0".encode_utf16().collect();
    let verb: Vec<u16> = "open\0".encode_utf16().collect();
    // Fixed OS settings URI, used only by the visible permission button.
    // Acceptance does not claim that the user granted location permission.
    let result = unsafe {
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            uri.as_ptr(),
            null(),
            null(),
            SW_SHOWNORMAL,
        )
    } as isize;
    if result <= 32 {
        bail!("Windows could not open location privacy settings (code {result})");
    }
    Ok(())
}

fn with_connection_profiles<T>(
    read: impl FnOnce(&[windows::Networking::Connectivity::ConnectionProfile]) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    use windows::{
        Networking::Connectivity::NetworkInformation,
        Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize},
    };
    // This synchronous scope stays on the native worker. An incompatible
    // apartment is an explicit error; no UI thread is reinitialized or blocked.
    unsafe { RoInitialize(RO_INIT_MULTITHREADED) }
        .context("initialize Windows network observation on its native worker")?;
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe { RoUninitialize() };
        }
    }
    let _apartment = Apartment;
    let profiles = NetworkInformation::GetConnectionProfiles()
        .context("observe Windows connection profiles")?;
    let count = profiles
        .Size()
        .context("read Windows connection profile count")?;
    if count > MAX_ADAPTERS as u32 {
        bail!("Windows connection profile count exceeds its observation bound");
    }
    let mut observed = Vec::with_capacity(count as usize);
    for index in 0..count {
        observed.push(
            profiles
                .GetAt(index)
                .context("read Windows connection profile")?,
        );
    }
    // Callers return owned data; all WinRT interfaces are released inside the
    // initialized apartment. No interface crosses an asynchronous suspension.
    read(&observed)
}

fn wifi_name(guid: &GUID) -> anyhow::Result<String> {
    use windows::Networking::Connectivity::NetworkConnectivityLevel;
    with_connection_profiles(|profiles| {
        let mut result = None;
        for profile in profiles {
            if !profile.IsWlanConnectionProfile()? {
                continue;
            }
            let identity = profile.NetworkAdapter()?.NetworkAdapterId()?;
            if (
                identity.data1,
                identity.data2,
                identity.data3,
                identity.data4,
            ) != (guid.data1, guid.data2, guid.data3, guid.data4)
            {
                continue;
            }
            if profile.GetNetworkConnectivityLevel()? == NetworkConnectivityLevel::None {
                bail!("Wi-Fi connection changed during observation");
            }
            if result.is_some() {
                bail!("multiple Wi-Fi profiles claim the selected interface");
            }
            // SSID-only API recommended by Microsoft. Do not query BSSIDs or
            // scan nearby networks merely to select a named Wi-Fi profile.
            let name = profile
                .WlanConnectionProfileDetails()?
                .GetConnectedSsid()
                .context("read the connected Wi-Fi name")?;
            result = Some(decode_wifi_name(&name)?);
        }
        result.context("the selected Wi-Fi interface has no current connection profile")
    })
}

fn decode_wifi_name(units: &[u16]) -> anyhow::Result<String> {
    if units.len() > 32 {
        bail!("Wi-Fi name exceeds its observation bound");
    }
    let name = String::from_utf16(units).context("Wi-Fi name is not valid UTF-16")?;
    if name.is_empty() || name.len() > 32 || name.chars().any(char::is_control) {
        bail!("Wi-Fi name cannot be represented by the profile matching contract");
    }
    Ok(name)
}

#[cfg(test)]
mod tests;

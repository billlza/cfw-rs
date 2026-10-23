//! The Wintun network device carrying one adapter GUID, found through SetupAPI
//! so SYSTEM can prove an adapter is gone or remove one that an earlier SYSTEM
//! process left behind. Only modern `SWD\WINTUN` instances are opened, a
//! device is never chosen by name, and the driver itself is never removed.
use super::{Error, Result, native_error};
use std::{
    mem::size_of,
    ptr::{null, null_mut},
    thread,
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Devices::DeviceAndDriverInstallation::*,
        Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND, GetLastError,
            INVALID_HANDLE_VALUE,
        },
        NetworkManagement::{IpHelper::ConvertInterfaceGuidToLuid, Ndis::NET_LUID_LH},
        System::Registry::{KEY_QUERY_VALUE, RRF_RT_REG_SZ, RegCloseKey, RegGetValueW},
    },
    core::GUID,
};

/// Network-class device enumeration never visits more instances than this.
const MAXIMUM_DEVICES: u32 = 4096;
const ABSENCE_POLL: Duration = Duration::from_millis(50);

struct DeviceSet(HDEVINFO);
impl DeviceSet {
    fn present_network_devices() -> Result<Self> {
        let raw =
            unsafe { SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, null(), null_mut(), DIGCF_PRESENT) };
        if raw == -1 {
            return Err(native_error("observe network device instances"));
        }
        Ok(Self(raw))
    }
    fn close(&mut self) -> Result<()> {
        if self.0 != -1 {
            if unsafe { SetupDiDestroyDeviceInfoList(self.0) } == 0 {
                return Err(native_error("close device information set"));
            }
            self.0 = -1;
        }
        Ok(())
    }
}
impl Drop for DeviceSet {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("Wintun device observation cleanup: {error}");
        }
    }
}

/// One present Wintun device instance and the interface GUID its driver key
/// names. Its set stays open so removal acts on the exact enumerated node.
pub(crate) struct WintunDevice {
    set: DeviceSet,
    device: SP_DEVINFO_DATA,
    instance_id: String,
    interface_guid: uuid::Uuid,
}
impl WintunDevice {
    /// The present Wintun instance for `guid`: none, exactly one, or an error
    /// when several instances claim the same interface GUID.
    pub(crate) fn find(guid: uuid::Uuid) -> Result<Option<Self>> {
        if guid.is_nil() {
            return Err("adapter identity is nil".into());
        }
        let set = DeviceSet::present_network_devices()?;
        let mut matched = None;
        for index in 0..MAXIMUM_DEVICES {
            let mut device = SP_DEVINFO_DATA {
                cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut device) } == 0 {
                if unsafe { GetLastError() } != ERROR_NO_MORE_ITEMS {
                    return Err(native_error("enumerate network device instances"));
                }
                return Ok(matched.map(|(device, instance_id)| Self {
                    set,
                    device,
                    instance_id,
                    interface_guid: guid,
                }));
            }
            let instance = instance_id(set.0, &device)?;
            // Non-Wintun devices are never opened for registry inspection or
            // removal; the product only creates modern SWD Wintun instances.
            if !instance.to_ascii_uppercase().starts_with("SWD\\WINTUN\\") {
                continue;
            }
            if network_guid(set.0, &device)? == guid {
                if matched.is_some() {
                    return Err("multiple Wintun instances claim the same interface GUID".into());
                }
                matched = Some((device, instance));
            }
        }
        Err("network device enumeration exceeded its bound".into())
    }

    pub(crate) fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub(crate) fn interface_guid(&self) -> uuid::Uuid {
        self.interface_guid
    }

    /// The enumerated node still names the same instance and interface GUID.
    pub(crate) fn revalidate(&self) -> Result<()> {
        if instance_id(self.set.0, &self.device)? != self.instance_id
            || network_guid(self.set.0, &self.device)? != self.interface_guid
        {
            return Err("retained Wintun device identity changed".into());
        }
        Ok(())
    }

    /// Remove this exact instance. A result that needs a restart is not a
    /// completed removal. The caller proves absence afterwards.
    pub(crate) fn remove(mut self) -> Result<()> {
        self.revalidate()?;
        let parameters = SP_REMOVEDEVICE_PARAMS {
            ClassInstallHeader: SP_CLASSINSTALL_HEADER {
                cbSize: size_of::<SP_CLASSINSTALL_HEADER>() as u32,
                InstallFunction: DIF_REMOVE,
            },
            Scope: DI_REMOVEDEVICE_GLOBAL,
            HwProfile: 0,
        };
        if unsafe {
            SetupDiSetClassInstallParamsW(
                self.set.0,
                &self.device,
                &parameters.ClassInstallHeader,
                size_of::<SP_REMOVEDEVICE_PARAMS>() as u32,
            )
        } == 0
        {
            return Err(native_error("prepare Wintun device removal"));
        }
        if unsafe { SetupDiCallClassInstaller(DIF_REMOVE, self.set.0, &self.device) } == 0 {
            return Err(native_error("remove Wintun device"));
        }
        let mut installed = SP_DEVINSTALL_PARAMS_W {
            cbSize: size_of::<SP_DEVINSTALL_PARAMS_W>() as u32,
            ..Default::default()
        };
        if unsafe { SetupDiGetDeviceInstallParamsW(self.set.0, &self.device, &mut installed) } == 0
        {
            return Err(native_error("observe Wintun device removal result"));
        }
        if installed.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART) != 0 {
            return Err("Wintun device removal requires a restart; cleanup is not complete".into());
        }
        self.set.close()
    }
}

/// The interface LUID Windows currently maps to `guid`, or None when no
/// interface carries it. Lookup failures other than absence are errors.
pub(crate) fn interface_luid(guid: uuid::Uuid) -> Result<Option<u64>> {
    let (data1, data2, data3, data4) = guid.as_fields();
    let native = GUID {
        data1,
        data2,
        data3,
        data4: *data4,
    };
    let mut luid = NET_LUID_LH { Value: 0 };
    let status = unsafe { ConvertInterfaceGuidToLuid(&native, &mut luid) };
    if status == ERROR_FILE_NOT_FOUND || status == ERROR_NOT_FOUND {
        return Ok(None);
    }
    if status != 0 {
        return Err(Error::Native {
            operation: "map adapter GUID to its interface",
            source: std::io::Error::from_raw_os_error(status as i32),
        });
    }
    match unsafe { luid.Value } {
        0 => Err("adapter GUID maps to a zero interface LUID".into()),
        value => Ok(Some(value)),
    }
}

/// Neither an interface nor a present Wintun device carries `guid`.
pub(crate) fn absent(guid: uuid::Uuid) -> Result<bool> {
    Ok(interface_luid(guid)?.is_none() && WintunDevice::find(guid)?.is_none())
}

/// Poll until `guid` is absent or `deadline` passes; a lookup error stops.
pub(crate) fn wait_until_absent(guid: uuid::Uuid, deadline: Instant) -> Result<bool> {
    loop {
        if absent(guid)? {
            return Ok(true);
        }
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(false);
        };
        thread::sleep(left.min(ABSENCE_POLL));
    }
}

pub(crate) fn instance_id(set: HDEVINFO, device: &SP_DEVINFO_DATA) -> Result<String> {
    let mut buffer = [0u16; 512];
    let mut required = 0;
    if unsafe {
        SetupDiGetDeviceInstanceIdW(
            set,
            device,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut required,
        )
    } == 0
    {
        return Err(native_error("observe device instance ID"));
    }
    if required == 0 || required as usize > buffer.len() || buffer[required as usize - 1] != 0 {
        return Err("invalid device instance ID length".into());
    }
    String::from_utf16(&buffer[..required as usize - 1])
        .map_err(|error| Error::Contract(error.to_string()))
}

pub(crate) fn network_guid(set: HDEVINFO, device: &SP_DEVINFO_DATA) -> Result<uuid::Uuid> {
    let key = unsafe {
        SetupDiOpenDevRegKey(set, device, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE)
    };
    if key == INVALID_HANDLE_VALUE {
        return Err(native_error("open adapter driver identity"));
    }
    let name: Vec<_> = "NetCfgInstanceId".encode_utf16().chain(Some(0)).collect();
    let mut buffer = [0u16; 64];
    let mut bytes = size_of::<[u16; 64]>() as u32;
    let status = unsafe {
        RegGetValueW(
            key,
            null(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    let closed = unsafe { RegCloseKey(key) };
    if status != 0 || closed != 0 {
        return Err(format!(
            "observe/close adapter driver identity: query={status}, close={closed}"
        )
        .into());
    }
    if bytes < 2
        || !bytes.is_multiple_of(2)
        || bytes as usize > size_of::<[u16; 64]>()
        || buffer[bytes as usize / 2 - 1] != 0
    {
        return Err("invalid adapter driver GUID length".into());
    }
    let text = String::from_utf16(&buffer[..bytes as usize / 2 - 1])
        .map_err(|error| Error::Contract(error.to_string()))?;
    uuid::Uuid::parse_str(&text).map_err(|error| Error::Contract(error.to_string()))
}

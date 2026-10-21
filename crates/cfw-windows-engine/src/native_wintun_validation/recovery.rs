//! One disposable probe adapter, identified while its retained owner is alive.
//! This is not a production recovery journal or permission to remove arbitrary
//! Wintun devices. No discovery-by-name or global driver cleanup is performed.
use super::{OwnerReady, Result, library, native_error};
use crate::{NativePeerProcess, PeerIdentityError};
use std::{
    mem::size_of,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Devices::DeviceAndDriverInstallation::*,
    Foundation::{ERROR_NO_MORE_ITEMS, GetLastError, INVALID_HANDLE_VALUE},
    System::Registry::{KEY_QUERY_VALUE, RRF_RT_REG_SZ, RegCloseKey, RegGetValueW},
};

struct DeviceSet(HDEVINFO);
impl DeviceSet {
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
            eprintln!("Wintun observation cleanup: {error}");
        }
    }
}

pub(super) struct OwnedDevice {
    set: DeviceSet,
    device: SP_DEVINFO_DATA,
    owner: NativePeerProcess,
    pub(super) instance_id: String,
    pub(super) interface_guid: uuid::Uuid,
    luid: u64,
    name: String,
}
impl OwnedDevice {
    pub(super) fn close(mut self) -> Result<()> {
        self.set.close()
    }

    pub(super) fn retain(
        ready: &OwnerReady,
        owner: NativePeerProcess,
        requested: uuid::Uuid,
    ) -> Result<Self> {
        owner.revalidate().map_err(|error| error.to_string())?;
        if owner.process_id() != ready.process_id
            || owner.identity().process_creation_time() != ready.process_creation_time
        {
            return Err("adapter recovery owner differs from the launched child".into());
        }
        let guid = library::interface_identity(ready.luid, &ready.name)?;
        if guid != requested {
            return Err("created adapter GUID differs from the requested probe identity".into());
        }
        let raw =
            unsafe { SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, null(), null_mut(), DIGCF_PRESENT) };
        if raw == -1 {
            return Err(native_error("observe network device instances"));
        }
        let set = DeviceSet(raw);
        let mut matched = None;
        for index in 0..4096 {
            let mut device = SP_DEVINFO_DATA {
                cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut device) } == 0 {
                if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                    let (device, instance_id) =
                        matched.ok_or("created Wintun device instance not found")?;
                    owner.revalidate().map_err(|error| error.to_string())?;
                    let result = Self {
                        set,
                        device,
                        owner,
                        instance_id,
                        interface_guid: guid,
                        luid: ready.luid,
                        name: ready.name.clone(),
                    };
                    result.revalidate_device()?;
                    return Ok(result);
                }
                return Err(native_error("enumerate network device instances"));
            }
            let instance = instance_id(set.0, &device)?;
            // Non-Wintun devices are never opened for registry inspection or
            // removal. This fixture only creates modern SWD Wintun instances.
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

    fn revalidate_device(&self) -> Result<()> {
        if instance_id(self.set.0, &self.device)? != self.instance_id
            || network_guid(self.set.0, &self.device)? != self.interface_guid
            || library::interface_identity(self.luid, &self.name)? != self.interface_guid
        {
            return Err("retained Wintun device identity changed".into());
        }
        Ok(())
    }

    pub(super) fn remove_after_owner_exit(&self) -> Result<()> {
        match self.owner.revalidate() {
            Err(PeerIdentityError::Exited) => {}
            Ok(()) => return Err("live adapter owner cannot be recovered".into()),
            Err(error) => return Err(format!("adapter owner retirement is unproven: {error}")),
        }
        self.revalidate_device()?;
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
            return Err(native_error("prepare owned adapter removal"));
        }
        if unsafe { SetupDiCallClassInstaller(DIF_REMOVE, self.set.0, &self.device) } == 0 {
            return Err(native_error("remove retained owned adapter"));
        }
        let mut installed = SP_DEVINSTALL_PARAMS_W {
            cbSize: size_of::<SP_DEVINSTALL_PARAMS_W>() as u32,
            ..Default::default()
        };
        if unsafe { SetupDiGetDeviceInstallParamsW(self.set.0, &self.device, &mut installed) } == 0
        {
            return Err(native_error("observe owned adapter removal result"));
        }
        if installed.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART) != 0 {
            return Err("owned adapter removal requires restart; cleanup is not complete".into());
        }
        library::wait_absent(self.luid, &self.name)
    }
}

fn instance_id(set: HDEVINFO, device: &SP_DEVINFO_DATA) -> Result<String> {
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
        return Err(native_error("observe retained device instance ID"));
    }
    if required == 0 || required as usize > buffer.len() || buffer[required as usize - 1] != 0 {
        return Err("invalid device instance ID length".into());
    }
    String::from_utf16(&buffer[..required as usize - 1]).map_err(|error| error.to_string())
}

fn network_guid(set: HDEVINFO, device: &SP_DEVINFO_DATA) -> Result<uuid::Uuid> {
    let key = unsafe {
        SetupDiOpenDevRegKey(set, device, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE)
    };
    if key == INVALID_HANDLE_VALUE {
        return Err(native_error("open retained adapter driver identity"));
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
        ));
    }
    if bytes < 2
        || !bytes.is_multiple_of(2)
        || bytes as usize > size_of::<[u16; 64]>()
        || buffer[bytes as usize / 2 - 1] != 0
    {
        return Err("invalid adapter driver GUID length".into());
    }
    let text =
        String::from_utf16(&buffer[..bytes as usize / 2 - 1]).map_err(|error| error.to_string())?;
    uuid::Uuid::parse_str(&text).map_err(|error| error.to_string())
}

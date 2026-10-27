//! One disposable probe adapter, identified while its retained owner is alive.
//! This is not a production recovery journal or permission to remove arbitrary
//! Wintun devices. No discovery-by-name or global driver cleanup is performed.
//! Device lookup and removal are the production `WintunDevice` operations.
use super::{OwnerReady, Result, library};
use crate::{NativePeerProcess, PeerIdentityError, tunnel::WintunDevice};

pub(super) struct OwnedDevice {
    device: Option<WintunDevice>,
    owner: NativePeerProcess,
    pub(super) instance_id: String,
    pub(super) interface_guid: uuid::Uuid,
    luid: u64,
    name: String,
}
impl OwnedDevice {
    pub(super) fn close(self) -> Result<()> {
        // Dropping an unremoved device closes its information set only.
        drop(self.device);
        Ok(())
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
        let guid = library::interface_identity(ready.luid, &ready.name)
            .map_err(|error| error.to_string())?;
        if guid != requested {
            return Err("created adapter GUID differs from the requested probe identity".into());
        }
        let device = WintunDevice::find(guid)
            .map_err(|error| error.to_string())?
            .ok_or("created Wintun device instance not found")?;
        owner.revalidate().map_err(|error| error.to_string())?;
        let result = Self {
            instance_id: device.instance_id().to_owned(),
            interface_guid: device.interface_guid(),
            device: Some(device),
            owner,
            luid: ready.luid,
            name: ready.name.clone(),
        };
        result.revalidate_device()?;
        Ok(result)
    }

    fn revalidate_device(&self) -> Result<()> {
        self.device
            .as_ref()
            .ok_or("retained Wintun device was already removed")?
            .revalidate()
            .map_err(|error| error.to_string())?;
        if library::interface_identity(self.luid, &self.name).map_err(|error| error.to_string())?
            != self.interface_guid
        {
            return Err("retained Wintun device identity changed".into());
        }
        Ok(())
    }

    pub(super) fn remove_after_owner_exit(&mut self) -> Result<()> {
        match self.owner.revalidate() {
            Err(PeerIdentityError::Exited) => {}
            Ok(()) => return Err("live adapter owner cannot be recovered".into()),
            Err(error) => return Err(format!("adapter owner retirement is unproven: {error}")),
        }
        self.revalidate_device()?;
        self.device
            .take()
            .ok_or("retained Wintun device was already removed")?
            .remove()
            .map_err(|error| error.to_string())?;
        library::wait_absent(self.luid, &self.name).map_err(|error| error.to_string())
    }
}

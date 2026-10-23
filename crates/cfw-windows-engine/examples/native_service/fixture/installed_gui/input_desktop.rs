//! Hosted installed-GUI validation requires the observed ordinary input desktop.
//! Read-only user-object access: no ACL, window-station or desktop switch.
use super::*;
use std::mem::size_of_val;
use windows_sys::Win32::System::StationsAndDesktops::*;

// WSF_VISIBLE is the documented flag for the interactive station.
const WSF_VISIBLE: u32 = 1;

pub(super) struct InputDesktop {
    handle: HDESK,
    path: Vec<u16>,
    station_name: String,
    desktop_name: String,
}

impl InputDesktop {
    pub(super) fn open() -> Result<Self> {
        let station = unsafe { GetProcessWindowStation() };
        if station.is_null() {
            return Err(error("observe GUI controller window station"));
        }
        let station_name = object_name(station)?;
        let mut flags = USEROBJECTFLAGS::default();
        let mut needed = 0;
        if unsafe {
            GetUserObjectInformationW(
                station,
                UOI_FLAGS,
                &mut flags as *mut USEROBJECTFLAGS as *mut c_void,
                size_of::<USEROBJECTFLAGS>() as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(error("observe GUI controller window-station flags"));
        }
        if needed as usize != size_of::<USEROBJECTFLAGS>() {
            return Err("GUI window-station flags have an unexpected size".into());
        }
        if !station_name.eq_ignore_ascii_case("WinSta0") || flags.dwFlags & WSF_VISIBLE == 0 {
            return Err("installed GUI requires the interactive Windows window station".into());
        }
        let handle = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
        if handle.is_null() {
            return Err(error("open hosted input desktop for observation"));
        }
        let mut result = Self {
            handle,
            path: Vec::new(),
            station_name,
            desktop_name: String::new(),
        };
        let desktop_name = object_name(handle)?;
        if !desktop_name.eq_ignore_ascii_case("Default") {
            return Err("hosted GUI input desktop is not the ordinary Default desktop".into());
        }
        result.path = wide(&format!("{}\\{desktop_name}", result.station_name));
        result.desktop_name = desktop_name;
        Ok(result)
    }

    pub(super) fn observation(&self) -> serde_json::Value {
        serde_json::json!({
            "window_station": self.station_name, "desktop": self.desktop_name,
            "interactive_window_station": true, "input_desktop_observed": true,
            "existing_user_object_permissions_changed": false
        })
    }

    pub(super) fn path(&mut self) -> *mut u16 {
        self.path.as_mut_ptr()
    }

    pub(super) fn close(&mut self) -> Result<()> {
        if !self.handle.is_null() {
            if unsafe { CloseDesktop(self.handle) } == 0 {
                return Err(error("close input desktop observation handle"));
            }
            self.handle = null_mut();
        }
        Ok(())
    }
}

impl Drop for InputDesktop {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("input desktop observation cleanup failed: {error}");
        }
    }
}

fn object_name(handle: HANDLE) -> Result<String> {
    let mut name = [0u16; 256];
    let mut needed = 0;
    if unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            name.as_mut_ptr().cast(),
            size_of_val(&name) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(error("read bounded GUI user-object name"));
    }
    if needed < 2 || needed as usize > size_of_val(&name) || !needed.is_multiple_of(2) {
        return Err("GUI user-object name length is invalid".into());
    }
    let name = &name[..needed as usize / 2];
    if name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
        return Err("GUI user-object name terminator is invalid".into());
    }
    String::from_utf16(&name[..name.len() - 1]).map_err(|e| e.to_string())
}

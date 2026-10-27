//! Private user objects for the restricted client's loader/USER initialization.
//! No existing desktop/window-station ACL is changed.
use super::*;
use windows_sys::Win32::System::StationsAndDesktops::*;

pub(super) struct Desktop {
    station: HWINSTA,
    desktop: HDESK,
    path: Vec<u16>,
}

struct Selection {
    station: HWINSTA,
    desktop: HDESK,
    restored: bool,
}
impl Selection {
    fn capture() -> Result<Self> {
        let station = unsafe { GetProcessWindowStation() };
        let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        if station.is_null() || desktop.is_null() {
            return Err(error("observe controller user-object selection"));
        }
        Ok(Self {
            station,
            desktop,
            restored: false,
        })
    }
    fn restore(&mut self) -> Result<()> {
        if unsafe { SetProcessWindowStation(self.station) } == 0 {
            return Err(error("restore controller window station"));
        }
        if unsafe { SetThreadDesktop(self.desktop) } == 0 {
            return Err(error("restore controller thread desktop"));
        }
        self.restored = true;
        Ok(())
    }
}
impl Drop for Selection {
    fn drop(&mut self) {
        if !self.restored
            && let Err(error) = self.restore()
        {
            eprintln!("fixture user-object selection cleanup failed: {error}");
        }
    }
}

impl Desktop {
    pub(super) fn new() -> Result<Self> {
        let user = NativePeerProcess::open(std::process::id()).map_err(|e| e.to_string())?;
        let sid = user.identity().user_sid();
        let security = Descriptor::new(&format!(
            "O:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)S:(ML;;NW;;;ME)"
        ))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.0,
            bInheritHandle: 0,
        };
        let station_name = format!("CFW-fixture-{}", uuid::Uuid::new_v4());
        let mut result = Self {
            station: null_mut(),
            desktop: null_mut(),
            path: wide(&format!("{station_name}\\client")),
        };
        // Drops before the owned handles on error/unwind. These selections
        // belong only to this controller; existing user-object ACLs stay intact.
        let mut selection = Selection::capture()?;
        let created = (|| -> Result<()> {
            unsafe { SetLastError(0) };
            result.station = unsafe {
                CreateWindowStationW(wide(&station_name).as_ptr(), 0, GENERIC_ALL, &attributes)
            };
            if result.station.is_null() {
                return Err(error("create private fixture window station"));
            }
            if io::Error::last_os_error().raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
                return Err("private fixture window station already existed".into());
            }
            if unsafe { SetProcessWindowStation(result.station) } == 0 {
                return Err(error("select private fixture window station"));
            }
            result.desktop = unsafe {
                CreateDesktopW(
                    wide("client").as_ptr(),
                    null(),
                    null(),
                    0,
                    GENERIC_ALL,
                    &attributes,
                )
            };
            if result.desktop.is_null() {
                return Err(error("create private fixture desktop"));
            }
            Ok(())
        })();
        let restored = selection.restore();
        match (created, restored) {
            (Ok(()), Ok(())) => {}
            (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
            (Err(error), Err(cleanup)) => {
                return Err(format!(
                    "{error}; user-object selection restoration also failed: {cleanup}"
                ));
            }
        }
        Ok(result)
    }

    pub(super) fn path(&mut self) -> *mut u16 {
        self.path.as_mut_ptr()
    }

    pub(super) fn close(&mut self) -> Result<()> {
        if !self.desktop.is_null() {
            if unsafe { CloseDesktop(self.desktop) } == 0 {
                return Err(error("close private fixture desktop"));
            }
            self.desktop = null_mut();
        }
        if !self.station.is_null() {
            if unsafe { CloseWindowStation(self.station) } == 0 {
                return Err(error("close private fixture window station"));
            }
            self.station = null_mut();
        }
        Ok(())
    }
}

impl Drop for Desktop {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            // Success paths explicitly check close; this is failure cleanup.
            eprintln!("fixture user-object cleanup failed: {error}");
        }
    }
}

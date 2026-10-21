//! Wintun 0.14.1 ABI, from the header in the hash-pinned official distribution.
//! This probe creates its own adapter handles and never calls OpenAdapter or
//! DeleteDriver. It does not establish product routing or recovery admission.
use super::{Result, native_error, pin};
use crate::VerifiedExecutable;
use std::{
    ffi::{OsString, c_void},
    mem::size_of,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    ptr::{NonNull, null_mut},
    thread,
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, FreeLibrary, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        NetworkManagement::{
            IpHelper::{GetIfEntry2, MIB_IF_ROW2},
            Ndis::NET_LUID_LH,
        },
        System::{
            LibraryLoader::{
                GetModuleFileNameW, GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
                LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
            },
            Threading::WaitForSingleObject,
        },
    },
    core::GUID,
};

type CreateAdapter = unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> *mut c_void;
type CloseAdapter = unsafe extern "system" fn(*mut c_void);
type GetAdapterLuid = unsafe extern "system" fn(*mut c_void, *mut NET_LUID_LH);
type StartSession = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type EndSession = unsafe extern "system" fn(*mut c_void);
type ReadWaitEvent = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
type DriverVersion = unsafe extern "system" fn() -> u32;

struct Module(Option<NonNull<c_void>>);
impl Module {
    fn close(&mut self) -> Result<()> {
        if let Some(handle) = self.0.take() {
            // The module owns this reference. No adapter/session may outlive it.
            if unsafe { FreeLibrary(handle.as_ptr()) } == 0 {
                return Err(native_error("release Wintun library"));
            }
        }
        Ok(())
    }
}
impl Drop for Module {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("Wintun failure cleanup: {error}");
        }
    }
}

pub(super) struct Library {
    module: Module,
    _image: VerifiedExecutable,
    create: CreateAdapter,
    close_adapter: CloseAdapter,
    luid: GetAdapterLuid,
    start: StartSession,
    end: EndSession,
    event: ReadWaitEvent,
    version: DriverVersion,
}
impl Library {
    pub(super) fn load(path: &Path) -> Result<Self> {
        let digest = super::digest_pin(pin("WINTUN_WINDOWS_AMD64_SHA256")?)?;
        let image = VerifiedExecutable::open(path, digest, pin("WINTUN_VERSION")?)
            .map_err(|error| error.to_string())?;
        let mut wide: Vec<_> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err("Wintun path contains NUL".into());
        }
        wide.push(0);
        // Only the retained absolute image and system DLL dependencies are searched.
        let handle = NonNull::new(unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        })
        .ok_or_else(|| native_error("load pinned Wintun library"))?;
        let module = Module(Some(handle));
        let mut actual = vec![0u16; 32768];
        let length = unsafe {
            GetModuleFileNameW(handle.as_ptr(), actual.as_mut_ptr(), actual.len() as u32)
        } as usize;
        if length == 0 || length >= actual.len() {
            return Err(native_error("observe loaded Wintun image"));
        }
        let actual = PathBuf::from(OsString::from_wide(&actual[..length]));
        image
            .verify_image_file(&actual)
            .map_err(|error| error.to_string())?;
        macro_rules! symbol {
            ($name:literal, $kind:ty) => {{
                let function =
                    unsafe { GetProcAddress(handle.as_ptr(), concat!($name, "\0").as_ptr()) }
                        .ok_or_else(|| native_error(concat!("resolve ", $name)))?;
                // Each signature exactly matches the pinned x64 wintun.h typedef.
                unsafe {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, $kind>(function)
                }
            }};
        }
        Ok(Self {
            create: symbol!("WintunCreateAdapter", CreateAdapter),
            close_adapter: symbol!("WintunCloseAdapter", CloseAdapter),
            luid: symbol!("WintunGetAdapterLUID", GetAdapterLuid),
            start: symbol!("WintunStartSession", StartSession),
            end: symbol!("WintunEndSession", EndSession),
            event: symbol!("WintunGetReadWaitEvent", ReadWaitEvent),
            version: symbol!("WintunGetRunningDriverVersion", DriverVersion),
            module,
            _image: image,
        })
    }

    pub(super) fn create(&self, id: uuid::Uuid) -> Result<Adapter<'_>> {
        let name = format!("CFW-TUN-probe-{id}");
        let wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let kind: Vec<_> = "CFW validation".encode_utf16().chain(Some(0)).collect();
        let (data1, data2, data3, data4) = id.as_fields();
        let guid = GUID {
            data1,
            data2,
            data3,
            data4: *data4,
        };
        let handle = NonNull::new(unsafe { (self.create)(wide.as_ptr(), kind.as_ptr(), &guid) })
            .ok_or_else(|| native_error("create owned Wintun adapter"))?;
        let adapter = Adapter {
            library: self,
            handle,
            name,
        };
        let luid = adapter.luid();
        if luid == 0 {
            return Err("created Wintun adapter has a zero LUID".into());
        }
        match observe(luid)? {
            Some(name) if name == adapter.name => {}
            Some(_) => {
                return Err(format!(
                    "created Wintun LUID {luid} has a different native alias"
                ));
            }
            None => {
                return Err(format!(
                    "created Wintun LUID {luid} is absent from the native interface table"
                ));
            }
        }
        Ok(adapter)
    }

    pub(super) fn close(mut self) -> Result<()> {
        self.module.close()
    }
}

pub(super) struct Adapter<'a> {
    library: &'a Library,
    handle: NonNull<c_void>,
    pub(super) name: String,
}
impl Adapter<'_> {
    pub(super) fn luid(&self) -> u64 {
        let mut luid = NET_LUID_LH { Value: 0 };
        unsafe {
            (self.library.luid)(self.handle.as_ptr(), &mut luid);
            luid.Value
        }
    }
    pub(super) fn session(&self) -> Result<Session<'_>> {
        // Wintun's documented minimum: two finite 128-KiB rings.
        let handle = NonNull::new(unsafe { (self.library.start)(self.handle.as_ptr(), 0x20000) })
            .ok_or_else(|| native_error("start Wintun packet session"))?;
        let session = Session {
            adapter: self,
            handle,
        };
        let event = unsafe { (self.library.event)(handle.as_ptr()) };
        if event.is_null() {
            return Err(native_error("observe Wintun receive event"));
        }
        // Borrowed from the session: never CloseHandle this event.
        let state = unsafe { WaitForSingleObject(event, 0) };
        if state == WAIT_FAILED {
            return Err(native_error("inspect Wintun receive event"));
        }
        if ![WAIT_OBJECT_0, WAIT_TIMEOUT].contains(&state) {
            return Err("unexpected Wintun receive-event state".into());
        }
        if unsafe { (self.library.version)() } == 0 {
            return Err(native_error("observe running Wintun driver"));
        }
        Ok(session)
    }
    pub(super) fn driver_version(&self) -> Result<u32> {
        let version = unsafe { (self.library.version)() };
        if version == 0 {
            return Err(native_error("observe running Wintun driver"));
        }
        Ok(version)
    }
}
impl Drop for Adapter<'_> {
    fn drop(&mut self) {
        unsafe { (self.library.close_adapter)(self.handle.as_ptr()) };
    }
}
pub(super) struct Session<'a> {
    adapter: &'a Adapter<'a>,
    handle: NonNull<c_void>,
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        unsafe { (self.adapter.library.end)(self.handle.as_ptr()) };
    }
}

pub(super) fn observe(luid: u64) -> Result<Option<String>> {
    if luid == 0 || size_of::<NET_LUID_LH>() != 8 {
        return Err("invalid native adapter identity".into());
    }
    let mut row = MIB_IF_ROW2 {
        InterfaceLuid: NET_LUID_LH { Value: luid },
        ..Default::default()
    };
    let status = unsafe { GetIfEntry2(&mut row) };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != 0 {
        return Err(format!(
            "observe adapter: {}",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    if unsafe { row.InterfaceLuid.Value } != luid {
        return Err("adapter observation changed its requested LUID".into());
    }
    let end = row
        .Alias
        .iter()
        .position(|value| *value == 0)
        .ok_or("unterminated adapter alias")?;
    Ok(Some(
        String::from_utf16(&row.Alias[..end]).map_err(|error| error.to_string())?,
    ))
}

pub(super) fn wait_absent(luid: u64, name: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match observe(luid)? {
            None => return Ok(()),
            Some(observed) if observed == name && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50))
            }
            Some(observed) if observed != name => {
                return Err("adapter LUID now belongs to another identity".into());
            }
            Some(_) => return Err("owned Wintun adapter remains after its owner retired".into()),
        }
    }
}

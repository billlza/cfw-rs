//! Wintun 0.14.1 ABI, from the header in the hash-pinned official distribution.
//! Owned handles only: never OpenAdapter or DeleteDriver. Routing and durable
//! authority admission remain separate from this low-level driver boundary.
use super::{Error, Result, native_error};
use crate::VerifiedExecutable;
#[cfg(feature = "native-service-validation")]
use std::path::Path;
use std::{
    ffi::{OsString, c_void},
    mem::size_of,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
    ptr::{NonNull, null_mut},
};
#[cfg(feature = "native-service-validation")]
use std::{
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
type ReceivePacket = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type ReleasePacket = unsafe extern "system" fn(*mut c_void, *const u8);
type AllocatePacket = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(*mut c_void, *const u8);

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

pub struct Library {
    module: Module,
    _image: VerifiedExecutable,
    create: CreateAdapter,
    close_adapter: CloseAdapter,
    luid: GetAdapterLuid,
    start: StartSession,
    end: EndSession,
    pub(super) event: ReadWaitEvent,
    version: DriverVersion,
    pub(super) receive: ReceivePacket,
    pub(super) release: ReleasePacket,
    pub(super) allocate: AllocatePacket,
    pub(super) send: SendPacket,
}
impl Library {
    pub fn load(installation: &crate::runtime_host::InstalledRuntime) -> Result<Self> {
        Self::from_verified(installation.wintun()?)
    }

    #[cfg(feature = "native-service-validation")]
    pub(crate) fn load_for_validation(path: &Path) -> Result<Self> {
        let pin = crate::runtime_host::wintun_image_pin()?;
        Self::from_verified(VerifiedExecutable::open(path, pin.digest()?, pin.version)?)
    }

    fn from_verified(image: VerifiedExecutable) -> Result<Self> {
        let path = image.path();
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
        image.verify_image_file(&actual)?;
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
            receive: symbol!("WintunReceivePacket", ReceivePacket),
            release: symbol!("WintunReleaseReceivePacket", ReleasePacket),
            allocate: symbol!("WintunAllocateSendPacket", AllocatePacket),
            send: symbol!("WintunSendPacket", SendPacket),
            module,
            _image: image,
        })
    }

    pub fn create(&self, id: uuid::Uuid) -> Result<Adapter<'_>> {
        if id.is_nil() {
            return Err("adapter identity is nil".into());
        }
        let name = format!("CFW-TUN-{id}");
        let wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let kind: Vec<_> = "Clash for Windows".encode_utf16().chain(Some(0)).collect();
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
                return Err(
                    format!("created Wintun LUID {luid} has a different native alias").into(),
                );
            }
            None => {
                return Err(format!(
                    "created Wintun LUID {luid} is absent from the native interface table"
                )
                .into());
            }
        }
        if interface_identity(luid, &adapter.name)? != id {
            return Err("created adapter GUID differs from its requested identity".into());
        }
        Ok(adapter)
    }

    pub fn close(mut self) -> Result<()> {
        self.module.close()
    }
}

pub struct Adapter<'a> {
    pub(super) library: &'a Library,
    handle: NonNull<c_void>,
    name: String,
}
impl Adapter<'_> {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn luid(&self) -> u64 {
        let mut luid = NET_LUID_LH { Value: 0 };
        unsafe {
            (self.library.luid)(self.handle.as_ptr(), &mut luid);
            luid.Value
        }
    }
    pub fn session(&self, mtu: u16) -> Result<Session<'_>> {
        super::packet::validate_mtu(mtu)?;
        // Wintun's documented minimum: two finite 128-KiB rings.
        let handle = NonNull::new(unsafe {
            (self.library.start)(self.handle.as_ptr(), super::RING_CAPACITY_BYTES)
        })
        .ok_or_else(|| native_error("start Wintun packet session"))?;
        let session = Session {
            adapter: self,
            handle,
            mtu,
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
    pub fn driver_version(&self) -> Result<u32> {
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
pub struct Session<'a> {
    pub(super) adapter: &'a Adapter<'a>,
    pub(super) handle: NonNull<c_void>,
    pub(super) mtu: u16,
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        unsafe { (self.adapter.library.end)(self.handle.as_ptr()) };
    }
}

pub fn observe(luid: u64) -> Result<Option<String>> {
    row(luid)?.map(|row| alias(&row)).transpose()
}

pub fn interface_identity(luid: u64, name: &str) -> Result<uuid::Uuid> {
    let row = row(luid)?.ok_or("owned adapter is absent")?;
    if alias(&row)? != name {
        return Err("adapter alias no longer matches its owner".into());
    }
    let guid = row.InterfaceGuid;
    Ok(uuid::Uuid::from_fields(
        guid.data1,
        guid.data2,
        guid.data3,
        &guid.data4,
    ))
}

fn row(luid: u64) -> Result<Option<MIB_IF_ROW2>> {
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
        return Err(Error::Native {
            operation: "observe adapter",
            source: std::io::Error::from_raw_os_error(status as i32),
        });
    }
    if unsafe { row.InterfaceLuid.Value } != luid {
        return Err("adapter observation changed its requested LUID".into());
    }
    Ok(Some(row))
}

fn alias(row: &MIB_IF_ROW2) -> Result<String> {
    let end = row
        .Alias
        .iter()
        .position(|value| *value == 0)
        .ok_or("unterminated adapter alias")?;
    String::from_utf16(&row.Alias[..end]).map_err(|error| Error::Contract(error.to_string()))
}

#[cfg(feature = "native-service-validation")]
pub fn wait_absent(luid: u64, name: &str) -> Result<()> {
    if absence_within_deadline(luid, name)? {
        Ok(())
    } else {
        Err("owned Wintun adapter remains after its owner retired".into())
    }
}

#[cfg(feature = "native-service-validation")]
pub fn absence_within_deadline(luid: u64, name: &str) -> Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match observe(luid)? {
            None => return Ok(true),
            Some(observed) if observed == name && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50))
            }
            Some(observed) if observed != name => {
                return Err("adapter LUID now belongs to another identity".into());
            }
            Some(_) => return Ok(false),
        }
    }
}

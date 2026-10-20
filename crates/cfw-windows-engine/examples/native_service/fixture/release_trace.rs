//! A bounded ETW controller/consumer used only in the opted-in disposable VM.
//! Read the real product emitter in the installed medium-integrity coordinator.
use super::{Result, path_wide, wide};
use cfw_windows_engine::{NativePeerProcess, runtime_host::InstalledRuntime};
use serde_json::{Value, json};
use std::{
    io::Read,
    mem::{offset_of, size_of},
    path::Path,
    ptr::null,
};
use windows_sys::{Win32::System::Diagnostics::Etw::*, core::GUID};

const PROVIDER: GUID = GUID::from_u128(0x25895b69_d30b_5395_8518_8926d4e012ab);
const SESSION: &str = "CFW installed desktop observation validation";
const PREFIX: &str = "cfw-windows-release-observation-v1 ";
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[repr(C)]
struct Properties {
    value: EVENT_TRACE_PROPERTIES,
    name: [u16; 128],
    file: [u16; 1024],
}

struct Trace {
    handle: Option<CONTROLTRACE_HANDLE>,
    properties: Box<Properties>,
}

impl Trace {
    fn start(path: &Path) -> Result<Self> {
        if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
            || std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1")
        {
            return Err("ETW controller requires opted-in disposable GitHub CI".into());
        }
        if path.exists() {
            return Err("ETW evidence path already exists".into());
        }
        let mut properties = Box::new(Properties {
            value: EVENT_TRACE_PROPERTIES::default(),
            name: [0; 128],
            file: [0; 1024],
        });
        let name = wide(SESSION);
        let file = path_wide(path);
        if file.len() > properties.file.len() || name.len() > properties.name.len() {
            return Err("ETW trace name or path exceeds the fixture bound".into());
        }
        properties.file[..file.len()].copy_from_slice(&file);
        properties.value.Wnode.BufferSize = size_of::<Properties>() as u32;
        properties.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties.value.Wnode.ClientContext = 1;
        properties.value.BufferSize = 64;
        properties.value.MinimumBuffers = 2;
        properties.value.MaximumBuffers = 8;
        properties.value.MaximumFileSize = 4;
        properties.value.LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL;
        properties.value.FlushTimer = 1;
        properties.value.LoggerNameOffset = offset_of!(Properties, name) as u32;
        properties.value.LogFileNameOffset = offset_of!(Properties, file) as u32;
        let mut handle = CONTROLTRACE_HANDLE::default();
        // SAFETY: Properties is aligned, contiguous and owns both string areas.
        let status = unsafe { StartTraceW(&mut handle, name.as_ptr(), &mut properties.value) };
        check("start bounded ETW session", status)?;
        let mut trace = Self {
            handle: Some(handle),
            properties,
        };
        // SAFETY: this controller owns the live session and fixed provider ID.
        let status = unsafe {
            EnableTraceEx2(
                handle,
                &PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                4,
                1,
                0,
                1000,
                null(),
            )
        };
        if let Err(operation) = check("enable desktop ETW provider", status) {
            return match trace.stop() {
                Ok(()) => Err(operation),
                Err(cleanup) => Err(format!("{operation}; stop trace: {cleanup}")),
            };
        }
        Ok(trace)
    }

    fn stop(&mut self) -> Result<()> {
        let handle = self.handle.ok_or("ETW session was already stopped")?;
        // SAFETY: only this fixture controls this retained session handle.
        let status = unsafe {
            ControlTraceW(
                handle,
                null(),
                &mut self.properties.value,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        check("stop and flush desktop ETW trace", status)?;
        self.handle = None;
        Ok(())
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        if self.handle.is_some()
            && let Err(error) = self.stop()
        {
            eprintln!("ETW fixture cleanup failed: {error}");
        }
    }
}

fn check(operation: &str, status: u32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!("{operation}: Win32 {status}"))
    }
}

#[derive(Default)]
struct Events {
    records: Vec<Value>,
    error: Option<String>,
}

unsafe extern "system" fn event(record: *mut EVENT_RECORD) {
    // SAFETY: ProcessTrace supplies live EVENT_RECORD/UserContext allocations;
    // one synchronous file consumer accesses Events until ProcessTrace returns.
    let record = unsafe { &*record };
    let events = unsafe { &mut *record.UserContext.cast::<Events>() };
    let provider = record.EventHeader.ProviderId;
    if events.error.is_some()
        || (
            provider.data1,
            provider.data2,
            provider.data3,
            provider.data4,
        ) != (
            PROVIDER.data1,
            PROVIDER.data2,
            PROVIDER.data3,
            PROVIDER.data4,
        )
    {
        return;
    }
    let read = || -> Result<Value> {
        let descriptor = record.EventHeader.EventDescriptor;
        if descriptor.Id != 1
            || descriptor.Version != 1
            || descriptor.Level != 4
            || descriptor.Keyword != 1
            || descriptor.Channel != 0
            || descriptor.Opcode != 0
            || descriptor.Task != 0
            || record.ExtendedDataCount != 0
            || record.UserData.is_null()
            || record.UserDataLength == 0
            || record.UserDataLength > 8192
            || events.records.len() >= 16
        {
            return Err("unexpected or unbounded desktop ETW record".into());
        }
        // SAFETY: ETW owns UserDataLength initialized bytes during this callback.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                record.UserData.cast::<u8>(),
                usize::from(record.UserDataLength),
            )
        };
        let message = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
        let payload = message
            .strip_prefix(PREFIX)
            .ok_or("ETW product prefix differs")?;
        let value: Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        if value["process"]["pid"] != record.EventHeader.ProcessId {
            return Err("ETW kernel header and product PID differ".into());
        }
        Ok(json!({"header_pid":record.EventHeader.ProcessId,"event":value}))
    };
    match read() {
        Ok(value) => events.records.push(value),
        Err(error) => events.error = Some(error),
    }
}

fn read_events(path: &Path) -> Result<Vec<Value>> {
    let length = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if length == 0 || length > MAX_FILE_BYTES {
        return Err("ETW file size is invalid".into());
    }
    let mut path = path_wide(path);
    let mut events = Events::default();
    let mut log = EVENT_TRACE_LOGFILEW {
        LogFileName: path.as_mut_ptr(),
        Anonymous1: EVENT_TRACE_LOGFILEW_0 {
            ProcessTraceMode: PROCESS_TRACE_MODE_EVENT_RECORD,
        },
        Anonymous2: EVENT_TRACE_LOGFILEW_1 {
            EventRecordCallback: Some(event),
        },
        Context: (&mut events as *mut Events).cast(),
        ..Default::default()
    };
    // SAFETY: the path and callback context remain alive until CloseTrace.
    let handle = unsafe { OpenTraceW(&mut log) };
    if handle.Value == u64::MAX {
        return Err(super::error("open ETW evidence"));
    }
    let read_status = unsafe { ProcessTrace(&handle, 1, null(), null()) };
    let close_status = unsafe { CloseTrace(handle) };
    if read_status != 0 || close_status != 0 {
        return Err(format!(
            "ETW read/close failed: {read_status}/{close_status}"
        ));
    }
    if let Some(error) = events.error {
        return Err(error);
    }
    if log.EventsLost != 0 || log.LogfileHeader.EventsLost != 0 {
        return Err("ETW consumer reported lost events".into());
    }
    Ok(events.records)
}

fn require_keys(value: &Value, expected: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("ETW field is not an object")?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err("ETW event has missing or unexpected fields".into());
    }
    Ok(())
}

fn validate(records: &[Value], directory: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    std::fs::File::open(directory.join("installed-host-coordinator-lifecycle.json"))
        .map_err(|e| e.to_string())?
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 16384 {
        return Err("coordinator receipt exceeds its bound".into());
    }
    let report: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let coordinator = &report["coordinator"];
    let installation = InstalledRuntime::open()
        .map_err(|e| e.to_string())?
        .release();
    let native = NativePeerProcess::open(std::process::id()).map_err(|e| e.to_string())?;
    let candidate = json!({"version":installation.version,"build_number":installation.build.to_string(),
        "msi_product_code":installation.product_code,"msi_package_code":installation.package_code});
    if records.len() != 4
        || coordinator["final_observation_sequence"] != 4
        || coordinator["modes"][0]["observation_sequence"] != 2
        || coordinator["modes"][1]["observation_sequence"] != 3
    {
        return Err("ETW trace does not contain the four coordinator observations".into());
    }
    for (index, (record, phase, snapshot)) in [
        (&records[0], "off", &coordinator["initial"]),
        (
            &records[1],
            "local_proxy_active",
            &coordinator["modes"][0]["snapshot"],
        ),
        (
            &records[2],
            "proxy_active",
            &coordinator["modes"][1]["snapshot"],
        ),
        (&records[3], "off", &coordinator["shutdown"]),
    ]
    .into_iter()
    .enumerate()
    {
        let event = &record["event"];
        require_keys(
            event,
            &[
                "schema_version",
                "document",
                "component",
                "event",
                "sequence",
                "recorded_unix_ms",
                "process",
                "candidate",
                "payload",
            ],
        )?;
        require_keys(
            &event["process"],
            &["pid", "creation_filetime", "session_id"],
        )?;
        require_keys(&event["payload"], &["state"])?;
        let state = &event["payload"]["state"];
        require_keys(
            state,
            &[
                "desired_mode",
                "generation",
                "config_digest",
                "phase",
                "owner",
                "ready",
                "ipv6_enabled",
            ],
        )?;
        let active = index == 1 || index == 2;
        if event["document"] != "cfw-windows-product-observation-event-v1"
            || event["schema_version"] != 1
            || event["component"] != "host"
            || event["event"] != "engine_snapshot"
            || event["sequence"] != index + 1
            || event["recorded_unix_ms"]
                .as_u64()
                .is_none_or(|time| time == 0)
            || event["candidate"] != candidate
            || event["process"]["pid"] != coordinator["process_observation"]["pid"]
            || event["process"]["creation_filetime"]
                != coordinator["process_observation"]["creation_filetime"]
            || event["process"]["session_id"] != native.identity().session_id()
            || state["phase"] != phase
            || state["desired_mode"] != snapshot["desired_mode"]
            || state["generation"] != snapshot["generation"]
            || state["config_digest"] != snapshot["config_digest"]
            || state["owner"]
                != if active {
                    json!("windows_user_agent")
                } else {
                    Value::Null
                }
            || state["ready"] != active
            || state["ipv6_enabled"] != active
        {
            return Err(format!(
                "ETW observation {} differs from the actual coordinator",
                index + 1
            ));
        }
    }
    Ok(())
}

pub(super) fn capture(directory: &Path, exercise: impl FnOnce() -> Result<()>) -> Result<()> {
    let path = directory.join("installed-host-observation.etl");
    let mut trace = Trace::start(&path)?;
    let operation = exercise();
    let cleanup = trace.stop();
    match (operation, cleanup) {
        (Err(operation), Err(cleanup)) => return Err(format!("{operation}; {cleanup}")),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
        (Ok(()), Ok(())) => {}
    }
    let properties = &trace.properties.value;
    if properties.EventsLost != 0
        || properties.LogBuffersLost != 0
        || properties.RealTimeBuffersLost != 0
    {
        return Err("ETW session lost events or buffers".into());
    }
    let records = read_events(&path)?;
    validate(&records, directory)?;
    let report = json!({"product_source":std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e|e.to_string())?,
        "provider":"25895b69-d30b-5395-8518-8926d4e012ab", "actual_product_emitter":true,
        "medium_integrity":true, "etl_readback_verified":true, "events_lost":properties.EventsLost,
        "log_buffers_lost":properties.LogBuffersLost, "records":records, "release_accepted":false});
    std::fs::write(
        directory.join("installed-host-observation.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

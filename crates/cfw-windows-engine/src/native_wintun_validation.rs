//! Isolated native driver experiments. Enabled only for validation builds and
//! opted-in disposable CI hosts; no production TUN capability uses this module.
use crate::NativePeerProcess;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

mod library;
mod recovery;
use library::{Library, observe, wait_absent};
type Result<T> = std::result::Result<T, String>;
const PINS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/dependency_pins.env"
));

fn pin(key: &str) -> Result<&'static str> {
    let prefix = format!("{key}=");
    let mut values = PINS.lines().filter_map(|line| line.strip_prefix(&prefix));
    let value = values.next().ok_or("missing compiled Wintun pin")?;
    if values.next().is_some() || value.is_empty() {
        return Err("ambiguous compiled Wintun pin".into());
    }
    Ok(value)
}

fn digest_pin(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid compiled Wintun digest".into());
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| error.to_string())?;
    }
    Ok(digest)
}

fn native_error(operation: &str) -> String {
    format!("{operation}: {}", std::io::Error::last_os_error())
}

fn source() -> Result<String> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("CFW_NATIVE_TUN_MUTATION_TESTS").as_deref() != Ok("1")
    {
        return Err("Wintun validation requires disposable Windows CI opt-in".into());
    }
    let source = std::env::var("CFW_NATIVE_TUN_SOURCE").map_err(|error| error.to_string())?;
    if source.len() != 40
        || !source
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid Wintun validation source".into());
    }
    Ok(source)
}

fn record(output: &Path, name: &str, value: &Value) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join(name))
        .map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(&mut file, value).map_err(|error| error.to_string())?;
    file.write_all(b"\n")
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())
}

/// CLI used exclusively by native-wintun-probe. No command installs a product
/// service or writes routes, DNS, firewall rules, or adapter IP configuration.
pub fn run(arguments: &[String]) -> Result<()> {
    let source = source()?;
    if arguments.len() == 3 && arguments[0] == "--adapter-owner" {
        return owner(&PathBuf::from(&arguments[1]), &arguments[2], &source);
    }
    if arguments.len() != 2 {
        return Err("expected Wintun DLL and absent receipt directory".into());
    }
    let dll = PathBuf::from(&arguments[0]);
    let output = PathBuf::from(&arguments[1]);
    if !dll.is_absolute() || !output.is_absolute() || output.exists() {
        return Err("invalid Wintun validation paths".into());
    }
    std::fs::create_dir(&output).map_err(|error| error.to_string())?;
    let peer = NativePeerProcess::open(std::process::id()).map_err(|error| error.to_string())?;
    record(
        &output,
        "initial.json",
        &json!({"source":source,"process_id":peer.process_id(),
        "process_creation_time":peer.identity().process_creation_time(),
        "integrity_rid":peer.identity().integrity_rid(),"local_system":peer.identity().is_local_system(),
        "dll_sha256":pin("WINTUN_WINDOWS_AMD64_SHA256")?,"release_accepted":false}),
    )?;
    let result = (|| {
        let library = Library::load(&dll)?;
        let observed = (|| {
            let adapter = library.create(uuid::Uuid::new_v4())?;
            let luid = adapter.luid();
            let name = adapter.name.clone();
            let session = adapter.session()?;
            let driver_version = adapter.driver_version()?;
            record(
                &output,
                "normal-live.json",
                &json!({"source":source,"luid":luid,"name":name,
                "session_started":true,"receive_wait_event_valid":true,"ring_capacity_bytes":131072,
                "running_driver_version":driver_version,"packet_traffic_verified":false}),
            )?;
            drop(session);
            drop(adapter);
            wait_absent(luid, &name)?;
            record(
                &output,
                "normal-retired.json",
                &json!({"source":source,"luid":luid,"name":name,
                "adapter_absence_observed":true,"release_accepted":false}),
            )?;
            abrupt_owner_exit(&library, &dll, &output, &source)?;
            Ok(())
        })();
        let closed = library.close();
        match (observed, closed) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(format!("{error}; library cleanup: {cleanup}")),
        }
    })();
    let receipt = record(
        &output,
        "result.json",
        &json!({"source":source,"success":result.is_ok(),
        "failure":result.as_ref().err(),"normal_and_forced_owner_exit_exercised":result.is_ok(),
        "crash_recovery_strategy":"retained_device_instance","service_restart_recovery_exercised":false,
        "explicit_route_dns_firewall_writes":false,"packet_traffic_verified":false,
        "product_tunnel_backend_exercised":false,"release_accepted":false}),
    );
    match (result, receipt) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(receipt)) => Err(format!("{error}; receipt: {receipt}")),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerReady {
    source: String,
    process_id: u32,
    process_creation_time: u64,
    name: String,
    luid: u64,
    session_started: bool,
}

fn owner(dll: &Path, id: &str, source: &str) -> Result<()> {
    let id = uuid::Uuid::parse_str(id).map_err(|error| error.to_string())?;
    let library = Library::load(dll)?;
    let adapter = library.create(id)?;
    let _session = adapter.session()?;
    let peer = NativePeerProcess::open(std::process::id()).map_err(|error| error.to_string())?;
    let ready = OwnerReady {
        source: source.into(),
        process_id: peer.process_id(),
        process_creation_time: peer.identity().process_creation_time(),
        name: adapter.name.clone(),
        luid: adapter.luid(),
        session_started: true,
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &ready).map_err(|error| error.to_string())?;
    stdout
        .write_all(b"\n")
        .and_then(|()| stdout.flush())
        .map_err(|error| error.to_string())?;
    // The parent must observe an abrupt retained-process exit, not an orderly
    // adapter close. CI's independent process deadline also bounds this child.
    loop {
        thread::park();
    }
}

fn terminate_child(child: &mut Child) -> Result<ExitStatus> {
    if child
        .try_wait()
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err("adapter owner exited before directed termination".into());
    }
    child.kill().map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("adapter owner termination was not observed".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn abrupt_owner_exit(library: &Library, dll: &Path, output: &Path, source: &str) -> Result<()> {
    let control_id = uuid::Uuid::new_v4();
    let control = library.create(control_id)?;
    let control_session = control.session()?;
    let control_luid = control.luid();
    let control_name = control.name.clone();
    if library::interface_identity(control_luid, &control_name)? != control_id {
        return Err("control adapter GUID differs from its creation identity".into());
    }
    record(
        output,
        "recovery-control-live.json",
        &json!({
            "source":source,"luid":control_luid,"name":control_name,
            "interface_guid":control_id.to_string(),"session_started":true
        }),
    )?;
    let id = uuid::Uuid::new_v4();
    let name = format!("CFW-TUN-probe-{id}");
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut child = Command::new(&executable)
        .arg("--adapter-owner")
        .arg(dll)
        .arg(id.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| error.to_string())?;
    let outcome = (|| {
        let stdout = child
            .stdout
            .take()
            .ok_or("adapter owner stdout was not captured")?;
        let (send, receive) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = BufReader::new(stdout)
                .take(4097)
                .read_until(b'\n', &mut bytes)
                .map_err(|error| error.to_string())
                .and_then(|_| {
                    if bytes.len() > 4096 || bytes.last() != Some(&b'\n') {
                        return Err("invalid adapter owner frame".into());
                    }
                    serde_json::from_slice::<OwnerReady>(&bytes).map_err(|error| error.to_string())
                });
            // A dropped receiver means the bounded caller already failed and
            // is retiring the child; no successful observation is published.
            let _ = send.send(result);
        });
        let ready = receive
            .recv_timeout(Duration::from_secs(30))
            .map_err(|error| format!("adapter owner readiness: {error}"))??;
        let peer = NativePeerProcess::open(child.id()).map_err(|error| error.to_string())?;
        if ready.source != source
            || ready.process_id != child.id()
            || ready.process_creation_time != peer.identity().process_creation_time()
            || ready.name != name
            || !ready.session_started
            || ready.luid == 0
            || peer
                .observed_image_path()
                .map_err(|error| error.to_string())?
                .canonicalize()
                .map_err(|error| error.to_string())?
                != executable
                    .canonicalize()
                    .map_err(|error| error.to_string())?
            || observe(ready.luid)?.as_deref() != Some(name.as_str())
        {
            return Err(
                "adapter readiness differs from the launched owner and native interface".into(),
            );
        }
        record(
            output,
            "abrupt-live.json",
            &serde_json::to_value(&ready).map_err(|error| error.to_string())?,
        )?;
        let wrong_guid = recovery::OwnedDevice::retain(
            &ready,
            peer.retain().map_err(|error| error.to_string())?,
            control_id,
        );
        match wrong_guid {
            Err(error)
                if error == "created adapter GUID differs from the requested probe identity" => {}
            Err(error) => {
                return Err(format!(
                    "foreign GUID rejection was not established: {error}"
                ));
            }
            Ok(_) => return Err("foreign adapter GUID was admitted for recovery".into()),
        }
        let device = recovery::OwnedDevice::retain(&ready, peer, id)?;
        let live_removal = device.remove_after_owner_exit();
        if live_removal != Err("live adapter owner cannot be recovered".into()) {
            return Err(format!(
                "live adapter owner removal was not rejected before mutation: {live_removal:?}"
            ));
        }
        record(
            output,
            "abrupt-device-binding.json",
            &json!({
                "source":source,"process_id":ready.process_id,"process_creation_time":ready.process_creation_time,
                "luid":ready.luid,"name":ready.name,"interface_guid":device.interface_guid.to_string(),
                "device_instance_id":device.instance_id,"live_owner_removal_rejected":true,
                "foreign_guid_rejected":true
            }),
        )?;
        Ok((ready, device))
    })();
    let exit = terminate_child(&mut child);
    let (ready, device, status) = match (outcome, exit) {
        (Ok((ready, device)), Ok(status)) => (ready, device, status),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(cleanup)) => return Err(format!("{error}; child cleanup: {cleanup}")),
    };
    if status.success() {
        return Err("forced adapter-owner exit unexpectedly reported success".into());
    }
    record(
        output,
        "abrupt-exit.json",
        &json!({"source":source,"process_id":ready.process_id,
        "process_creation_time":ready.process_creation_time,"exit_code":status.code(),"retained_child_exit_observed":true}),
    )?;
    // The original native experiment proved that abrupt process exit can
    // leave an adapter present. Preserve this observation, then require exact
    // retained-device recovery and independent interface absence.
    let recovered = (|| {
        let automatic = library::absence_within_deadline(ready.luid, &name)?;
        record(
            output,
            "abrupt-before-recovery.json",
            &json!({
                "source":source,"luid":ready.luid,"name":name,
                "automatic_absence_observed":automatic,"observation_limit_ms":15000,
                "release_accepted":false
            }),
        )?;
        if !automatic {
            device.remove_after_owner_exit()?;
        }
        record(
            output,
            "abrupt-retired.json",
            &json!({"source":source,"luid":ready.luid,"name":name,
        "adapter_absence_observed":true,"automatic_absence_observed":automatic,
        "explicit_owned_device_removal":!automatic,"release_accepted":false}),
        )
    })();
    let closed = device.close();
    let result = match (recovered, closed) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; device observer cleanup: {cleanup}")),
    };
    let control_result = (|| {
        if library::interface_identity(control_luid, &control_name)? != control_id {
            return Err("adapter recovery changed the live control adapter".into());
        }
        record(
            output,
            "recovery-control-preserved.json",
            &json!({
                "source":source,"luid":control_luid,"name":control_name,
                "interface_guid":control_id.to_string(),"live_control_preserved":true
            }),
        )
    })();
    drop(control_session);
    drop(control);
    let control_cleanup = library::wait_absent(control_luid, &control_name).and_then(|()| {
        record(
            output,
            "recovery-control-retired.json",
            &json!({
                "source":source,"luid":control_luid,"name":control_name,
                "adapter_absence_observed":true,"release_accepted":false
            }),
        )
    });
    let failures: Vec<_> = [result, control_result, control_cleanup]
        .into_iter()
        .filter_map(Result::err)
        .collect();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

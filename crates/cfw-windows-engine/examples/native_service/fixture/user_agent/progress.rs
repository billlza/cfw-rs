//! Nonsecret test progress only. This file grants no product capability.
use super::*;
use cfw_windows_engine::authority::LeaseContext;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    agent_pid: u32,
    engine_pid: u32,
    operation_id: uuid::Uuid,
    lease_id: uuid::Uuid,
}
fn path(root: &Path, name: &str, context: &LeaseContext) -> PathBuf {
    root.join(format!(
        "{name}-{}.ready.json",
        context.operation.operation_id
    ))
}
pub(super) fn publish(
    root: &Path,
    name: &str,
    ready: &cfw_windows_engine::user_agent::ReadyObservation,
) -> Result<()> {
    let target = path(root, name, ready.context());
    let partial = target.with_extension("part");
    let value = Ready {
        agent_pid: std::process::id(),
        engine_pid: ready.process_id(),
        operation_id: ready.context().operation.operation_id,
        lease_id: ready.context().lease_id,
    };
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&partial)
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(&value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    // Publish a complete, already-flushed file without replacing a prior run.
    std::fs::hard_link(&partial, &target).map_err(|e| e.to_string())?;
    std::fs::remove_file(partial).map_err(|e| e.to_string())
}
pub(super) fn wait(
    root: &Path,
    name: &str,
    context: &LeaseContext,
    child: &impl AsRawHandle,
    deadline: Instant,
) -> Result<OwnedHandle> {
    let target = path(root, name, context);
    let agent_pid = unsafe { GetProcessId(child.as_raw_handle()) };
    if agent_pid == 0 || agent_pid == std::process::id() {
        return Err("runtime fixture did not retain a distinct agent process".into());
    }
    loop {
        match unsafe { WaitForSingleObject(child.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => {}
            WAIT_OBJECT_0 => return Err("agent exited before parent observed Ready".into()),
            _ => return Err(error("observe runtime agent before Ready")),
        }
        match std::fs::File::open(&target) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(4097)
                    .read_to_end(&mut bytes)
                    .map_err(|e| e.to_string())?;
                if bytes.len() > 4096 {
                    return Err("runtime Ready metadata exceeded bound".into());
                }
                let ready: Ready = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                if ready.agent_pid != agent_pid
                    || ready.engine_pid == 0
                    || ready.engine_pid == agent_pid
                    || ready.engine_pid == std::process::id()
                    || ready.operation_id != context.operation.operation_id
                    || ready.lease_id != context.lease_id
                {
                    return Err(
                        "runtime Ready metadata did not match retained child/operation".into(),
                    );
                }
                let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, ready.engine_pid) };
                if process.is_null() {
                    return Err(error("retain cross-process engine"));
                }
                return Ok(unsafe { OwnedHandle::from_raw_handle(process) });
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(format!("runtime Ready metadata unavailable: {e}")),
        }
    }
}

use super::*;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

enum Validation {
    Wire(authority_wire::Validation),
    Runtime(user_agent::Validation),
}
impl Validation {
    fn new(runtime: bool) -> Self {
        if runtime {
            Self::Runtime(user_agent::Validation::new())
        } else {
            Self::Wire(authority_wire::Validation::new())
        }
    }
    fn handle(
        &mut self,
        connection: &mut cfw_windows_engine::LocalServiceConnection,
        request: cfw_windows_engine::AuthenticatedServiceRequest,
    ) -> Result<cfw_windows_engine::authority::AuthorizedReply> {
        match self {
            Self::Wire(value) => value.handle(connection, request),
            Self::Runtime(value) => value.handle(connection, request),
        }
    }
    fn finish(&mut self) -> Result<()> {
        match self {
            Self::Wire(value) => value.finish(),
            Self::Runtime(value) => value.finish(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Installation {
    desktop_image: PathBuf,
    desktop_digest: [u8; 32],
    agent_image: PathBuf,
    agent_digest: [u8; 32],
    user_sid: String,
    authentication_id: u64,
    session_id: u32,
    pub(super) runtime: Option<user_agent::EngineInstallation>,
}

pub(super) fn run_desktop_validation(root: &Path, prefix: &str, expected: [u8; 32]) -> Result<()> {
    run_desktop(root, prefix, expected)
}
pub(super) fn run_runtime_desktop_validation(
    root: &Path,
    name: &str,
    expected: [u8; 32],
) -> Result<()> {
    let image = root.join("desktop-fixture.exe");
    let _held = verified(&image, expected)?;
    restricted::run_desktop_runtime(&image, name, expected)
}
fn run_desktop(root: &Path, prefix: &str, expected: [u8; 32]) -> Result<()> {
    let image = root.join("desktop-fixture.exe");
    let _held = verified(&image, expected)?;
    let output_path = root.join(format!("{prefix}-desktop-client-output.txt"));
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .map_err(|e| e.to_string())?;
    let hex: String = expected.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut child = Command::new(image)
        .args(["--desktop-validation", prefix, &hex])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(output.try_clone().map_err(|e| e.to_string())?)
        .stderr(output)
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(90);
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => break Err("desktop fixture exceeded deadline".to_owned()),
            Err(error) => break Err(format!("observe desktop fixture: {error}")),
        }
    };
    let status = match outcome {
        Ok(status) => status,
        Err(original) => {
            let kill = child.kill();
            let wait = cfw_windows_storage::wait_until(&child, Instant::now() + LIMIT);
            return Err(format!("{original}; cleanup kill={kill:?}, wait={wait:?}"));
        }
    };
    let diagnostics = std::fs::read(&output_path).map_err(|e| e.to_string())?;
    if diagnostics.len() > 16384 {
        return Err("desktop fixture diagnostics exceeded bound".into());
    }
    print!("{}", String::from_utf8_lossy(&diagnostics));
    if !status.success() {
        return Err(format!("desktop fixture exited {status}"));
    }
    let report = std::fs::read(root.join(format!("{prefix}-desktop-client.json")))
        .map_err(|e| e.to_string())?;
    if report.len() > 8192 {
        return Err("desktop fixture report exceeded bound".into());
    }
    let report: serde_json::Value = serde_json::from_slice(&report).map_err(|e| e.to_string())?;
    let expected_report = serde_json::json!({"success":true,"role":"desktop","native_identity_bound":true,"live_console_authorized":true});
    if report != expected_report {
        return Err(format!(
            "desktop fixture report did not attest its checks: {report}"
        ));
    }
    Ok(())
}

pub(super) fn desktop_validation(prefix: &str, hex: &str) -> Result<()> {
    let id = prefix
        .strip_prefix("CFW-scm-fixture-")
        .ok_or("invalid desktop fixture prefix")?;
    let parsed = uuid::Uuid::parse_str(id).map_err(|e| e.to_string())?;
    if parsed.to_string() != id
        || hex.len() != 64
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid desktop fixture identity".into());
    }
    let installed = installation()?;
    let actual_hex: String = installed
        .agent_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if hex != actual_hex {
        return Err("desktop fixture source digest mismatch".into());
    }
    let first = Installed::open_existing(format!("{prefix}-a"))?;
    let second = Installed::open_existing(format!("{prefix}-b"))?;
    exercise_services(
        &first,
        &second,
        prefix,
        &installed.agent_image,
        installed.agent_digest,
    )?;
    let root = installed
        .desktop_image
        .parent()
        .ok_or("missing desktop fixture parent")?;
    let mut report = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(format!("{prefix}-desktop-client.json")))
        .map_err(|e| e.to_string())?;
    report
        .write_all(
            serde_json::to_string(
                &serde_json::json!({"success":true,"role":"desktop","native_identity_bound":true,"live_console_authorized":true}),
            )
            .map_err(|e| e.to_string())?
            .as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    report.sync_all().map_err(|e| e.to_string())
}

// Only the disposable fixture reads this test parameter file. Product listener
// construction receives already-verified installation images, never wire paths.
pub(super) fn write_installation(root: &Path, agent: &Path, digest: [u8; 32]) -> Result<()> {
    write_installation_mode(root, agent, digest, None)
}
pub(super) fn write_installation_mode(
    root: &Path,
    agent: &Path,
    digest: [u8; 32],
    runtime: Option<user_agent::EngineInstallation>,
) -> Result<()> {
    let desktop_image = root.join("desktop-fixture.exe");
    std::fs::copy(
        std::env::current_exe().map_err(|e| e.to_string())?,
        &desktop_image,
    )
    .map_err(|e| e.to_string())?;
    let current = NativePeerProcess::open(std::process::id()).map_err(|e| e.to_string())?;
    let installation = Installation {
        desktop_image,
        desktop_digest: digest,
        agent_image: agent.to_owned(),
        agent_digest: digest,
        user_sid: current.identity().user_sid().to_owned(),
        authentication_id: current.identity().authentication_id(),
        session_id: current.identity().session_id(),
        runtime,
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("fixture-installation.json"))
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(&installation).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

pub(super) fn installation() -> Result<Installation> {
    let image = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = image
        .parent()
        .ok_or("missing fixture parent")?
        .join("fixture-installation.json");
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(8193)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 8192 {
        return Err("fixture installation exceeded bound".into());
    }
    let value: Installation = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if value.user_sid.is_empty()
        || value.user_sid.len() > 184
        || value.authentication_id == 0
        || value.authentication_id == u64::MAX
        || value.session_id == u32::MAX
    {
        return Err("invalid fixture installation user identity".into());
    }
    Ok(value)
}

pub(super) fn desktop_image() -> Result<(PathBuf, [u8; 32])> {
    let installed = installation()?;
    Ok((installed.desktop_image, installed.desktop_digest))
}

pub(super) fn service_image() -> Result<(PathBuf, [u8; 32])> {
    let installed = installation()?;
    Ok((installed.agent_image, installed.agent_digest))
}

pub(super) fn require_rejection(
    root: &Path,
    service: &str,
    role: ServiceClientRole,
    kind: &str,
) -> Result<()> {
    let deadline = Instant::now() + LIMIT;
    loop {
        for entry in std::fs::read_dir(root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if !entry
                .file_name()
                .to_string_lossy()
                .ends_with(".rejection.json")
            {
                continue;
            }
            let bytes = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
            if bytes.len() > 4096 {
                return Err("fixture rejection record exceeded bound".into());
            }
            let record: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            if record
                == serde_json::json!({"service":service,"role":role_text(role),"rejection":kind})
            {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "fixture did not observe {kind} for {}",
                role_text(role)
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn serve(name: &str, status_handle: SERVICE_STATUS_HANDLE) -> Result<()> {
    let installed = installation()?;
    let desktop = LocalServiceListener::bind(
        name,
        ServiceClientRole::Desktop,
        verified(&installed.desktop_image, installed.desktop_digest)?,
    )
    .map_err(|e| e.to_string())?;
    let agent = LocalServiceListener::bind(
        name,
        ServiceClientRole::UserAgent,
        verified(&installed.agent_image, installed.agent_digest)?,
    )
    .map_err(|e| e.to_string())?;
    let mut workers = Vec::new();
    // Fixture ownership is established by the first actually admitted desktop,
    // never by the bootstrap JSON. This exercises the policy input; it is not
    // the product's durable authority lease or runtime state machine.
    let lease_owner = Arc::new(Mutex::new(None));
    let authority = Arc::new(Mutex::new(Validation::new(installed.runtime.is_some())));
    for (role, listener) in [
        (ServiceClientRole::Desktop, desktop),
        (ServiceClientRole::UserAgent, agent),
    ] {
        let name = name.to_owned();
        let installed = installed.clone();
        let lease_owner = lease_owner.clone();
        let authority = authority.clone();
        workers.push(thread::spawn(move || {
            let result = serve_role(&name, role, listener, &installed, &lease_owner, &authority);
            if result.is_err() {
                STOP.store(true, Ordering::SeqCst);
            }
            result
        }));
    }
    let running = status(status_handle, SERVICE_RUNNING, 0);
    if running.is_err() {
        STOP.store(true, Ordering::SeqCst);
    }
    while !STOP.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(10));
    }
    let stopping = status(status_handle, SERVICE_STOP_PENDING, 0);
    let mut failures = Vec::new();
    for worker in workers {
        match worker.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(error),
            Err(_) => failures.push("fixture transport worker panicked".into()),
        }
    }
    if let Err(error) = running {
        failures.push(error);
    }
    if let Err(error) = stopping {
        failures.push(error);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn serve_role(
    name: &str,
    role: ServiceClientRole,
    mut listener: LocalServiceListener,
    installed: &Installation,
    lease_owner: &Mutex<Option<NativeUserSession>>,
    authority: &Mutex<Validation>,
) -> Result<()> {
    let serving = serve_connections(name, role, &mut listener, installed, lease_owner, authority);
    let closing = listener.close().map_err(|e| e.to_string());
    match (serving, closing) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => {
            Err(format!("{operation}; listener cleanup failed: {cleanup}"))
        }
    }
}

fn serve_connections(
    name: &str,
    role: ServiceClientRole,
    listener: &mut LocalServiceListener,
    installed: &Installation,
    lease_owner: &Mutex<Option<NativeUserSession>>,
    authority: &Mutex<Validation>,
) -> Result<()> {
    thread::scope(|scope| {
        let mut workers: Vec<thread::ScopedJoinHandle<'_, Result<()>>> = Vec::new();
        let serving = (|| -> Result<()> {
            while !STOP.load(Ordering::SeqCst) {
                let mut index = 0;
                while index < workers.len() {
                    if workers[index].is_finished() {
                        workers
                            .swap_remove(index)
                            .join()
                            .map_err(|_| "fixture connection worker panicked")??;
                    } else {
                        index += 1;
                    }
                }
                let connection = match listener.accept(Instant::now() + Duration::from_millis(100))
                {
                    Ok(connection) => connection,
                    // The same pending accept survives an idle poll. Product
                    // listener slots bound the number of retained connections.
                    Err(ServiceTransportError::Deadline) => continue,
                    Err(error) => return Err(error.to_string()),
                };
                workers.push(scope.spawn(move || {
                    // Move before the first read: each worker owns all reads,
                    // native message admission and replies on this connection.
                    let result =
                        serve_connection(name, role, connection, installed, lease_owner, authority);
                    if result.is_err() {
                        STOP.store(true, Ordering::SeqCst);
                    }
                    result
                }));
            }
            Ok(())
        })();
        let mut failures = Vec::new();
        if let Err(error) = serving {
            STOP.store(true, Ordering::SeqCst);
            failures.push(error);
        }
        for worker in workers {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(error),
                Err(_) => failures.push("fixture connection worker panicked".into()),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    })
}

fn serve_connection(
    name: &str,
    role: ServiceClientRole,
    mut connection: cfw_windows_engine::LocalServiceConnection,
    installed: &Installation,
    lease_owner: &Mutex<Option<NativeUserSession>>,
    authority: &Mutex<Validation>,
) -> Result<()> {
    let mut wire_connection = false;
    let mut job_keeper: Option<cfw_windows_engine::authority::JobKeeperProbe> = None;
    loop {
        if STOP.load(Ordering::SeqCst) {
            return Ok(());
        }
        // The wire fixture keeps its desktop connection while a restricted
        // child exchanges commands. Existing transport timeout cases retain
        // their five-second deadline; typed fixture connections get LIMIT.
        let receive_timeout = if wire_connection {
            LIMIT
        } else {
            Duration::from_secs(5)
        };
        let request = match connection.receive(Instant::now() + receive_timeout) {
            Ok(request) => request,
            Err(error) => {
                if STOP.load(Ordering::SeqCst) {
                    return Ok(());
                }
                let kind = rejection_kind(&error).ok_or_else(|| error.to_string())?;
                record_rejection(name, role, kind)?;
                break;
            }
        };
        if STOP.load(Ordering::SeqCst) {
            return Ok(());
        }
        let identity = request.identity();
        if request.role() != role
            || identity.user_sid() != installed.user_sid
            || identity.authentication_id() != installed.authentication_id
            || identity.session_id() != installed.session_id
        {
            return Err(
                "authenticated fixture request lost native role/user/session binding".into(),
            );
        }
        if request.body().starts_with(b"{") {
            wire_connection = true;
            let mut authority = authority
                .lock()
                .map_err(|_| "native wire lifecycle guard poisoned")?;
            let reply = authority.handle(&mut connection, request)?;
            match reply
                .send(&mut connection, Instant::now() + LIMIT)
                .map_err(|e| e.to_string())?
            {
                None
                | Some(
                    cfw_windows_engine::authority::AuthorityError::Ticket
                    | cfw_windows_engine::authority::AuthorityError::Stale
                    | cfw_windows_engine::authority::AuthorityError::Identity,
                ) => {}
                Some(error) => {
                    return Err(format!(
                        "unexpected wire fixture rejection after publication: {error}"
                    ));
                }
            }
            continue;
        }
        let peer_session = request.identity().user_session().clone();
        let mut owner = lease_owner
            .lock()
            .map_err(|_| "fixture lease guard poisoned")?;
        let system = NativePeerProcess::open(std::process::id()).map_err(|e| e.to_string())?;
        let (lease, requirement) = match (role, request.body()) {
            (ServiceClientRole::UserAgent, b"agent-without-lease") => {
                (None, UserAgentLeaseRequirement::OwnedLease)
            }
            (ServiceClientRole::UserAgent, b"agent-foreign-lease") => (
                Some(system.identity().user_session()),
                UserAgentLeaseRequirement::OwnedLease,
            ),
            (ServiceClientRole::UserAgent, b"agent-observe-without-lease") => {
                (None, UserAgentLeaseRequirement::OwnedLeaseOrNone)
            }
            _ => (owner.as_ref(), UserAgentLeaseRequirement::OwnedLease),
        };
        let admitted = match authorize_service_request(
            &mut connection,
            request,
            lease,
            requirement,
            Instant::now() + LIMIT,
        ) {
            Ok(admitted) => admitted,
            Err(ServiceAuthorizationError::LeaseRequired) => {
                record_rejection(name, role, "lease_required")?;
                break;
            }
            Err(ServiceAuthorizationError::LeaseOwnerMismatch) => {
                record_rejection(name, role, "lease_owner_mismatch")?;
                break;
            }
            Err(error) => {
                let detail = match LiveConsoleSession::observe() {
                    Ok(console) => format!(
                        "peer_session={}, console_session={}, sid_matches={}, logon_matches={}",
                        peer_session.session_id(),
                        console.identity().session_id(),
                        peer_session.user_sid() == console.identity().user_sid(),
                        peer_session.authentication_id() == console.identity().authentication_id()
                    ),
                    Err(observation) => format!("console observation: {observation}"),
                };
                return Err(format!(
                    "native fixture authorization failed: {error}; {detail}"
                ));
            }
        };
        if role == ServiceClientRole::Desktop && owner.is_none() {
            *owner = Some(admitted.owner().clone());
        }
        drop(owner);
        let request = admitted.request();
        if admitted.process().process_id() == 0
            || admitted.process().identity() != request.identity()
        {
            return Err("authorized fixture lost its retained process identity".into());
        }
        if role == ServiceClientRole::UserAgent {
            let reply = match request.body() {
                b"job-keeper-begin" if job_keeper.is_none() => {
                    let probe =
                        cfw_windows_engine::authority::JobKeeperProbe::new(admitted.process())
                            .map_err(|e| e.to_string())?;
                    let value = serde_json::to_vec(&job_keeper::Transfer {
                        handle: probe.handle_value(),
                        root: probe.root().clone(),
                    })
                    .map_err(|e| e.to_string())?;
                    job_keeper = Some(probe);
                    Some(value)
                }
                b"job-keeper-observe" => {
                    job_keeper
                        .as_mut()
                        .ok_or("missing keeper fixture")?
                        .observe_without_creator(admitted.process())
                        .map_err(|e| e.to_string())?;
                    Some(b"retained".to_vec())
                }
                body if body.starts_with(b"job-keeper-verify:") => {
                    let bytes: [u8; 8] = body[b"job-keeper-verify:".len()..]
                        .try_into()
                        .map_err(|_| "invalid keeper verification frame")?;
                    let result = job_keeper
                        .as_ref()
                        .ok_or("missing keeper fixture")?
                        .verify_reference(admitted.process(), u64::from_le_bytes(bytes));
                    Some(match result {
                        Ok(()) => b"verified".to_vec(),
                        Err(cfw_windows_engine::authority::RuntimeJobError::Security) => {
                            b"unrelated".to_vec()
                        }
                        Err(error) => return Err(error.to_string()),
                    })
                }
                b"job-keeper-release" => {
                    job_keeper
                        .as_mut()
                        .ok_or("missing keeper fixture")?
                        .observe_release(admitted.process())
                        .map_err(|e| e.to_string())?;
                    Some(b"released".to_vec())
                }
                _ => None,
            };
            if let Some(reply) = reply {
                connection
                    .reply(request, &reply, Instant::now() + LIMIT)
                    .map_err(|e| e.to_string())?;
                continue;
            }
        }
        if request.body() == b"done" && job_keeper.as_ref().is_some_and(|p| !p.released()) {
            return Err("keeper fixture ended before handle retirement".into());
        }
        if request.body() == b"identity-probe" {
            connection
                .reply(request, b"ready", Instant::now() + LIMIT)
                .map_err(|e| e.to_string())?;
            let root = installed
                .agent_image
                .parent()
                .ok_or("missing fixture root")?;
            let deadline = Instant::now() + LIMIT;
            while !root
                .join("identity-probe.ready")
                .try_exists()
                .map_err(|e| e.to_string())?
            {
                if STOP.load(Ordering::SeqCst) {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err("queued identity fixture did not become ready".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            continue;
        }
        let state_validation =
            if request.body() == b"authority-state" && role == ServiceClientRole::Desktop {
                Some(authority_state::begin(&admitted)?)
            } else {
                None
            };
        let (reply, finished): (&[u8], bool) = match request.body() {
            b"ping" => (b"pong", false),
            b"done" => (b"end!", true),
            b"authority-wire-finish" | b"authority-runtime-finish"
                if role == ServiceClientRole::Desktop =>
            {
                authority
                    .lock()
                    .map_err(|_| "native wire lifecycle guard poisoned")?
                    .finish()?;
                (b"wire-ok", true)
            }
            b"authority-state" if state_validation.is_some() => (b"state-ok", true),
            command @ (b"authority-journal" | b"authority-journal-observe")
                if role == ServiceClientRole::Desktop =>
            {
                authority_journal::exercise(name, command, admitted.owner())?;
                (b"journal-ok", true)
            }
            command @ (b"machine-record-seed" | b"machine-record-observe")
                if role == ServiceClientRole::Desktop =>
            {
                machine_record::exercise(name, command)?;
                (b"record-ok", true)
            }
            b"agent-observe-without-lease" if role == ServiceClientRole::UserAgent => {
                (b"seen", true)
            }
            _ => return Err("unexpected authenticated fixture request".into()),
        };
        if let Err(error) = connection.reply(request, reply, Instant::now() + LIMIT) {
            if STOP.load(Ordering::SeqCst) {
                return Ok(());
            }
            let kind = rejection_kind(&error).ok_or_else(|| error.to_string())?;
            record_rejection(name, role, kind)?;
            break;
        }
        if let Some(validation) = state_validation {
            validation.finish_after_reply(&admitted)?;
        }
        if finished {
            break;
        }
    }
    Ok(())
}

fn rejection_kind(error: &ServiceTransportError) -> Option<&'static str> {
    match error {
        ServiceTransportError::Client(cfw_windows_engine::PeerIdentityError::Executable(
            cfw_windows_engine::Error::ExecutableIdentity,
        )) => Some("executable_mismatch"),
        ServiceTransportError::Client(cfw_windows_engine::PeerIdentityError::IdentityChanged) => {
            Some("message_identity_changed")
        }
        ServiceTransportError::ClientIdentity => Some("client_identity"),
        ServiceTransportError::Client(_) => Some("client_identity"),
        ServiceTransportError::MessageLength => Some("message_length"),
        ServiceTransportError::Deadline => Some("message_deadline"),
        ServiceTransportError::Io(error)
            if matches!(error.raw_os_error(), Some(109 | 232 | 233)) =>
        {
            Some("peer_closed")
        }
        _ => None,
    }
}

fn role_text(role: ServiceClientRole) -> &'static str {
    match role {
        ServiceClientRole::Desktop => "desktop",
        ServiceClientRole::UserAgent => "user-agent",
    }
}

fn record_rejection(service: &str, role: ServiceClientRole, kind: &str) -> Result<()> {
    let image = std::env::current_exe().map_err(|e| e.to_string())?;
    let root = image.parent().ok_or("missing fixture parent")?;
    let name = format!("service-rejection-{}", uuid::Uuid::new_v4());
    let temporary = root.join(format!("{name}.tmp"));
    let final_path = root.join(format!("{name}.rejection.json"));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    let record = serde_json::json!({"service":service,"role":role_text(role),"rejection":kind});
    output
        .write_all(&serde_json::to_vec(&record).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())?;
    drop(output);
    std::fs::rename(temporary, final_path).map_err(|e| e.to_string())
}

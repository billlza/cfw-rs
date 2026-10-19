//! Real engine/WinINet ownership through the native SYSTEM dispatcher. The
//! global cleanup observation remains explicitly injected by this fixture.
use super::*;
use cfw_engine_api::{EngineCommandContext, EngineStartRequest, authority_v1::AuthorityState};
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use cfw_windows_credentials::WindowsCredentialStore;
use cfw_windows_engine::{
    AuthenticatedServiceRequest, LocalServiceConnection, WindowsSystemProxy,
    authority::{
        AuthorizedReply, CleanupEvidence,
        wire::{Command, Rejection, Request, WireError},
    },
    user_agent::{
        ControlError, StopReason, UserAgentError, UserAgentRuntime, UserAgentSession,
        handoff::UserAgentLaunch,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::{Arc, mpsc},
};

mod child;
mod desktop_runtime;
mod lan;
mod progress;
mod start_request;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EngineInstallation {
    path: PathBuf,
    digest: [u8; 32],
    version: String,
}
fn hash(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid runtime fixture digest".into());
    }
    let mut value = [0; 32];
    for (index, byte) in value.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(value)
}
fn write_report(path: &Path, value: &serde_json::Value) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

pub(super) struct Validation {
    scope: Option<authority_wire::Scoped>,
    ready: usize,
    stopped: usize,
    heartbeats: usize,
    reconciled: usize,
    rejected_bindings: usize,
}
impl Validation {
    pub(super) fn new() -> Self {
        Self {
            scope: None,
            ready: 0,
            stopped: 0,
            heartbeats: 0,
            reconciled: 0,
            rejected_bindings: 0,
        }
    }
    pub(super) fn handle(
        &mut self,
        connection: &mut LocalServiceConnection,
        request: AuthenticatedServiceRequest,
    ) -> Result<AuthorizedReply> {
        if self.scope.is_none() {
            self.scope = Some(authority_wire::Scoped::new()?);
        }
        let command = Request::decode(request.body()).map_err(|e| e.to_string())?;
        let controller = self
            .scope
            .as_mut()
            .and_then(|s| s.controller.as_mut())
            .ok_or("missing runtime authority")?;
        if matches!(command.command(), Command::Observe) && self.stopped > self.reconciled {
            let snapshot = controller.snapshot();
            if snapshot.state != AuthorityState::Stopping {
                return Err("runtime did not preserve stopped scope".into());
            }
            let lease = controller
                .cleanup_target()
                .ok_or("missing stopped runtime scope")?
                .lease_id;
            // No claim of production/global cleanup: the service fixture has no
            // TUN/global observer. Actual per-user cleanup comes from the agent.
            controller
                .reconcile_off(CleanupEvidence::for_validation(
                    snapshot.revision.ok_or("unknown runtime revision")?,
                    Some(lease),
                    true,
                ))
                .map_err(|e| e.to_string())?;
            self.reconciled += 1;
        }
        let ready = matches!(command.command(), Command::Ready(_));
        let stopped = matches!(command.command(), Command::Stopped(_));
        let heartbeat = matches!(command.command(), Command::Heartbeat(_));
        let binding = matches!(command.command(), Command::BindUserAgent(_));
        drop(command);
        let reply = controller
            .handle(connection, request, Instant::now() + LIMIT)
            .map_err(|e| e.to_string())?;
        if let Some(error) = reply.rejection() {
            if binding
                && matches!(error, cfw_windows_engine::authority::AuthorityError::Ticket)
                && self.rejected_bindings == 0
                && self.ready == 0
            {
                self.rejected_bindings += 1;
                return Ok(reply);
            }
            return Err(format!("real runtime command rejected: {error}"));
        }
        self.ready += usize::from(ready);
        self.stopped += usize::from(stopped);
        self.heartbeats += usize::from(heartbeat);
        Ok(reply)
    }
    pub(super) fn finish(&mut self) -> Result<()> {
        if self.ready != 2
            || self.stopped != 2
            || self.reconciled != 2
            || self.heartbeats < 2
            || self.rejected_bindings != 1
        {
            return Err(format!(
                "incomplete runtime sequence: ready={}, stopped={}, reconciled={}, heartbeat={}, rejected_bindings={}",
                self.ready, self.stopped, self.reconciled, self.heartbeats, self.rejected_bindings
            ));
        }
        self.scope
            .as_mut()
            .ok_or("missing runtime validation")?
            .cleanup()?;
        write_report(
            &authority_journal::root()?.join("user-agent.wire-validation.json"),
            &serde_json::json!({"ready_reports":self.ready,"stopped_reports":self.stopped,"heartbeats":self.heartbeats,"rejected_bindings":self.rejected_bindings,"global_cleanup_observations_injected":true,"synthetic_runtime_reports":false,"full_service_backend_proven":false}),
        )
    }
}
pub(super) fn client_report() -> serde_json::Value {
    serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"modes":["local_proxy","system_proxy"],"actual_engine_started":true,"actual_http_proxy_traffic":true,"held_process_exit_observed":true,"listeners_released":true,"original_proxy_restored":true,"native_stopped_acknowledged":true,"authority_revocation_stops_system_proxy":true,"system_proxy_with_lan_sharing":true,"lan_trusted_source_passed":true,"lan_untrusted_source_rejected":true,"lan_listener_released":true,"lan_peer_scope":"same_host_private_interface_and_loopback","shared_start_request_validated":true,"invalid_ticket_precedes_vault_access":true,"desktop_runtime_same_process_fixture":false,"desktop_medium_integrity":true,"privileged_console_observer_rejected":true,"product_user_agent_launcher":true,"product_desktop_supervision":true,"machine_lineage_store":true,"recorded_runtime_scope_validated":true,"desktop_invalid_calls_preserve_preparation":true,"retained_agent_exit_observed":true,"explicit_handle_list":true,"distinct_desktop_agent_images":true,"private_inherited_handoff":true,"cancellable_launch_transport":true,"received_frame_acknowledged":true,"handoff_exceeds_pipe_buffer_hint":true,"original_controller_key_authenticated":true,"unauthenticated_controller_rejected":true,"global_cleanup_observations_injected":true,"full_service_backend_proven":false})
}
pub(super) fn run_validation() -> Result<()> {
    for variable in [
        "CFW_NATIVE_SERVICE_MUTATION_TESTS",
        "CFW_NATIVE_PROXY_MUTATION_TESTS",
    ] {
        if std::env::var(variable).as_deref() != Ok("1") {
            return Err(format!(
                "real runtime fixture requires {variable}=1 in a disposable Windows user"
            ));
        }
    }
    let source = std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e| e.to_string())?;
    if source.len() != 40 || !source.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid runtime fixture source".into());
    }
    let receipts = PathBuf::from(
        std::env::var_os("CFW_NATIVE_SERVICE_RECEIPTS")
            .ok_or("missing runtime receipt directory")?,
    );
    if !receipts.is_absolute() || !receipts.is_dir() {
        return Err("invalid runtime receipt directory".into());
    }
    let install = EngineInstallation {
        path: PathBuf::from(
            std::env::var_os("CFW_ENGINE_HOST_PATH").ok_or("missing runtime engine")?,
        ),
        digest: hash(&std::env::var("CFW_ENGINE_HOST_SHA256").map_err(|e| e.to_string())?)?,
        version: std::env::var("CFW_ENGINE_HOST_VERSION").map_err(|e| e.to_string())?,
    };
    let _held = VerifiedExecutable::open(&install.path, install.digest, &install.version)
        .map_err(|e| e.to_string())?;
    let root = tempfile::tempdir().map_err(|e| e.to_string())?;
    let result = (|| {
        let image = root.path().join("service-fixture.exe");
        std::fs::copy(std::env::current_exe().map_err(|e| e.to_string())?, &image)
            .map_err(|e| e.to_string())?;
        let expected = digest(&image)?;
        transport::write_installation_mode(root.path(), &image, expected, Some(install))?;
        let manager = Sc(unsafe {
            OpenSCManagerW(
                null(),
                null(),
                SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
            )
        });
        if manager.0.is_null() {
            return Err(error("open runtime fixture SCM"));
        }
        let name = format!("CFW-scm-fixture-{}-a", uuid::Uuid::new_v4());
        let mut service = Installed::create(&manager, name.clone(), &image)?;
        let test = transport::run_runtime_desktop_validation(root.path(), &name, expected);
        let removal = service.remove();
        match (test, removal) {
            (Ok(()), Ok(())) => {}
            (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
            (Err(test), Err(cleanup)) => return Err(format!("{test}; service cleanup: {cleanup}")),
        }
        drop(service);
        let check =
            Sc(unsafe { OpenServiceW(manager.0, wide(&name).as_ptr(), SERVICE_QUERY_STATUS) });
        if !check.0.is_null()
            || io::Error::last_os_error().raw_os_error()
                != Some(ERROR_SERVICE_DOES_NOT_EXIST as i32)
        {
            return Err("runtime fixture service deletion was not observed".into());
        }
        let wire = std::fs::read(root.path().join("user-agent.wire-validation.json"))
            .map_err(|e| e.to_string())?;
        if wire.len() > 4096 {
            return Err("runtime wire report exceeded bound".into());
        }
        let wire: serde_json::Value = serde_json::from_slice(&wire).map_err(|e| e.to_string())?;
        if wire["ready_reports"] != 2
            || wire["stopped_reports"] != 2
            || wire["heartbeats"].as_u64().is_none_or(|n| n < 2)
        {
            return Err("runtime wire report incomplete".into());
        }
        write_report(
            &receipts.join("user-agent-runtime-receipt.json"),
            &serde_json::json!({"product_source":source,"client":client_report(),"wire":wire,"temporary_service_removed":true,"release_accepted":false}),
        )
    })();
    let diagnostics = collect_fixture_diagnostics(root.path(), &receipts);
    match (result, diagnostics) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(test), Err(diagnostics)) => {
            Err(format!("{test}; diagnostic collection: {diagnostics}"))
        }
    }
}
fn reserve() -> Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())
}

pub(super) fn desktop(name: &str, hex: &str) -> Result<()> {
    desktop_runtime::run(name, hex)
}
pub(super) fn agent(
    name: &str,
    image: &Path,
    digest: [u8; 32],
    case: restricted::ClientCase,
) -> Result<()> {
    child::run(name, image, digest, case)
}
pub(super) fn desktop_report() -> serde_json::Value {
    serde_json::json!({"success":true,"role":"desktop","privileged_console_observer_rejected":true,"medium_integrity":true,"administrator_member":false,"product_user_agent_launcher":true,"product_desktop_supervision":true,"machine_lineage_store":true,"recorded_runtime_scope_validated":true,"desktop_invalid_calls_preserve_preparation":true,"retained_agent_exit_observed":true,"explicit_handle_list":true,"distinct_agent_process":true,"distinct_agent_image":true,"private_inherited_handoff":true,"cancellable_launch_transport":true,"received_frame_acknowledged":true,"handoff_exceeds_pipe_buffer_hint":true,"original_controller_key_authenticated":true,"unauthenticated_controller_rejected":true,"actual_http_proxy_traffic":true,"held_process_exit_observed":true,"listeners_released":true,"original_proxy_restored":true,"lan_trusted_source_passed":true,"lan_untrusted_source_rejected":true,"lan_listener_released":true})
}
pub(super) fn agent_report(mode: ProjectionMode) -> serde_json::Value {
    serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"mode":mode,"inherited_start_request_validated":true,"parent_image_authenticated":true,"actual_engine_started":true,"authority_revocation_stopped_runtime":true,"native_stopped_acknowledged":true,"local_cleanup_observed":true,"original_proxy_restored":true})
}
pub(super) fn rejected_report() -> serde_json::Value {
    serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"inherited_start_request_validated":true,"parent_image_authenticated":true,"invalid_ticket_precedes_vault_access":true,"actual_engine_started":false})
}

fn traffic(proxy: std::net::SocketAddr) -> Result<()> {
    let server = reserve()?;
    server.set_nonblocking(true).map_err(|e| e.to_string())?;
    let destination = server.local_addr().map_err(|e| e.to_string())?;
    thread::scope(|scope| {
        let worker=scope.spawn(move||->Result<()> {
            let deadline=Instant::now()+Duration::from_secs(5);
            let (mut socket,_)=loop {match server.accept(){Ok(value)=>break value,Err(e) if e.kind()==io::ErrorKind::WouldBlock && Instant::now()<deadline=>thread::sleep(Duration::from_millis(5)),Err(e)=>return Err(e.to_string())}};
            socket.set_nonblocking(false).map_err(|e|e.to_string())?;
            socket.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e|e.to_string())?;
            socket.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e|e.to_string())?;
            let mut header=Vec::new();
            while !header.ends_with(b"\r\n\r\n") {let mut byte=[0];socket.read_exact(&mut byte).map_err(|e|e.to_string())?;header.push(byte[0]);if header.len()>8192{return Err("runtime HTTP request exceeded bound".into());}}
            if !header.starts_with(b"GET /agent-lifecycle HTTP/1.1\r\n") {return Err("runtime HTTP request mismatch".into());}
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\ncfw-user-agent").map_err(|e|e.to_string())
        });
        let response = (|| -> Result<()> {
            let mut socket = TcpStream::connect_timeout(&proxy, Duration::from_secs(5))
                .map_err(|e| e.to_string())?;
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            write!(socket,"GET http://{destination}/agent-lifecycle HTTP/1.1\r\nHost: {destination}\r\nConnection: close\r\n\r\n").map_err(|e|e.to_string())?;
            let mut bytes = String::new();
            socket
                .take(65536)
                .read_to_string(&mut bytes)
                .map_err(|e| e.to_string())?;
            if !bytes.starts_with("HTTP/1.1 200") || !bytes.ends_with("cfw-user-agent") {
                return Err("runtime proxy traffic response mismatch".into());
            }
            Ok(())
        })();
        let server = worker.join().map_err(|_| "runtime HTTP server panicked")?;
        match (response, server) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(client), Err(server)) => Err(format!("{client}; server: {server}")),
        }
    })
}

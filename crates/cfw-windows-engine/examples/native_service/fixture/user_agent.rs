//! Real engine/WinINet ownership through the native SYSTEM dispatcher. The
//! LocalProxy and SystemProxy normal stops use their production cleanup paths.
use super::diagnostics::with_diagnostics;
use super::*;
use cfw_engine_api::{EngineCommandContext, EngineStartRequest, authority_v1::AuthorityState};
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use cfw_windows_credentials::WindowsCredentialStore;
use cfw_windows_engine::{
    AuthenticatedServiceRequest, LocalServiceConnection, WindowsSystemProxy,
    authority::{
        AuthorizedReply,
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
mod credentials;
mod desktop_runtime;
mod lan;
mod progress;
pub(super) mod restart;
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
    cleanup_rejections: Vec<&'static str>,
    local_live_stop_rejected: bool,
    process_observations: Vec<serde_json::Value>,
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
            cleanup_rejections: Vec::new(),
            local_live_stop_rejected: false,
            process_observations: Vec::new(),
        }
    }
    pub(super) fn handle(
        &mut self,
        connection: &mut LocalServiceConnection,
        request: AuthenticatedServiceRequest,
    ) -> Result<(AuthorizedReply, bool)> {
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
            let observation = controller
                .observe_runtime_processes()
                .map_err(|e| e.to_string())?;
            if !observation.processes_retired() {
                return Err("runtime processes still alive after held Agent exit".into());
            }
            self.process_observations
                .push(authority_wire::process_report("retired", &observation));
            if controller
                .cleanup_target()
                .ok_or("missing stop context")?
                .operation
                .mode
                == cfw_engine_api::authority_v1::AuthorityMode::LocalProxy
            {
                let completed = controller
                    .reconcile_local_stop()
                    .map_err(|e| e.to_string())?;
                if !self.local_live_stop_rejected || completed.snapshot().state != AuthorityState::Off
                    || completed.snapshot().revision != snapshot.revision.and_then(|v| v.checked_add(1))
                    || controller.recovery_target().is_none_or(|m| m.operation().is_some()
                        || m.transition() != cfw_windows_engine::authority_journal::JournalTransition::GlobalOff)
                { return Err("LocalProxy stop did not commit exact production GlobalOff".into()); }
                write_report(
                    &authority_journal::root()?.join("runtime-stop-local-service.json"),
                    &serde_json::json!({
                        "prior":completed.prior(),"processes":authority_wire::process_report("normal_stop", completed.processes()),
                        "snapshot":completed.snapshot(),"metadata":controller.recovery_target(),
                        "production_cleanup":true,"live_stopped_owner_rejected":true,"lease_released":controller.lease_owner().is_none(),
                    }),
                )?;
                self.reconciled += 1;
            }
        }
        let ready = matches!(command.command(), Command::Ready(_));
        let stopped = matches!(command.command(), Command::Stopped(_));
        let heartbeat = matches!(command.command(), Command::Heartbeat(_));
        let binding = matches!(command.command(), Command::BindUserAgent(_));
        let cleanup = matches!(command.command(), Command::ReconcileProxyCleanup(_));
        let begin_cleanup = matches!(command.command(), Command::BeginProxyCleanup(_));
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
                return Ok((reply, false));
            }
            if begin_cleanup && self.ready == 2 && self.reconciled == 1 {
                if self.stopped == 1
                    && self.cleanup_rejections.is_empty()
                    && matches!(
                        error,
                        cfw_windows_engine::authority::AuthorityError::Recovering
                    )
                {
                    self.cleanup_rejections.push("active_cleanup_rejected");
                    return Ok((reply, true));
                }
                if self.stopped == 2
                    && self.cleanup_rejections.len() == 1
                    && matches!(
                        error,
                        cfw_windows_engine::authority::AuthorityError::Identity
                    )
                {
                    self.cleanup_rejections
                        .push("same_owner_new_connection_rejected");
                    return Ok((reply, false));
                }
            }
            return Err(format!("real runtime command rejected: {error}"));
        }
        if cleanup {
            let observed = reply
                .proxy_recovery_observation()
                .ok_or("missing production stop proof")?;
            let metadata = controller
                .recovery_target()
                .ok_or("missing cleanup metadata")?;
            if self.stopped != 2
                || self.reconciled != 1
                || controller.snapshot().state != AuthorityState::Off
                || metadata.transition()
                    != cfw_windows_engine::authority_journal::JournalTransition::GlobalOff
                || metadata.operation().is_some()
                || controller.lease_owner().is_some()
            {
                return Err("normal SystemProxy stop did not commit production GlobalOff".into());
            }
            write_report(
                &authority_journal::root()?.join("runtime-stop-system-service.json"),
                &serde_json::json!({
                    "context":observed.context(),"processes":authority_wire::process_report("normal_stop", observed.processes()),
                    "metadata":metadata,"snapshot":controller.snapshot(),"production_cleanup":true,"lease_released":true,
                    "rejected":self.cleanup_rejections,
                    "recorded_process_id":observed.recorded_process_id(),"recorded_process_creation_time":observed.recorded_process_creation_time(),
                }),
            )?;
            self.reconciled += 1;
        }
        if stopped {
            let observation = authority_wire::require_live_runtime(controller, 1)?;
            if controller
                .cleanup_target()
                .ok_or("missing acknowledged stop")?
                .operation
                .mode
                == cfw_engine_api::authority_v1::AuthorityMode::LocalProxy
            {
                let before = controller.snapshot();
                if !matches!(
                    controller.reconcile_local_stop(),
                    Err(cfw_windows_engine::authority::AuthorityError::CleanupUnproven)
                ) || controller.snapshot() != before
                {
                    return Err("live LocalProxy owner did not block production cleanup".into());
                }
                self.local_live_stop_rejected = true;
            }
            self.process_observations
                .push(authority_wire::process_report(
                    "stopped_report",
                    &observation,
                ));
        }
        if ready {
            let observation = self
                .scope
                .as_mut()
                .ok_or("missing runtime job scope")?
                .verify_reopen_with_live_runtime(2)?;
            self.process_observations
                .push(authority_wire::process_report(
                    "ready_observed",
                    &observation,
                ));
        }
        self.ready += usize::from(ready);
        self.stopped += usize::from(stopped);
        self.heartbeats += usize::from(heartbeat);
        Ok((reply, false))
    }
    pub(super) fn finish(&mut self) -> Result<()> {
        if self.ready != 2
            || self.stopped != 2
            || self.reconciled != 2
            || self.heartbeats < 2
            || self.rejected_bindings != 1
            || !self.local_live_stop_rejected
            || self.cleanup_rejections
                != [
                    "active_cleanup_rejected",
                    "same_owner_new_connection_rejected",
                ]
            || self.process_observations.len() != 6
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
            &serde_json::json!({"ready_reports":self.ready,"stopped_reports":self.stopped,"heartbeats":self.heartbeats,"rejected_bindings":self.rejected_bindings,"system_runtime_job_observed":true,"job_failure_boundaries_verified":true,"process_observations":self.process_observations,"nested_engine_membership_observed":true,"engine_keeper_survives_agent_reference_release":true,"job_reopened_after_service_handles_closed":true,"live_member_without_job_name_rejected":true,"live_processes_block_reconcile":true,"ordinary_agent_job_rights_denied":true,"global_cleanup_observations_injected":false,"production_system_proxy_stop":true,"production_local_proxy_stop":true,"local_recovery_while_live_rejected":true,"injected_cleanup_modes":[],"synthetic_runtime_reports":false,"full_service_backend_proven":false}),
        )
    }
}
fn credential_report() -> serde_json::Value {
    serde_json::json!({"runtime_credential_bindings_persisted":true,"async_credential_vault_adapter":true,"async_credential_rebind_verified":true,"active_gc_protects_exact_audience":true,"gc_rechecks_state_at_commit":true,"runtime_gc_observation_errors_rejected":true,"protected_vault_missing_rejected":true,"retired_credentials_collected":true})
}
pub(super) fn client_report() -> serde_json::Value {
    let mut report = serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"modes":["local_proxy","system_proxy"],"actual_engine_started":true,"actual_http_proxy_traffic":true,"held_process_exit_observed":true,"listeners_released":true,"durable_runtime_storage":true,"restoration_observed_after_agent_exit":true,"original_proxy_restored":true,"native_stopped_acknowledged":true,"authority_revocation_stops_system_proxy":true,"system_proxy_with_lan_sharing":true,"lan_trusted_source_passed":true,"lan_untrusted_source_rejected":true,"lan_listener_released":true,"lan_peer_scope":"same_host_private_interface_and_loopback","shared_start_request_validated":true,"invalid_ticket_precedes_vault_access":true,"desktop_runtime_same_process_fixture":false,"desktop_medium_integrity":true,"privileged_console_observer_rejected":true,"product_user_agent_launcher":true,"product_desktop_supervision":true,"machine_lineage_store":true,"recorded_runtime_scope_validated":true,"credential_lifecycle":credential_report(),"desktop_invalid_calls_preserve_preparation":true,"retained_agent_exit_observed":true,"explicit_handle_list":true,"distinct_desktop_agent_images":true,"private_inherited_handoff":true,"cancellable_launch_transport":true,"received_frame_acknowledged":true,"handoff_exceeds_pipe_buffer_hint":true,"original_controller_key_authenticated":true,"unauthenticated_controller_rejected":true,"global_cleanup_observations_injected":false,"full_service_backend_proven":false});
    report["production_system_proxy_stop"] = serde_json::json!(true);
    report["production_local_proxy_stop"] = serde_json::json!(true);
    report["injected_cleanup_modes"] = serde_json::json!([]);
    report
}
pub(super) fn run_validation() -> Result<()> {
    run_mode(None)
}
pub(super) fn run_restart_validation(mode: restart::Mode) -> Result<()> {
    run_mode(Some(mode))
}
fn run_mode(restart: Option<restart::Mode>) -> Result<()> {
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
    let receipts = if restart == Some(restart::Mode::Local) {
        let directory = receipts.join("local-restart");
        std::fs::create_dir(&directory).map_err(|e| e.to_string())?;
        directory
    } else {
        receipts
    };
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
    with_diagnostics(root.path(), &receipts, || {
        let image = root.path().join("service-fixture.exe");
        std::fs::copy(std::env::current_exe().map_err(|e| e.to_string())?, &image)
            .map_err(|e| e.to_string())?;
        let expected = digest(&image)?;
        transport::write_installation_runtime(
            root.path(),
            &image,
            expected,
            Some(install),
            restart,
        )?;
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
        let test = if let Some(mode) = restart {
            restart::exercise(&mut service, root.path(), &name, expected, mode)
        } else {
            transport::run_runtime_desktop_validation(root.path(), &name, expected)
        };
        let removal = service.remove();
        match (test, removal) {
            (Ok(()), Ok(())) => {}
            (Err(error), Ok(())) | (Ok(()), Err(error)) => {
                eprintln!("runtime fixture failed before service disposal: {error}");
                return Err(error);
            }
            (Err(test), Err(cleanup)) => {
                let error = format!("{test}; service cleanup: {cleanup}");
                eprintln!("runtime fixture failed before service disposal: {error}");
                return Err(error);
            }
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
        if let Some(mode) = restart {
            return restart::receipt(root.path(), &receipts, &source, mode);
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
    })
}

fn reserve() -> Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())
}

fn observe_persisted_restoration(
    root: &Path,
    context: &cfw_windows_engine::authority::LeaseContext,
    engine: &OwnedHandle,
) -> Result<()> {
    let storage =
        cfw_windows_engine::user_agent::UserRuntimeStorage::open(&root.join("runtime-state"))
            .map_err(|e| e.to_string())?;
    let runtime = &context.operation.root;
    let command = EngineCommandContext {
        installation_id: runtime.installation_id.to_string(),
        config_epoch: runtime.epoch,
        generation: runtime.generation,
    };
    let digest: String = context
        .operation
        .identity_sha256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let observed = storage
        .proxy()
        .observe_restoration(&command, &digest)
        .map_err(|e| e.to_string())?;
    let id = unsafe { GetProcessId(engine.as_raw_handle()) };
    if id == 0 {
        return Err(error("query retired engine identity for restoration"));
    }
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe {
        GetProcessTimes(
            engine.as_raw_handle(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(error("query retired engine creation time for restoration"));
    }
    let created = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if observed.recorded_process_id() != id || observed.recorded_process_creation_time() != created
    {
        return Err("durable proxy restoration refers to a different engine process".into());
    }
    Ok(())
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
    serde_json::json!({"success":true,"role":"desktop","privileged_console_observer_rejected":true,"medium_integrity":true,"administrator_member":false,"product_user_agent_launcher":true,"product_desktop_supervision":true,"machine_lineage_store":true,"recorded_runtime_scope_validated":true,"credential_lifecycle":credential_report(),"desktop_invalid_calls_preserve_preparation":true,"retained_agent_exit_observed":true,"explicit_handle_list":true,"distinct_agent_process":true,"distinct_agent_image":true,"private_inherited_handoff":true,"cancellable_launch_transport":true,"received_frame_acknowledged":true,"handoff_exceeds_pipe_buffer_hint":true,"original_controller_key_authenticated":true,"unauthenticated_controller_rejected":true,"actual_http_proxy_traffic":true,"held_process_exit_observed":true,"listeners_released":true,"durable_runtime_storage":true,"restoration_observed_after_agent_exit":true,"original_proxy_restored":true,"lan_trusted_source_passed":true,"lan_untrusted_source_rejected":true,"lan_listener_released":true})
}
pub(super) fn agent_report(mode: ProjectionMode) -> serde_json::Value {
    serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"mode":mode,"runtime_credentials_resolved_from_shared_vault":true,"inherited_start_request_validated":true,"parent_image_authenticated":true,"actual_engine_started":true,"authority_revocation_stopped_runtime":true,"native_stopped_acknowledged":true,"local_cleanup_observed":true,"durable_runtime_storage":true,"durable_proxy_restoration_record":(mode == ProjectionMode::SystemProxy),"original_proxy_restored":true})
}
pub(super) fn rejected_report() -> serde_json::Value {
    serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"inherited_start_request_validated":true,"parent_image_authenticated":true,"invalid_ticket_precedes_vault_access":true,"actual_engine_started":false})
}

pub(super) fn traffic(proxy: std::net::SocketAddr) -> Result<()> {
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

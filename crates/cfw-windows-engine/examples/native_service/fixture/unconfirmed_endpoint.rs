//! A Tunnel lease that ends after SYSTEM offered its packet endpoint and
//! before the UserAgent confirmed it. The real Authority runs in a disposable
//! SYSTEM service beside the installed product, whose Wintun it loads. A
//! fixture UserAgent binds, opens the tunnel until the endpoint is offered
//! and then ends its lease without confirming: by exiting, or by
//! acknowledging a stop first. Nothing here reconciles the record. SYSTEM's
//! own supervision, at the product service's interval, must retire the
//! adapter and the unconfirmed endpoint and reach Off.
use super::*;
use cfw_engine_api::authority_v1::{AuthorityState, RootContext};
use cfw_singbox_config::DirectIpv4HostRoutes;
use cfw_windows_engine::{
    AuthenticatedServiceRequest, LocalServiceConnection, RunMode,
    authority::{
        AuthorityChannel, AuthorizedReply, PrepareRequest, StoppedReport,
        wire::{Command, Request, Response, TunnelOpenRequest},
    },
    runtime_host::InstalledRuntime,
    tunnel::{adapter_guid, interface_luid},
};
use std::{io::Write, sync::Arc};

/// The product service's supervision interval.
const TICK: Duration = Duration::from_millis(100);
/// Retirement removes the adapter, which Windows may take 15 s to drop.
const SETTLE: Duration = Duration::from_secs(30);
/// How long the UserAgent polls for the offer while SYSTEM creates the adapter.
const OFFER: Duration = Duration::from_secs(40);
/// A Desktop's connection is its lease's host connection. It stays idle while
/// the UserAgent waits for the offer and while SYSTEM settles the record, so
/// this service does not expire it earlier.
pub(super) const IDLE: Duration = Duration::from_secs(120);
/// Two cases, each with an adapter, a UserAgent and a bounded settlement.
pub(super) const DESKTOP: Duration = Duration::from_secs(210);
const SETTLE_REQUEST: &[u8] = b"unconfirmed-endpoint-settle:";
const MAX_ERRORS: usize = 6;
const MAX_ERROR_BYTES: usize = 240;

/// How the fixture UserAgent ends its lease once the endpoint is offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ending {
    /// It exits. SYSTEM loses the runtime's connection and its process.
    Lost,
    /// It acknowledges a stop, as a UserAgent does whose start was stopped
    /// before it confirmed the endpoint, and exits.
    Stopped,
}
impl Ending {
    const ALL: [Self; 2] = [Self::Lost, Self::Stopped];
    fn label(self) -> &'static str {
        match self {
            Self::Lost => "lost",
            Self::Stopped => "stopped",
        }
    }
    /// The settlement request of one ending, if `body` is one.
    pub(super) fn settlement(body: &[u8]) -> Option<Self> {
        let label = body.strip_prefix(SETTLE_REQUEST)?;
        Self::ALL
            .into_iter()
            .find(|ending| ending.label().as_bytes() == label)
    }
}

/// The SYSTEM side: one real Authority per case, so a record that cannot
/// reach Off leaves the next case its own fresh installation.
pub(super) struct Validation {
    scoped: Option<authority_wire::Scoped>,
    open_requests: u32,
    confirmations: u32,
    stop_acknowledged: bool,
    settled: Vec<Ending>,
    complete: bool,
}
impl Validation {
    pub(super) fn new() -> Self {
        Self {
            scoped: None,
            open_requests: 0,
            confirmations: 0,
            stop_acknowledged: false,
            settled: Vec::new(),
            complete: false,
        }
    }

    pub(super) fn handle(
        &mut self,
        connection: &mut LocalServiceConnection,
        request: AuthenticatedServiceRequest,
    ) -> Result<AuthorizedReply> {
        if self.complete {
            return Err("unconfirmed endpoint fixture already completed".into());
        }
        if self.scoped.is_none() {
            // Fails here, before any lease, when the product is not installed.
            InstalledRuntime::open()
                .and_then(|installation| installation.wintun())
                .map_err(|e| format!("installed Wintun for the endpoint fixture: {e}"))?;
            self.scoped = Some(authority_wire::Scoped::new()?);
        }
        let command = Request::decode(request.body()).map_err(|e| e.to_string())?;
        let (open, confirmation, stopped) = (
            matches!(command.command(), Command::OpenTunnel(_)),
            matches!(command.command(), Command::ConfirmTunnelEndpoint(_)),
            matches!(command.command(), Command::Stopped(_)),
        );
        drop(command);
        let controller = self
            .scoped
            .as_mut()
            .and_then(|scoped| scoped.controller.as_mut())
            .ok_or("missing endpoint fixture controller")?;
        let reply = controller
            .handle(connection, request, Instant::now() + LIMIT)
            .map_err(|e| e.to_string())?;
        if let Some(error) = reply.rejection() {
            return Err(format!("endpoint fixture command was rejected: {error}"));
        }
        self.open_requests += u32::from(open);
        self.confirmations += u32::from(confirmation);
        self.stop_acknowledged |= stopped;
        Ok(reply)
    }

    /// Run SYSTEM's own supervision, as the product service does on every
    /// tick, until the record is Off or `SETTLE` has passed. The outcome is
    /// this case's receipt and the reply. A record that is not Off is
    /// reported as it is, never repaired here.
    pub(super) fn settle(&mut self, ending: Ending) -> Result<Vec<u8>> {
        if self.complete || self.settled.len() >= Ending::ALL.len() {
            return Err("unexpected endpoint fixture settlement".into());
        }
        let mut scoped = self
            .scoped
            .take()
            .ok_or("endpoint fixture settled without a lease")?;
        let controller = scoped
            .controller
            .as_mut()
            .ok_or("missing endpoint fixture controller")?;
        let installation = controller
            .recovery_target()
            .ok_or("endpoint fixture has no record")?
            .root()
            .installation_id;
        let started = Instant::now();
        let mut ticks = 0_u32;
        let mut errors = Vec::new();
        // From the state the UserAgent left, through every one supervision made.
        let mut states = vec![controller.snapshot().state];
        let snapshot = loop {
            ticks += 1;
            if let Err(error) = controller.supervise_for_validation() {
                let mut text = error.to_string();
                if text.len() > MAX_ERROR_BYTES {
                    let mut end = MAX_ERROR_BYTES;
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    text.truncate(end);
                }
                // As the product service records a supervision failure: once,
                // until its text changes.
                if errors.last() != Some(&text) && errors.len() < MAX_ERRORS {
                    errors.push(text);
                }
            }
            let snapshot = controller.snapshot();
            if states.last() != Some(&snapshot.state) {
                states.push(snapshot.state);
            }
            if snapshot.state == AuthorityState::Off || started.elapsed() >= SETTLE {
                break snapshot;
            }
            thread::sleep(TICK);
        };
        let elapsed = started.elapsed();
        let adapter = interface_luid(adapter_guid(installation)).map_err(|e| e.to_string())?;
        let record = controller
            .recovery_target()
            .ok_or("endpoint fixture lost its record")?;
        let report = serde_json::json!({
            "document":"cfw-unconfirmed-endpoint-v1","source":transport::installation()?.source,
            "ending":ending.label(),"state":snapshot.state,"revision":snapshot.revision,
            "transition":record.transition(),"operation_recorded":record.operation().is_some(),
            "lease_released":controller.lease_owner().is_none(),
            "open_tunnel_requests":self.open_requests,"endpoint_confirmations":self.confirmations,
            "stop_acknowledged":self.stop_acknowledged,
            "states":states,"supervision_ticks":ticks,"supervision_errors":errors,
            "elapsed_millis":u64::try_from(elapsed.as_millis()).map_err(|e| e.to_string())?,
            "adapter_present":adapter.is_some(),
        });
        let bytes = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(authority_journal::root()?.join(format!(
                "unconfirmed-endpoint-{}.wire-validation.json",
                ending.label()
            )))
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        if snapshot.state == AuthorityState::Off {
            self.settled.push(ending);
        }
        self.open_requests = 0;
        self.confirmations = 0;
        self.stop_acknowledged = false;
        // The next case enrolls its own installation, whatever this one left.
        scoped.cleanup()?;
        Ok(bytes)
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        if self.complete {
            return Err("duplicate endpoint fixture finish".into());
        }
        if self.scoped.is_some() || self.settled != Ending::ALL {
            return Err("endpoint fixture cases did not each settle to Off".into());
        }
        self.complete = true;
        Ok(())
    }
}

fn request(channel: &mut AuthorityChannel, command: Command) -> Result<Response> {
    channel
        .request(
            Request::new(command).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())
}

/// The record's revision while it is Off.
fn off_revision(channel: &mut AuthorityChannel) -> Result<u64> {
    match request(channel, Command::Observe)? {
        Response::Observed(snapshot) if snapshot.state == AuthorityState::Off => snapshot
            .revision
            .ok_or_else(|| "endpoint fixture record has no known revision".into()),
        Response::Observed(snapshot) => Err(format!(
            "endpoint fixture record is {:?}, not Off",
            snapshot.state
        )),
        _ => Err("endpoint fixture observation was not answered".into()),
    }
}

/// One case from the Desktop: prepare a Tunnel lease, hand it to a UserAgent
/// that takes the endpoint offer and ends, then have SYSTEM settle the record.
fn exercise(
    name: &str,
    image: &Path,
    digest: [u8; 32],
    service_image: &Arc<VerifiedExecutable>,
    ending: Ending,
) -> Result<()> {
    let mut channel =
        AuthorityChannel::connect(name, ServiceClientRole::Desktop, Arc::clone(service_image))
            .map_err(|e| e.to_string())?;
    off_revision(&mut channel)?;
    let Response::Lineage(lineage) = request(&mut channel, Command::LoadLineage)? else {
        return Err("endpoint fixture lineage was not answered".into());
    };
    let Response::Lineage(allocated) = request(&mut channel, Command::ReserveGeneration(lineage))?
    else {
        return Err("endpoint fixture generation was not reserved".into());
    };
    let expected_revision = off_revision(&mut channel)?;
    let Response::Prepared(prepared) = request(
        &mut channel,
        Command::Prepare(PrepareRequest {
            root: RootContext {
                installation_id: allocated.installation_id,
                epoch: allocated.config_epoch,
                generation: allocated.generation,
            },
            operation_id: uuid::Uuid::new_v4(),
            mode: RunMode::Tunnel,
            config_sha256: [3; 32],
            identity_sha256: [4; 32],
            expected_revision,
        }),
    )?
    else {
        return Err("endpoint fixture lease was not prepared".into());
    };
    let handoff = Request::new(Command::BindUserAgent(prepared.into_bind()))
        .map_err(|e| e.to_string())?
        .encode()
        .map_err(|e| e.to_string())?;
    restricted::run_unconfirmed_endpoint(image, name, digest, ending, handoff.as_bytes())?;
    drop(handoff);
    // On its own connection: this Desktop's lease connection stays open, as a
    // Desktop's does whose UserAgent failed.
    let mut settlement =
        ServiceChannel::connect(name, ServiceClientRole::Desktop, Arc::clone(service_image))
            .map_err(|e| e.to_string())?;
    let mut body = SETTLE_REQUEST.to_vec();
    body.extend_from_slice(ending.label().as_bytes());
    let reply = settlement
        .request(&body, Instant::now() + SETTLE + LIMIT)
        .map_err(|e| e.to_string())?;
    let outcome: serde_json::Value =
        serde_json::from_slice(reply.as_bytes()).map_err(|e| e.to_string())?;
    if outcome["state"] != "off"
        || outcome["adapter_present"] != false
        || outcome["lease_released"] != true
        || outcome["operation_recorded"] != false
        || outcome["endpoint_confirmations"] != 0
        || outcome["stop_acknowledged"] != (ending == Ending::Stopped)
    {
        return Err(format!(
            "SYSTEM did not bring a lease that ended with an unconfirmed endpoint to Off: {outcome}"
        ));
    }
    Ok(())
}

/// What the Desktop attests once both cases reached Off.
pub(super) fn desktop_report() -> serde_json::Value {
    serde_json::json!({"success":true,"role":"desktop","lost_lease_reached_off":true,"acknowledged_stop_reached_off":true,"endpoint_never_confirmed":true})
}

/// The Desktop of both cases, started by `run` from the admitted image.
pub(super) fn desktop(name: &str, hex: &str) -> Result<()> {
    if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
        return Err("endpoint fixture Desktop requires disposable CI opt-in".into());
    }
    let id = name
        .strip_prefix("CFW-scm-fixture-")
        .and_then(|s| s.strip_suffix("-a"))
        .ok_or("invalid endpoint fixture service")?;
    let parsed = uuid::Uuid::parse_str(id).map_err(|e| e.to_string())?;
    if parsed.is_nil() || parsed.to_string() != id {
        return Err("noncanonical endpoint fixture service".into());
    }
    let (image, expected) = transport::service_image()?;
    let expected_hex: String = expected.iter().map(|byte| format!("{byte:02x}")).collect();
    if hex != expected_hex {
        return Err("endpoint fixture source mismatch".into());
    }
    let service_image = Arc::new(verified(&image, expected)?);
    // Both cases run even when the first fails: each has its own Authority,
    // and each leaves its own receipt.
    let failures: Vec<_> = Ending::ALL
        .into_iter()
        .filter_map(|ending| {
            exercise(name, &image, expected, &service_image, ending)
                .err()
                .map(|error| format!("{}: {error}", ending.label()))
        })
        .collect();
    if !failures.is_empty() {
        return Err(failures.join("; "));
    }
    let mut finish = ServiceChannel::connect(name, ServiceClientRole::Desktop, service_image)
        .map_err(|e| e.to_string())?;
    if finish
        .request(b"authority-wire-finish", Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"wire-ok"
    {
        return Err("endpoint fixture completion mismatch".into());
    }
    let root = std::env::current_exe().map_err(|e| e.to_string())?;
    let root = root.parent().ok_or("missing admitted Desktop directory")?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(format!("{name}-desktop-client.json")))
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(&desktop_report()).map_err(|e| e.to_string())?)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}

/// The UserAgent of one case: bind, open the tunnel until SYSTEM offers its
/// endpoint, and end the lease without ever confirming that endpoint.
pub(super) fn agent(name: &str, image: &Path, digest: [u8; 32], ending: Ending) -> Result<()> {
    let bind = agent_handoff::read()?;
    let Command::BindUserAgent(material) = bind.command() else {
        return Err("endpoint agent handoff was not a bind request".into());
    };
    let context = material.context.clone();
    let mut channel =
        AuthorityChannel::connect(name, ServiceClientRole::UserAgent, verified(image, digest)?)
            .map_err(|e| e.to_string())?;
    // The channel confirms the keeper of the runtime Job before it answers.
    let Response::Bound(bound) = channel
        .request(bind, Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
    else {
        return Err("endpoint agent did not receive a runtime binding".into());
    };
    if bound.context() != &context {
        return Err("endpoint agent was bound to another lease".into());
    }
    // The link the installed Tunnel suites configure. It is never routed:
    // SYSTEM routes an adapter only once its endpoint is confirmed.
    let open = TunnelOpenRequest {
        context: context.clone(),
        ipv6_enabled: false,
        bypass_private_networks: true,
        direct_ipv4_hosts: DirectIpv4HostRoutes::none(),
        mtu: 1500,
    };
    let deadline = Instant::now() + OFFER;
    loop {
        match request(&mut channel, Command::OpenTunnel(open.clone()))? {
            Response::TunnelOffered(_) => break,
            Response::TunnelPending if Instant::now() < deadline => thread::sleep(TICK),
            Response::TunnelPending => {
                return Err("SYSTEM did not offer its endpoint in time".into());
            }
            _ => return Err("endpoint agent's tunnel request was not answered".into()),
        }
    }
    // SYSTEM now holds the handoff of an endpoint whose client end is in this
    // process. This process never confirms it.
    if ending == Ending::Stopped {
        match request(
            &mut channel,
            Command::Stopped(StoppedReport {
                context,
                engine_stopped: true,
                transport_closed: true,
                os_restored: true,
                observed_millis: 1,
            }),
        )? {
            Response::Status(snapshot) if snapshot.state == AuthorityState::Stopping => {}
            _ => return Err("endpoint agent's stop was not acknowledged".into()),
        }
    }
    drop((bound, channel));
    Ok(())
}

/// Start the disposable service and its Desktop. The installed product must
/// be present: SYSTEM's tunnel host loads its Wintun.
pub(super) fn run() -> Result<()> {
    if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
        return Err("endpoint fixture requires disposable CI opt-in".into());
    }
    let receipts = PathBuf::from(
        std::env::var_os("CFW_NATIVE_SERVICE_RECEIPTS").ok_or("missing endpoint receipts")?,
    );
    if !receipts.is_absolute() || !receipts.is_dir() {
        return Err("invalid endpoint receipts".into());
    }
    let root = tempfile::tempdir().map_err(|e| e.to_string())?;
    diagnostics::with_diagnostics(root.path(), &receipts, || {
        let image = root.path().join("service-fixture.exe");
        std::fs::copy(std::env::current_exe().map_err(|e| e.to_string())?, &image)
            .map_err(|e| e.to_string())?;
        let expected = digest(&image)?;
        transport::write_installation_unconfirmed_endpoint(root.path(), &image, expected)?;
        let manager = Sc(unsafe {
            OpenSCManagerW(
                null(),
                null(),
                SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
            )
        });
        if manager.0.is_null() {
            return Err(error("open endpoint fixture SCM"));
        }
        let name = format!("CFW-scm-fixture-{}-a", uuid::Uuid::new_v4());
        let mut service = Installed::create(&manager, name.clone(), &image)?;
        let result = transport::run_unconfirmed_endpoint_desktop(root.path(), &name, expected);
        let cleanup = service.remove();
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
            (Err(e), Err(c)) => Err(format!("{e}; fixture service removal: {c}")),
        }
    })
}

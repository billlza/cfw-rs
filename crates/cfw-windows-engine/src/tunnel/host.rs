//! SYSTEM's tunnel network for one Tunnel lease, owned on one dedicated thread
//! from adapter creation until its removal is proven. The thread creates the
//! adapter under the installation's fixed interface GUID, configures its link,
//! runs the packet pump once the UserAgent confirms its endpoint, routes the
//! adapter when the engine reports Ready, and on retirement stops the pump,
//! ends the session and removes the adapter. Nothing here grants a lease or
//! reports Off: the Authority composes cleanup evidence from the outcome.
//!
//! The interface GUID is derived from the installation, as wireguard-windows
//! and sing-tun derive theirs from a tunnel name, so Windows keeps one network
//! profile and a stale adapter is found by identity instead of by name.
use super::{
    DeliveryPolicy, Error, Library, NetworkReceipt, PacketPump, PacketServer, PumpReport, Result,
    TunnelNetworkPlan, WintunDevice, adapter_absent, adapter_guid, network,
    wait_until_adapter_absent,
};
use serde::Serialize;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// How long a closed adapter may take to leave the interface table.
const REMOVAL: Duration = Duration::from_secs(15);
/// The host thread observes pump termination at least this often.
const COMMAND_POLL: Duration = Duration::from_millis(50);

enum Command {
    Pump {
        server: PacketServer,
        policy: DeliveryPolicy,
        reply: SyncSender<Result<()>>,
    },
    Route {
        reply: SyncSender<Result<NetworkReceipt>>,
    },
    ExpectPeerClose,
    Retire {
        deadline: Instant,
    },
}

/// Packet counters of a retired pump, for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PumpSummary {
    pub to_engine_packets: u64,
    pub to_engine_bytes: u64,
    pub to_system_packets: u64,
    pub to_system_bytes: u64,
    pub ring_full_waits: u64,
    pub refused_packets: u64,
}
impl From<&PumpReport> for PumpSummary {
    fn from(report: &PumpReport) -> Self {
        let refused = &report.refused;
        Self {
            to_engine_packets: report.to_engine.packets,
            to_engine_bytes: report.to_engine.bytes,
            to_system_packets: report.to_system.packets,
            to_system_bytes: report.to_system.bytes,
            ring_full_waits: report.ring_full_waits,
            refused_packets: refused.destination.packets
                + refused.source.packets
                + refused.protocol.packets,
        }
    }
}

/// What the host thread observed by the time it exited. Its exit closed the
/// session, the endpoint's server end and the adapter handle; `adapter_absent`
/// is the independent observation that the adapter has left Windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TunnelRetirement {
    pub adapter: uuid::Uuid,
    pub adapter_created: bool,
    pub link: Option<NetworkReceipt>,
    pub routed: Option<NetworkReceipt>,
    pub pump_started: bool,
    pub pump: Option<PumpSummary>,
    /// Set when retirement observed the engine closing its endpoint after
    /// `expect_peer_close`, i.e. a clean engine-first stop.
    pub engine_closed_endpoint: Option<i32>,
    /// The first failure the thread recorded, if any. Diagnostic text only.
    pub failure: Option<String>,
    /// The device instance a recovery host removed, if one was present.
    pub removed_device_instance: Option<String>,
    pub adapter_absent: bool,
}
impl TunnelRetirement {
    fn new(adapter: uuid::Uuid) -> Self {
        Self {
            adapter,
            adapter_created: false,
            link: None,
            routed: None,
            pump_started: false,
            pump: None,
            engine_closed_endpoint: None,
            failure: None,
            removed_device_instance: None,
            adapter_absent: false,
        }
    }
    fn record(&mut self, error: &Error) {
        if self.failure.is_none() {
            self.failure = Some(error.to_string());
        }
    }
}

/// The Authority's handle on one host thread. Commands are bounded waits on
/// the Authority's guard; retirement itself is asynchronous and observed with
/// `retirement`. Dropping the handle makes the thread retire on its own.
pub struct TunnelHost {
    adapter: uuid::Uuid,
    /// None for a recovery host, which serves no run.
    plan: Option<TunnelNetworkPlan>,
    commands: SyncSender<Command>,
    link: Option<Receiver<Result<NetworkReceipt>>>,
    pump_ended: Arc<AtomicBool>,
    worker: Option<JoinHandle<TunnelRetirement>>,
    outcome: Option<TunnelRetirement>,
    peer_close_expected: bool,
    retiring: bool,
}

impl TunnelHost {
    /// Start a host that creates and configures the installation's adapter.
    /// `poll_link` reports the result; the host must be retired either way.
    pub fn start(installation: uuid::Uuid, plan: TunnelNetworkPlan) -> Result<Self> {
        let adapter = adapter_guid(installation);
        Self::spawn(adapter, Operation::Serve(plan))
    }

    /// Start a host that only removes an adapter an earlier SYSTEM process
    /// left behind and proves its absence. No adapter is created.
    pub fn recover(installation: uuid::Uuid) -> Result<Self> {
        let adapter = adapter_guid(installation);
        let mut host = Self::spawn(adapter, Operation::RemoveStale)?;
        host.link = None;
        host.retiring = true;
        Ok(host)
    }

    fn spawn(adapter: uuid::Uuid, operation: Operation) -> Result<Self> {
        let (commands, receiver) = mpsc::sync_channel(4);
        let (link_sender, link) = mpsc::sync_channel(1);
        let pump_ended = Arc::new(AtomicBool::new(false));
        let plan = match &operation {
            Operation::Serve(plan) => Some(plan.clone()),
            Operation::RemoveStale => None,
        };
        let worker_ended = Arc::clone(&pump_ended);
        let worker = thread::Builder::new()
            .name("cfw-tunnel-host".into())
            .spawn(move || run(adapter, operation, link_sender, &receiver, &worker_ended))
            .map_err(|source| Error::Native {
                operation: "start the tunnel host thread",
                source,
            })?;
        Ok(Self {
            adapter,
            plan,
            commands,
            link: Some(link),
            pump_ended,
            worker: Some(worker),
            outcome: None,
            peer_close_expected: false,
            retiring: false,
        })
    }

    pub fn adapter(&self) -> uuid::Uuid {
        self.adapter
    }

    /// The plan this host serves; a recovery host has none.
    pub fn plan(&self) -> Result<&TunnelNetworkPlan> {
        self.plan
            .as_ref()
            .ok_or_else(|| "a recovery tunnel host serves no plan".into())
    }

    /// The configured link, or why it could not be configured, once the
    /// thread has answered; None while it is still working. One answer only.
    pub fn poll_link(&mut self) -> Option<Result<NetworkReceipt>> {
        let link = self.link.as_ref()?;
        let answer = match link.try_recv() {
            Ok(answer) => answer,
            Err(mpsc::TryRecvError::Empty) => return None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Err("tunnel host exited before configuring its link".into())
            }
        };
        self.link = None;
        Some(answer)
    }

    /// Hand the confirmed endpoint to the pump.
    pub fn start_pump(
        &mut self,
        server: PacketServer,
        policy: DeliveryPolicy,
        deadline: Instant,
    ) -> Result<()> {
        if self.retiring {
            return Err("tunnel host is retiring".into());
        }
        let (reply, answer) = mpsc::sync_channel(1);
        self.send(Command::Pump {
            server,
            policy,
            reply,
        })?;
        receive(&answer, deadline, "tunnel packet pump start")
    }

    /// Route the adapter once the engine serves its endpoint.
    pub fn route(&mut self, deadline: Instant) -> Result<NetworkReceipt> {
        if self.retiring {
            return Err("tunnel host is retiring".into());
        }
        let (reply, answer) = mpsc::sync_channel(1);
        self.send(Command::Route { reply })?;
        receive(&answer, deadline, "tunnel routes")
    }

    /// Either pump worker has exited; the run can no longer carry packets.
    pub fn pump_ended(&self) -> bool {
        self.pump_ended.load(Ordering::Acquire)
    }

    /// Arm before the engine is asked to stop. Idempotent.
    pub fn expect_peer_close(&mut self) -> Result<()> {
        if self.peer_close_expected || self.retiring {
            return Ok(());
        }
        self.send(Command::ExpectPeerClose)?;
        self.peer_close_expected = true;
        Ok(())
    }

    /// Ask the thread to retire by `deadline`. Idempotent; observe the result
    /// with `retirement`.
    pub fn begin_retirement(&mut self, deadline: Instant) -> Result<()> {
        if self.retiring {
            return Ok(());
        }
        self.send(Command::Retire { deadline })?;
        self.retiring = true;
        Ok(())
    }

    pub fn retiring(&self) -> bool {
        self.retiring
    }

    /// The thread's outcome once it has exited, joining it on first sight.
    pub fn retirement(&mut self) -> Result<Option<&TunnelRetirement>> {
        if self.outcome.is_none() && self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            let worker = self.worker.take().ok_or("tunnel host worker was lost")?;
            self.outcome = Some(worker.join().map_err(|_| "tunnel host thread panicked")?);
        }
        Ok(self.outcome.as_ref())
    }

    fn send(&self, command: Command) -> Result<()> {
        self.commands.try_send(command).map_err(|error| {
            Error::from(match error {
                TrySendError::Full(_) => "tunnel host command queue is full",
                TrySendError::Disconnected(_) => "tunnel host thread has exited",
            })
        })
    }
}

fn receive<T>(receiver: &Receiver<Result<T>>, deadline: Instant, operation: &str) -> Result<T> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| Error::from(format!("{operation} deadline expired")))?;
    match receiver.recv_timeout(left) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            Err(format!("{operation} did not complete before its deadline").into())
        }
        Err(RecvTimeoutError::Disconnected) => {
            Err(format!("tunnel host exited before {operation}").into())
        }
    }
}

enum Operation {
    Serve(TunnelNetworkPlan),
    RemoveStale,
}

fn run(
    adapter: uuid::Uuid,
    operation: Operation,
    link: SyncSender<Result<NetworkReceipt>>,
    commands: &Receiver<Command>,
    pump_ended: &AtomicBool,
) -> TunnelRetirement {
    let mut retirement = TunnelRetirement::new(adapter);
    let mut link = Some(link);
    let operated = match &operation {
        Operation::Serve(plan) => serve(
            adapter,
            plan,
            &mut link,
            commands,
            pump_ended,
            &mut retirement,
        ),
        Operation::RemoveStale => remove_stale(adapter, &mut retirement),
    };
    if let Err(error) = operated {
        retirement.record(&error);
        if let Some(link) = link.take() {
            // The Authority may already have dropped this host; retirement
            // below still runs and is observed through the thread's outcome.
            if let Err(undelivered) = link.try_send(Err(error)) {
                drop(undelivered);
            }
        }
    }
    // Every native object of this run was dropped above, so the adapter's
    // handle is closed; Windows now removes the device asynchronously.
    match wait_until_adapter_absent(adapter, Instant::now() + REMOVAL) {
        Ok(absent) => retirement.adapter_absent = absent,
        Err(error) => retirement.record(&error),
    }
    retirement
}

fn remove_stale(adapter: uuid::Uuid, retirement: &mut TunnelRetirement) -> Result<()> {
    if let Some(device) = WintunDevice::find(adapter)? {
        if device.interface_guid() != adapter {
            return Err("stale Wintun device names another interface GUID".into());
        }
        retirement.removed_device_instance = Some(device.instance_id().to_owned());
        device.remove()?;
    }
    Ok(())
}

fn serve(
    guid: uuid::Uuid,
    plan: &TunnelNetworkPlan,
    link: &mut Option<SyncSender<Result<NetworkReceipt>>>,
    commands: &Receiver<Command>,
    pump_ended: &AtomicBool,
    retirement: &mut TunnelRetirement,
) -> Result<()> {
    // A present adapter here contradicts the Off this lease started from:
    // fail closed instead of adopting or replacing it.
    if !adapter_absent(guid)? {
        return Err("a tunnel adapter of this installation already exists".into());
    }
    let installation = crate::runtime_host::InstalledRuntime::open()?;
    let library = Library::load(&installation)?;
    let served = (|| {
        let adapter = library.create(guid)?;
        retirement.adapter_created = true;
        let receipt = network::configure_link(&adapter, guid, plan)?;
        retirement.link = Some(receipt.clone());
        let mut session = adapter.session(plan.mtu())?;
        if let Some(link) = link.take()
            && link.try_send(Ok(receipt)).is_err()
        {
            // The Authority dropped this host: retire without serving.
            return Ok(());
        }
        await_pump(
            &adapter,
            &mut session,
            Serving {
                guid,
                plan,
                commands,
                pump_ended,
                retirement,
            },
        )
        // The session, then the adapter, drop here.
    })();
    let closed = library.close();
    match (served, closed) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(Error::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}

/// What the serving thread keeps while the pump runs: the run's identity and
/// plan, its command queue, the shared pump status and the outcome record.
struct Serving<'a> {
    guid: uuid::Uuid,
    plan: &'a TunnelNetworkPlan,
    commands: &'a Receiver<Command>,
    pump_ended: &'a AtomicBool,
    retirement: &'a mut TunnelRetirement,
}

fn await_pump(
    adapter: &super::Adapter<'_>,
    session: &mut super::Session<'_>,
    mut serving: Serving<'_>,
) -> Result<()> {
    let mut peer_close = false;
    loop {
        match serving.commands.recv() {
            Ok(Command::Pump {
                server,
                policy,
                reply,
            }) => {
                return thread::scope(|scope| {
                    let pump = match PacketPump::start(scope, session, server, policy) {
                        Ok(pump) => pump,
                        Err(error) => {
                            serving.retirement.record(&error);
                            answer(reply, Err(error));
                            return Ok(());
                        }
                    };
                    serving.retirement.pump_started = true;
                    answer(reply, Ok(()));
                    if peer_close {
                        pump.control().expect_peer_close();
                    }
                    pumped(adapter, pump, peer_close, &mut serving);
                    Ok(())
                });
            }
            Ok(Command::Route { reply }) => {
                answer(reply, Err("tunnel routes require a running pump".into()));
            }
            Ok(Command::ExpectPeerClose) => peer_close = true,
            Ok(Command::Retire { .. }) | Err(_) => return Ok(()),
        }
    }
}

fn pumped(
    adapter: &super::Adapter<'_>,
    pump: PacketPump<'_>,
    mut peer_close: bool,
    serving: &mut Serving<'_>,
) {
    loop {
        match serving.commands.recv_timeout(COMMAND_POLL) {
            Ok(Command::Route { reply }) => {
                let routed = network::route(adapter.luid(), serving.guid, serving.plan);
                match &routed {
                    Ok(receipt) => serving.retirement.routed = Some(receipt.clone()),
                    Err(error) => serving.retirement.record(error),
                }
                answer(reply, routed);
            }
            Ok(Command::ExpectPeerClose) => {
                peer_close = true;
                pump.control().expect_peer_close();
            }
            Ok(Command::Pump { reply, .. }) => {
                // Dropping the second endpoint retires it unused.
                answer(reply, Err("the tunnel packet pump already runs".into()));
            }
            Ok(Command::Retire { deadline }) => {
                retire_pump(pump, peer_close, deadline, serving.retirement);
                return;
            }
            Err(RecvTimeoutError::Timeout) => {
                if pump.control().terminated() {
                    serving.pump_ended.store(true, Ordering::Release);
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                retire_pump(pump, false, Instant::now(), serving.retirement);
                return;
            }
        }
    }
}

fn retire_pump(
    pump: PacketPump<'_>,
    peer_close: bool,
    deadline: Instant,
    retirement: &mut TunnelRetirement,
) {
    if peer_close {
        match pump.finish(deadline) {
            Ok(retired) => {
                retirement.pump = Some(PumpSummary::from(retired.report()));
                retirement.engine_closed_endpoint = Some(retired.peer_close_code());
            }
            Err(error) => retirement.record(&error),
        }
    } else {
        match pump.stop() {
            Ok(report) => retirement.pump = Some(PumpSummary::from(&report)),
            Err(error) => retirement.record(&error),
        }
    }
}

fn answer<T>(reply: SyncSender<Result<T>>, result: Result<T>) {
    // A caller past its deadline no longer waits; its error stands.
    if let Err(undelivered) = reply.try_send(result) {
        drop(undelivered);
    }
}

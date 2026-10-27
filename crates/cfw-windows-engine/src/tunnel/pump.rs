//! One owned Wintun session exchanging complete IP packets with one packet
//! endpoint, on two scoped workers. This data-plane primitive grants no
//! Authority lease and changes no adapter, address, route, DNS, firewall or
//! proxy state. Engine-to-system packets reach the session only when the
//! owner's `DeliveryPolicy` admits them; refused packets are counted by
//! reason and never end the run.
//!
//! Retirement order: the owner calls `expect_peer_close`, stops the engine
//! (which closes its endpoint first, so it can report a clean Stopped), then
//! `finish`. The to-engine worker stops forwarding at once; the reader treats
//! the closed endpoint as the expected observation. Any other worker exit
//! cancels both directions, and the first failure is reported.
use super::{
    Error, PACKET_TRANSFER_BOUND, PumpDirection, Result, Session,
    channel::{PacketReceiver, PacketSender, PacketServer},
    merge_failures, peer_close_code,
    policy::{DeliveryPolicy, Refusal, RefusalReason},
    session::{SessionReceiver, SessionSender},
};
use crate::ServiceTransportError;
use std::{
    any::Any,
    os::windows::io::OwnedHandle,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    thread::{self, Scope, ScopedJoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Upper bound for one blocked session wait or endpoint poll, so a worker
/// observes cancellation promptly. Never a packet deadline.
const WAIT_SLICE: Duration = Duration::from_millis(50);
const RING_RETRY: Duration = Duration::from_millis(1);
const FINISH_POLL: Duration = Duration::from_millis(5);

/// Packets whose transfer completed and was observed. A write that completed
/// natively but reported cancellation or a deadline is not counted, so these
/// are lower bounds and never evidence of a dropped packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectionCounters {
    pub packets: u64,
    pub bytes: u64,
    pub largest_packet: usize,
}

/// Engine packets the delivery policy refused for one reason. They never
/// reached the session, so `to_system` keeps matching what the adapter
/// received. `first` is the earliest refusal for this reason. A report taken
/// while the pump runs may trail by one packet; a retirement report is exact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RefusedClass {
    pub packets: u64,
    pub bytes: u64,
    pub first: Option<Refusal>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RefusedPackets {
    pub destination: RefusedClass,
    pub source: RefusedClass,
    pub protocol: RefusedClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PumpReport {
    pub to_engine: DirectionCounters,
    pub to_system: DirectionCounters,
    /// Bounded retries while the system send ring was full.
    pub ring_full_waits: u64,
    /// Engine packets the delivery policy kept from the system.
    pub refused: RefusedPackets,
}

/// Constructed only by `finish`: both workers joined without a failure, the
/// reader observed the engine close its endpoint after `expect_peer_close`,
/// and the server end was the last reference and is closed. A closed
/// endpoint alone does not prove a clean engine stop; that needs the engine's
/// own Stopped receipt. Not Clone, Debug or serializable.
pub struct PumpRetirement {
    report: PumpReport,
    peer_close_code: i32,
}
impl PumpRetirement {
    pub fn report(&self) -> &PumpReport {
        &self.report
    }
    /// The native code with which the endpoint reported its peer closing.
    pub fn peer_close_code(&self) -> i32 {
        self.peer_close_code
    }
}

#[derive(Default)]
struct Tally {
    packets: AtomicU64,
    bytes: AtomicU64,
    largest: AtomicUsize,
}
impl Tally {
    fn add(&self, length: usize) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(length as u64, Ordering::Relaxed);
        self.largest.fetch_max(length, Ordering::Relaxed);
    }
    fn snapshot(&self) -> DirectionCounters {
        DirectionCounters {
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            largest_packet: self.largest.load(Ordering::Relaxed),
        }
    }
}

/// Written only by the engine-to-system worker; the first refusal is set
/// before the counts, so a snapshot with packets has its sample.
#[derive(Default)]
struct RefusalTally {
    packets: AtomicU64,
    bytes: AtomicU64,
    first: OnceLock<Refusal>,
}
impl RefusalTally {
    fn add(&self, refusal: Refusal, length: usize) {
        self.first.get_or_init(|| refusal);
        self.packets.fetch_add(1, Ordering::Release);
        self.bytes.fetch_add(length as u64, Ordering::Relaxed);
    }
    fn snapshot(&self) -> RefusedClass {
        let packets = self.packets.load(Ordering::Acquire);
        RefusedClass {
            packets,
            bytes: self.bytes.load(Ordering::Relaxed),
            first: self.first.get().copied(),
        }
    }
}

struct Shared {
    /// The endpoint's irreversible cancellation: earlier PacketCancellation
    /// handles and this pump stop the same two workers.
    abort: Arc<AtomicBool>,
    peer_closing: AtomicBool,
    peer_close_code: AtomicI32,
    first_failure: AtomicU8,
    exited: AtomicU8,
    to_engine: Tally,
    to_system: Tally,
    ring_full_waits: AtomicU64,
    refused_destination: RefusalTally,
    refused_source: RefusalTally,
    refused_protocol: RefusalTally,
}
impl Shared {
    fn new(abort: Arc<AtomicBool>) -> Self {
        Self {
            abort,
            peer_closing: AtomicBool::new(false),
            peer_close_code: AtomicI32::new(0),
            first_failure: AtomicU8::new(0),
            exited: AtomicU8::new(0),
            to_engine: Tally::default(),
            to_system: Tally::default(),
            ring_full_waits: AtomicU64::new(0),
            refused_destination: RefusalTally::default(),
            refused_source: RefusalTally::default(),
            refused_protocol: RefusalTally::default(),
        }
    }
    fn refuse(&self, refusal: Refusal, length: usize) {
        match refusal.reason {
            RefusalReason::Destination => &self.refused_destination,
            RefusalReason::Source => &self.refused_source,
            RefusalReason::Protocol => &self.refused_protocol,
        }
        .add(refusal, length);
    }
    fn aborted(&self) -> bool {
        self.abort.load(Ordering::Acquire)
    }
    fn abort(&self) {
        self.abort.store(true, Ordering::Release);
    }
    fn peer_closing(&self) -> bool {
        self.peer_closing.load(Ordering::Acquire)
    }
    fn fail(&self, direction: PumpDirection) {
        let _first = self.first_failure.compare_exchange(
            0,
            bit(direction),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    fn first_failure(&self) -> Option<PumpDirection> {
        match self.first_failure.load(Ordering::Acquire) {
            1 => Some(PumpDirection::ToEngine),
            2 => Some(PumpDirection::ToSystem),
            _ => None,
        }
    }
    fn report(&self) -> PumpReport {
        PumpReport {
            to_engine: self.to_engine.snapshot(),
            to_system: self.to_system.snapshot(),
            ring_full_waits: self.ring_full_waits.load(Ordering::Relaxed),
            refused: RefusedPackets {
                destination: self.refused_destination.snapshot(),
                source: self.refused_source.snapshot(),
                protocol: self.refused_protocol.snapshot(),
            },
        }
    }
}

fn bit(direction: PumpDirection) -> u8 {
    match direction {
        PumpDirection::ToEngine => 1,
        PumpDirection::ToSystem => 2,
    }
}

/// Cross-thread control of one pump. Holding it grants no ownership: only the
/// pump owner can join the workers and report their retirement.
#[derive(Clone)]
pub struct PumpControl(Arc<Shared>);
impl PumpControl {
    /// Arm before asking the engine to stop. Forwarding to the engine ends at
    /// once and the endpoint closing becomes the expected observation.
    pub fn expect_peer_close(&self) {
        self.0.peer_closing.store(true, Ordering::Release);
    }
    /// Irreversible. Retirement still has to be reported by the owner.
    pub fn abort(&self) {
        self.0.abort();
    }
    /// Either worker has exited, including after a failure.
    pub fn terminated(&self) -> bool {
        self.0.exited.load(Ordering::Acquire) != 0
    }
}

/// Records a worker's exit even when it unwinds. Only the to-engine worker
/// ending because the engine is closing leaves its sibling running: the
/// reader still has to observe that close.
struct ExitGuard<'a> {
    shared: &'a Shared,
    direction: PumpDirection,
    finished: Option<bool>,
}
impl ExitGuard<'_> {
    fn finish(mut self, result: &Result<()>) {
        if result.is_err() {
            self.shared.fail(self.direction);
        }
        let keep_sibling = result.is_ok()
            && self.direction == PumpDirection::ToEngine
            && self.shared.peer_closing();
        self.finished = Some(keep_sibling);
    }
}
impl Drop for ExitGuard<'_> {
    fn drop(&mut self) {
        match self.finished {
            Some(true) => {}
            Some(false) => self.shared.abort(),
            None => {
                // Unwinding: the panic text is preserved by the joining owner.
                self.shared.fail(self.direction);
                self.shared.abort();
            }
        }
        self.shared
            .exited
            .fetch_or(bit(self.direction), Ordering::AcqRel);
    }
}

#[must_use = "a pump must be finished or stopped to report its retirement"]
pub struct PacketPump<'scope> {
    shared: Arc<Shared>,
    pipe: Option<Arc<OwnedHandle>>,
    to_engine: Option<ScopedJoinHandle<'scope, Result<()>>>,
    to_system: Option<ScopedJoinHandle<'scope, Result<()>>>,
}

impl<'scope> PacketPump<'scope> {
    /// Consume the endpoint and borrow the session exclusively for both
    /// workers. `policy` names the adapter addresses the owner assigned. A
    /// failed start stops and joins whatever already started.
    pub fn start(
        scope: &'scope Scope<'scope, '_>,
        session: &'scope mut Session<'_>,
        server: PacketServer,
        policy: DeliveryPolicy,
    ) -> Result<Self> {
        let (incoming, outgoing) = session.split();
        Self::start_halves(scope, incoming, outgoing, server, policy)
    }

    pub(super) fn start_halves(
        scope: &'scope Scope<'scope, '_>,
        incoming: SessionReceiver<'scope>,
        outgoing: SessionSender<'scope>,
        server: PacketServer,
        policy: DeliveryPolicy,
    ) -> Result<Self> {
        let parts = server.into_pump_parts()?;
        if parts.mtu != incoming.mtu() {
            return Err("packet session and endpoint MTUs differ".into());
        }
        let mut pump = Self {
            shared: Arc::new(Shared::new(parts.cancel)),
            pipe: Some(parts.pipe),
            to_engine: None,
            to_system: None,
        };
        let (endpoint_reader, endpoint_writer) = (parts.receiver, parts.sender);
        let worker = Arc::clone(&pump.shared);
        pump.to_engine = Some(
            thread::Builder::new()
                .name("cfw-tunnel-to-engine".into())
                .spawn_scoped(scope, move || {
                    supervise(&worker, PumpDirection::ToEngine, || {
                        to_engine(&incoming, endpoint_writer, &worker)
                    })
                })
                .map_err(|source| Error::Native {
                    operation: "start the system-to-engine packet worker",
                    source,
                })?,
        );
        let worker = Arc::clone(&pump.shared);
        pump.to_system = Some(
            thread::Builder::new()
                .name("cfw-tunnel-to-system".into())
                .spawn_scoped(scope, move || {
                    supervise(&worker, PumpDirection::ToSystem, || {
                        to_system(&outgoing, endpoint_reader, &worker, &policy)
                    })
                })
                .map_err(|source| Error::Native {
                    operation: "start the engine-to-system packet worker",
                    source,
                })?,
        );
        Ok(pump)
    }

    pub fn control(&self) -> PumpControl {
        PumpControl(Arc::clone(&self.shared))
    }

    /// Counters observed so far; retirement is reported only by finish/stop.
    pub fn report(&self) -> PumpReport {
        self.shared.report()
    }

    /// Clean retirement after `expect_peer_close` and an engine stop: wait
    /// until the reader observes the engine closing its endpoint, then join
    /// both workers and close the server end. A failure, a missing close or a
    /// retained endpoint reference is an error.
    pub fn finish(mut self, deadline: Instant) -> Result<PumpRetirement> {
        if !self.shared.peer_closing() {
            self.shared.abort();
            let contract = Error::Contract("pump retirement requires expect_peer_close".into());
            // A failure the workers already recorded stays the operation.
            return Err(match self.retire() {
                Ok(_) => contract,
                Err(failure) => Error::Cleanup {
                    operation: Box::new(failure),
                    cleanup: Box::new(contract),
                },
            });
        }
        while !self
            .to_system
            .as_ref()
            .is_none_or(ScopedJoinHandle::is_finished)
            && Instant::now() < deadline
        {
            thread::sleep(FINISH_POLL);
        }
        self.shared.abort();
        let report = self.retire()?;
        match self.shared.peer_close_code.load(Ordering::Acquire) {
            0 => Err(Error::PeerCloseUnobserved),
            peer_close_code => Ok(PumpRetirement {
                report,
                peer_close_code,
            }),
        }
    }

    /// Abort path. No claim is made about the engine's endpoint; the workers
    /// are joined, the server end is closed and any recorded failure returns.
    pub fn stop(mut self) -> Result<PumpReport> {
        self.shared.abort();
        self.retire()
    }

    fn retire(&mut self) -> Result<PumpReport> {
        let to_engine = join(self.to_engine.take(), PumpDirection::ToEngine);
        let to_system = join(self.to_system.take(), PumpDirection::ToSystem);
        let (first, second) = match self.shared.first_failure() {
            Some(PumpDirection::ToSystem) => (to_system, to_engine),
            _ => (to_engine, to_system),
        };
        let failure = merge_failures(first.err(), second.err());
        let closed = match self.pipe.take().map(Arc::try_unwrap) {
            Some(Ok(server_end)) => {
                drop(server_end);
                None
            }
            Some(Err(_shared)) => Some(Error::Contract(
                "packet endpoint is still referenced after its workers retired".into(),
            )),
            None => Some(Error::Contract(
                "packet endpoint was already retired".into(),
            )),
        };
        match merge_failures(failure, closed) {
            Some(error) => Err(error),
            None => Ok(self.shared.report()),
        }
    }
}

impl Drop for PacketPump<'_> {
    fn drop(&mut self) {
        // finish/stop report retirement. This only stops and joins the
        // workers so a panic is not re-raised anonymously at scope exit.
        self.shared.abort();
        for (handle, direction) in [
            (self.to_engine.take(), PumpDirection::ToEngine),
            (self.to_system.take(), PumpDirection::ToSystem),
        ] {
            if let Err(error) = join(handle, direction) {
                eprintln!("Windows tunnel packet pump emergency retirement: {error}");
            }
        }
    }
}

fn supervise(
    shared: &Shared,
    direction: PumpDirection,
    work: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let guard = ExitGuard {
        shared,
        direction,
        finished: None,
    };
    let result = work();
    guard.finish(&result);
    result
}

fn join(handle: Option<ScopedJoinHandle<'_, Result<()>>>, direction: PumpDirection) -> Result<()> {
    match handle {
        None => Ok(()),
        Some(handle) => handle.join().unwrap_or_else(|payload| {
            Err(Error::WorkerPanicked {
                direction,
                message: panic_text(payload.as_ref()),
            })
        }),
    }
}

fn panic_text(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-text panic payload".into()
    }
}

fn to_engine(
    session: &SessionReceiver<'_>,
    mut endpoint: PacketSender,
    shared: &Shared,
) -> Result<()> {
    let mut buffer = Zeroizing::new(vec![0u8; usize::from(session.mtu())]);
    loop {
        if shared.aborted() || shared.peer_closing() {
            return Ok(());
        }
        let Some(length) = session.receive(&mut buffer[..])? else {
            session.wait_readable(WAIT_SLICE)?;
            continue;
        };
        // An engine asked to stop is closing its endpoint. The run is ending,
        // so this last system packet is not written into a closing pipe.
        if shared.peer_closing() {
            return Ok(());
        }
        let deadline = Instant::now() + PACKET_TRANSFER_BOUND;
        match endpoint.send(&buffer[..length], deadline, &shared.abort) {
            Ok(()) => shared.to_engine.add(length),
            Err(error) => return endpoint_exit(PumpDirection::ToEngine, error, shared),
        }
    }
}

fn to_system(
    session: &SessionSender<'_>,
    mut endpoint: PacketReceiver,
    shared: &Shared,
    policy: &DeliveryPolicy,
) -> Result<()> {
    let outcome = (|| {
        loop {
            if shared.aborted() {
                return Ok(());
            }
            match endpoint.receive(Instant::now() + WAIT_SLICE, &shared.abort) {
                Ok(Some(packet)) => {
                    let bytes = packet.payload.as_bytes();
                    match policy.admit(&packet.header) {
                        Ok(()) => deliver(session, bytes, shared)?,
                        Err(refusal) => shared.refuse(refusal, bytes.len()),
                    }
                }
                Ok(None) => {}
                Err(error) => return endpoint_exit(PumpDirection::ToSystem, error, shared),
            }
        }
    })();
    let retired = endpoint.retire();
    match merge_failures(outcome.err(), retired.err()) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Queue one engine packet, waiting a bounded time for the system ring.
/// The bound is below the engine's own write deadline, so a full ring is
/// reported here, not mistaken for an engine failure.
fn deliver(session: &SessionSender<'_>, bytes: &[u8], shared: &Shared) -> Result<()> {
    let deadline = Instant::now() + PACKET_TRANSFER_BOUND;
    loop {
        match session.send(bytes) {
            Ok(()) => {
                shared.to_system.add(bytes.len());
                return Ok(());
            }
            // Stopping: the undelivered packet ends with this run.
            Err(Error::RingFull) if shared.aborted() => return Ok(()),
            Err(Error::RingFull) if Instant::now() < deadline => {
                shared.ring_full_waits.fetch_add(1, Ordering::Relaxed);
                thread::sleep(RING_RETRY);
            }
            Err(Error::RingFull) => {
                return Err(Error::Stalled {
                    direction: PumpDirection::ToSystem,
                });
            }
            Err(error) => return Err(error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointExit {
    Cancelled,
    PeerClosed(i32),
    Stalled,
    Failed,
}

fn classify(error: &Error) -> EndpointExit {
    let Error::Transport(error) = error else {
        return EndpointExit::Failed;
    };
    match error {
        ServiceTransportError::Cancelled => EndpointExit::Cancelled,
        ServiceTransportError::Deadline => EndpointExit::Stalled,
        ServiceTransportError::Io(source) => {
            peer_close_code(source).map_or(EndpointExit::Failed, EndpointExit::PeerClosed)
        }
        // Our cancellation raced the engine closing its end: still our stop.
        ServiceTransportError::Cleanup { operation, cleanup }
            if matches!(**operation, ServiceTransportError::Cancelled) =>
        {
            match &**cleanup {
                ServiceTransportError::Io(source) if peer_close_code(source).is_some() => {
                    EndpointExit::Cancelled
                }
                _ => EndpointExit::Failed,
            }
        }
        _ => EndpointExit::Failed,
    }
}

/// Our own cancellation is not a failure. The engine closing its endpoint
/// is the expected observation only after `expect_peer_close`; the reader
/// records it as the retirement evidence.
fn endpoint_exit(direction: PumpDirection, error: Error, shared: &Shared) -> Result<()> {
    match classify(&error) {
        EndpointExit::Cancelled if shared.aborted() => Ok(()),
        EndpointExit::PeerClosed(code) if shared.peer_closing() => {
            if direction == PumpDirection::ToSystem {
                shared.peer_close_code.store(code, Ordering::Release);
            }
            Ok(())
        }
        EndpointExit::PeerClosed(code) => Err(Error::PeerClosed { code }),
        EndpointExit::Stalled => Err(Error::Stalled { direction }),
        EndpointExit::Cancelled | EndpointExit::Failed => Err(error),
    }
}

#[cfg(test)]
mod tests;

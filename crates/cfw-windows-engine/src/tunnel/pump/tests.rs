//! The real pipe and pump workers against a fake session table. The fake
//! implements the Wintun calls the pump uses, so failure paths that the
//! driver cannot be forced into on a hosted runner are exercised directly.
use super::*;
use crate::{
    service_transport::native_io::{self, PendingMessageRead},
    tunnel::session::{SessionReceiver, SessionSender},
};
use std::{
    collections::VecDeque,
    ffi::c_void,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr::{NonNull, null, null_mut},
    sync::{Mutex, MutexGuard, PoisonError},
};
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_MORE_ITEMS, SetLastError},
    System::Threading::{CreateEventW, ResetEvent, SetEvent},
};

const MTU: u16 = 1500;
const ALWAYS: usize = usize::MAX;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Fake bookkeeping never panics while locked; poisoning cannot occur.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Fake {
    inbound: Mutex<VecDeque<Vec<u8>>>,
    loans: Mutex<Vec<Box<[u8]>>>,
    allocations: Mutex<Vec<Box<[u8]>>>,
    outbound: Mutex<Vec<Vec<u8>>>,
    released: AtomicUsize,
    unknown: AtomicUsize,
    ring_full: AtomicUsize,
    event: OwnedHandle,
}
impl Fake {
    fn new() -> Self {
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        assert!(!event.is_null(), "{}", std::io::Error::last_os_error());
        Self {
            inbound: Mutex::default(),
            loans: Mutex::default(),
            allocations: Mutex::default(),
            outbound: Mutex::default(),
            released: AtomicUsize::new(0),
            unknown: AtomicUsize::new(0),
            ring_full: AtomicUsize::new(0),
            event: unsafe { OwnedHandle::from_raw_handle(event) },
        }
    }
    fn push(&self, packet: Vec<u8>) {
        let mut inbound = lock(&self.inbound);
        inbound.push_back(packet);
        assert_ne!(unsafe { SetEvent(self.event.as_raw_handle()) }, 0);
    }
    fn halves(&self, mtu: u16) -> (SessionReceiver<'_>, SessionSender<'_>) {
        let session = NonNull::from(self).cast::<c_void>();
        let event = NonNull::new(self.event.as_raw_handle()).expect("fake read event");
        // SAFETY: the fake table is thread-safe, `session` and `event` belong
        // to this Fake, and the halves cannot outlive the borrow of `self`.
        unsafe {
            (
                SessionReceiver::from_parts(session, fake_receive, fake_release, event, mtu),
                SessionSender::from_parts(session, fake_allocate, fake_send, mtu),
            )
        }
    }
    fn outbound(&self) -> Vec<Vec<u8>> {
        lock(&self.outbound).clone()
    }
    fn assert_loans_balanced(&self, received: usize) {
        assert_eq!(self.released.load(Ordering::SeqCst), received);
        assert_eq!(self.unknown.load(Ordering::SeqCst), 0);
        assert!(lock(&self.loans).is_empty());
        assert!(lock(&self.allocations).is_empty());
    }
}

unsafe fn fake(session: *mut c_void) -> &'static Fake {
    // Every test keeps its Fake alive until the pump scope has joined.
    unsafe { &*session.cast::<Fake>() }
}

unsafe extern "system" fn fake_receive(session: *mut c_void, size: *mut u32) -> *mut u8 {
    let fake = unsafe { fake(session) };
    let mut inbound = lock(&fake.inbound);
    let Some(packet) = inbound.pop_front() else {
        unsafe {
            ResetEvent(fake.event.as_raw_handle());
            SetLastError(ERROR_NO_MORE_ITEMS);
        }
        return null_mut();
    };
    if inbound.is_empty() {
        unsafe { ResetEvent(fake.event.as_raw_handle()) };
    }
    drop(inbound);
    let mut loan = packet.into_boxed_slice();
    let pointer = loan.as_mut_ptr();
    unsafe { *size = loan.len() as u32 };
    lock(&fake.loans).push(loan);
    pointer
}

unsafe extern "system" fn fake_release(session: *mut c_void, packet: *const u8) {
    let fake = unsafe { fake(session) };
    let mut loans = lock(&fake.loans);
    match loans.iter().position(|loan| loan.as_ptr() == packet) {
        Some(index) => {
            loans.swap_remove(index);
            fake.released.fetch_add(1, Ordering::SeqCst);
        }
        None => {
            fake.unknown.fetch_add(1, Ordering::SeqCst);
        }
    }
}

unsafe extern "system" fn fake_allocate(session: *mut c_void, size: u32) -> *mut u8 {
    let fake = unsafe { fake(session) };
    let remaining = fake.ring_full.load(Ordering::SeqCst);
    if remaining != 0 {
        if remaining != ALWAYS {
            fake.ring_full.fetch_sub(1, Ordering::SeqCst);
        }
        unsafe { SetLastError(ERROR_BUFFER_OVERFLOW) };
        return null_mut();
    }
    let mut slot = vec![0u8; size as usize].into_boxed_slice();
    let pointer = slot.as_mut_ptr();
    lock(&fake.allocations).push(slot);
    pointer
}

unsafe extern "system" fn fake_send(session: *mut c_void, packet: *const u8) {
    let fake = unsafe { fake(session) };
    let mut allocations = lock(&fake.allocations);
    match allocations.iter().position(|slot| slot.as_ptr() == packet) {
        Some(index) => {
            let slot = allocations.swap_remove(index);
            drop(allocations);
            lock(&fake.outbound).push(slot.into_vec());
        }
        None => {
            fake.unknown.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn ipv4(length: usize, marker: u8) -> Vec<u8> {
    let mut packet = vec![marker; length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    packet
}

fn ipv6(length: usize, marker: u8) -> Vec<u8> {
    let mut packet = vec![marker; length];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&u16::try_from(length - 40).unwrap().to_be_bytes());
    packet
}

/// The test process acts as the engine through the raw client end.
struct Engine {
    pipe: Arc<OwnedHandle>,
    mtu: u16,
}
impl Engine {
    fn new(pipe: OwnedHandle, mtu: u16) -> Self {
        Self {
            pipe: Arc::new(pipe),
            mtu,
        }
    }
    fn write(&self, bytes: &[u8]) {
        native_io::write_bounded(
            &self.pipe,
            bytes,
            Instant::now() + Duration::from_secs(5),
            usize::from(self.mtu),
            None,
        )
        .expect("engine packet write");
    }
    fn next(&self, wait: Duration) -> std::result::Result<Option<Vec<u8>>, ServiceTransportError> {
        let mut read = PendingMessageRead::new(Arc::clone(&self.pipe), usize::from(self.mtu))?;
        let packet = read.poll(Instant::now() + wait, &AtomicBool::new(false))?;
        Ok(packet.map(|packet| packet.as_bytes().to_vec()))
    }
    fn read(&self) -> Vec<u8> {
        self.next(Duration::from_secs(5))
            .expect("engine packet read")
            .expect("engine packet before its deadline")
    }
    /// The server end is gone: nothing was left queued and reading fails.
    fn assert_endpoint_closed(&self) {
        let observed = self.next(Duration::from_secs(5));
        assert!(
            matches!(&observed, Err(ServiceTransportError::Io(error)) if peer_close_code(error).is_some()),
            "server end still open or a packet was left queued: {:?}",
            observed.map_err(|error| error.to_string())
        );
    }
    fn close(self) {
        drop(Arc::into_inner(self.pipe).expect("only reference to the client end"));
    }
}

fn eventually(limit: Duration, condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    condition()
}

#[test]
fn packet_pump_moves_exact_packets_both_ways_and_retires_after_the_engine_closes() {
    let fake = Fake::new();
    let system = [ipv4(1500, 1), ipv4(64, 2), ipv6(1500, 3), ipv4(1280, 4)];
    for packet in &system {
        fake.push(packet.clone());
    }
    let engine_packets = [ipv4(1500, 9), ipv6(40, 8), ipv4(20, 7)];
    let (server, client) = PacketServer::pair_for_test(MTU);
    let engine = Engine::new(client, MTU);
    let retirement = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        for expected in &system {
            assert_eq!(&engine.read(), expected);
        }
        for packet in &engine_packets {
            engine.write(packet);
        }
        assert!(eventually(Duration::from_secs(5), || fake.outbound().len()
            == engine_packets.len()));
        // A write is counted after its completion is observed, which can
        // trail the engine's read; arm the close only once all are counted.
        assert!(eventually(Duration::from_secs(5), || pump
            .report()
            .to_engine
            .packets
            == system.len() as u64));
        pump.control().expect_peer_close();
        engine.close();
        pump.finish(Instant::now() + Duration::from_secs(5))
    })
    .unwrap();
    assert_eq!(fake.outbound(), engine_packets.to_vec());
    let report = retirement.report();
    assert_eq!(
        report.to_engine,
        DirectionCounters {
            packets: 4,
            bytes: 1500 + 64 + 1500 + 1280,
            largest_packet: 1500
        }
    );
    assert_eq!(
        report.to_system,
        DirectionCounters {
            packets: 3,
            bytes: 1500 + 40 + 20,
            largest_packet: 1500
        }
    );
    assert_eq!(report.ring_full_waits, 0);
    assert_eq!(retirement.peer_close_code(), 109);
    fake.assert_loans_balanced(system.len());
}

#[test]
fn packet_pump_reports_an_engine_that_closes_before_retirement_was_requested() {
    let fake = Fake::new();
    let (server, client) = PacketServer::pair_for_test(MTU);
    let failure = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        let control = pump.control();
        drop(client);
        assert!(eventually(Duration::from_secs(5), || control.terminated()));
        pump.stop().unwrap_err()
    });
    assert!(
        matches!(failure, Error::PeerClosed { code: 109 }),
        "{failure}"
    );
    fake.assert_loans_balanced(0);
}

#[test]
fn packet_pump_fails_closed_when_the_system_ring_stays_full() {
    let fake = Fake::new();
    fake.ring_full.store(ALWAYS, Ordering::SeqCst);
    let (server, client) = PacketServer::pair_for_test(MTU);
    let engine = Engine::new(client, MTU);
    let (failure, waits, elapsed) = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        let control = pump.control();
        let started = Instant::now();
        engine.write(&ipv4(100, 5));
        assert!(eventually(Duration::from_secs(6), || control.terminated()));
        let elapsed = started.elapsed();
        let waits = pump.report().ring_full_waits;
        (pump.stop().unwrap_err(), waits, elapsed)
    });
    assert!(
        matches!(
            failure,
            Error::Stalled {
                direction: PumpDirection::ToSystem
            }
        ),
        "{failure}"
    );
    assert!(waits > 0);
    assert!(elapsed >= PACKET_TRANSFER_BOUND - Duration::from_millis(100));
    assert!(elapsed < Duration::from_secs(5));
    assert!(fake.outbound().is_empty());
    engine.assert_endpoint_closed();
    fake.assert_loans_balanced(0);
}

#[test]
fn packet_pump_retries_a_briefly_full_ring_and_delivers_once() {
    let fake = Fake::new();
    fake.ring_full.store(3, Ordering::SeqCst);
    let (server, client) = PacketServer::pair_for_test(MTU);
    let engine = Engine::new(client, MTU);
    let packet = ipv6(900, 6);
    let retirement = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        engine.write(&packet);
        assert!(eventually(Duration::from_secs(5), || fake.outbound().len() == 1));
        pump.control().expect_peer_close();
        engine.close();
        pump.finish(Instant::now() + Duration::from_secs(5))
    })
    .unwrap();
    assert_eq!(fake.outbound(), [packet]);
    assert_eq!(retirement.report().ring_full_waits, 3);
    assert_eq!(retirement.report().to_system.packets, 1);
    fake.assert_loans_balanced(0);
}

#[test]
fn packet_pump_fails_when_the_engine_stops_reading() {
    let fake = Fake::new();
    for marker in 0..4000u32 {
        fake.push(ipv4(1500, (marker % 251) as u8));
    }
    let (server, client) = PacketServer::pair_for_test(MTU);
    let failure = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        let control = pump.control();
        assert!(eventually(Duration::from_secs(8), || control.terminated()));
        pump.stop().unwrap_err()
    });
    drop(client);
    assert!(
        matches!(
            failure,
            Error::Stalled {
                direction: PumpDirection::ToEngine
            }
        ),
        "{failure}"
    );
}

#[test]
fn packet_pump_rejects_a_malformed_engine_packet_without_forwarding_it() {
    let fake = Fake::new();
    let (server, client) = PacketServer::pair_for_test(MTU);
    let engine = Engine::new(client, MTU);
    let failure = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        let control = pump.control();
        engine.write(&[0x45]);
        assert!(eventually(Duration::from_secs(5), || control.terminated()));
        pump.stop().unwrap_err()
    });
    assert!(matches!(failure, Error::Packet), "{failure}");
    assert!(fake.outbound().is_empty());
    engine.assert_endpoint_closed();
}

#[test]
fn packet_pump_rejects_a_malformed_system_packet_and_releases_it_once() {
    let fake = Fake::new();
    let mut malformed = ipv4(200, 3);
    malformed[2..4].copy_from_slice(&199u16.to_be_bytes());
    fake.push(malformed);
    let (server, client) = PacketServer::pair_for_test(MTU);
    let engine = Engine::new(client, MTU);
    let failure = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        let control = pump.control();
        assert!(eventually(Duration::from_secs(5), || control.terminated()));
        pump.stop().unwrap_err()
    });
    assert!(matches!(failure, Error::Packet), "{failure}");
    engine.assert_endpoint_closed();
    fake.assert_loans_balanced(1);
}

#[test]
fn packet_pump_owner_stop_is_not_a_failure_and_closes_the_endpoint() {
    let fake = Fake::new();
    let (server, client) = PacketServer::pair_for_test(MTU);
    let engine = Engine::new(client, MTU);
    let packet = ipv4(700, 4);
    let report = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        fake.push(packet.clone());
        assert_eq!(engine.read(), packet);
        assert!(eventually(Duration::from_secs(5), || pump
            .report()
            .to_engine
            .packets
            == 1));
        pump.stop()
    })
    .unwrap();
    assert_eq!(report.to_engine.packets, 1);
    assert_eq!(report.to_system.packets, 0);
    engine.assert_endpoint_closed();
    fake.assert_loans_balanced(1);
}

#[test]
fn packet_pump_retirement_requires_the_expected_engine_close() {
    let fake = Fake::new();
    let (server, client) = PacketServer::pair_for_test(MTU);
    let engine = Engine::new(client, MTU);
    let failure = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        pump.finish(Instant::now() + Duration::from_secs(5))
            .err()
            .expect("finish without expect_peer_close")
    });
    assert!(matches!(failure, Error::Contract(_)), "{failure}");
    engine.assert_endpoint_closed();
}

#[test]
fn packet_pump_reports_an_engine_that_never_closes_by_its_deadline() {
    let fake = Fake::new();
    let (server, client) = PacketServer::pair_for_test(MTU);
    let engine = Engine::new(client, MTU);
    let (failure, elapsed) = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        pump.control().expect_peer_close();
        let started = Instant::now();
        let failure = pump
            .finish(started + Duration::from_millis(300))
            .err()
            .expect("an open engine endpoint cannot retire");
        (failure, started.elapsed())
    });
    assert!(matches!(failure, Error::PeerCloseUnobserved), "{failure}");
    assert!(elapsed >= Duration::from_millis(300));
    assert!(elapsed < Duration::from_secs(2));
    engine.assert_endpoint_closed();
}

#[test]
fn packet_pump_writer_seeing_the_close_first_still_retires_through_the_reader() {
    let fake = Fake::new();
    for marker in 0..4000u32 {
        fake.push(ipv6(1500, (marker % 251) as u8));
    }
    let (server, client) = PacketServer::pair_for_test(MTU);
    let retirement = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        // The engine reads nothing, so the writer blocks on a full pipe.
        thread::sleep(Duration::from_millis(300));
        assert!(!pump.control().terminated());
        assert!(
            pump.report().to_engine.packets < 4000,
            "the pipe never filled"
        );
        pump.control().expect_peer_close();
        drop(client);
        pump.finish(Instant::now() + Duration::from_secs(5))
    })
    .unwrap();
    assert_eq!(retirement.peer_close_code(), 109);
    assert!(retirement.report().to_engine.packets > 0);
}

#[test]
fn packet_pump_drop_without_retirement_stops_and_joins_both_workers() {
    let fake = Fake::new();
    let (server, client) = PacketServer::pair_for_test(MTU);
    let engine = Engine::new(client, MTU);
    let started = Instant::now();
    thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        let pump = PacketPump::start_halves(scope, incoming, outgoing, server).unwrap();
        drop(pump);
    });
    assert!(started.elapsed() < Duration::from_secs(2));
    engine.assert_endpoint_closed();
}

#[test]
fn packet_pump_refuses_a_session_and_endpoint_with_different_mtus() {
    let fake = Fake::new();
    let (server, client) = PacketServer::pair_for_test(9000);
    let engine = Engine::new(client, 9000);
    let refused = thread::scope(|scope| {
        let (incoming, outgoing) = fake.halves(MTU);
        PacketPump::start_halves(scope, incoming, outgoing, server)
            .err()
            .expect("mismatched MTUs")
    });
    assert!(matches!(refused, Error::Contract(_)), "{refused}");
    engine.assert_endpoint_closed();
}

#[test]
fn packet_worker_unwinding_cancels_its_sibling_and_keeps_the_panic_text() {
    let shared = Shared::new(Arc::new(AtomicBool::new(false)));
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            supervise(&shared, PumpDirection::ToSystem, || -> Result<()> {
                panic!("injected pump fault")
            })
        });
        let failure = join(Some(worker), PumpDirection::ToSystem).unwrap_err();
        assert!(
            matches!(
                &failure,
                Error::WorkerPanicked { direction: PumpDirection::ToSystem, message }
                    if message == "injected pump fault"
            ),
            "{failure}"
        );
    });
    assert!(shared.aborted());
    assert_eq!(shared.first_failure(), Some(PumpDirection::ToSystem));
    assert_eq!(shared.exited.load(Ordering::SeqCst), 2);
}

#[test]
fn packet_only_the_writer_ending_for_an_expected_close_keeps_the_reader_running() {
    let expected = Shared::new(Arc::new(AtomicBool::new(false)));
    expected.peer_closing.store(true, Ordering::SeqCst);
    supervise(&expected, PumpDirection::ToEngine, || Ok(())).unwrap();
    assert!(!expected.aborted());
    assert_eq!(expected.exited.load(Ordering::SeqCst), 1);
    assert_eq!(expected.first_failure(), None);

    let unexpected = Shared::new(Arc::new(AtomicBool::new(false)));
    supervise(&unexpected, PumpDirection::ToEngine, || Ok(())).unwrap();
    assert!(unexpected.aborted());

    let reader = Shared::new(Arc::new(AtomicBool::new(false)));
    reader.peer_closing.store(true, Ordering::SeqCst);
    supervise(&reader, PumpDirection::ToSystem, || Ok(())).unwrap();
    assert!(reader.aborted());

    let failed = Shared::new(Arc::new(AtomicBool::new(false)));
    failed.peer_closing.store(true, Ordering::SeqCst);
    assert!(supervise(&failed, PumpDirection::ToEngine, || Err(Error::Packet)).is_err());
    assert!(failed.aborted());
    assert_eq!(failed.first_failure(), Some(PumpDirection::ToEngine));
}

#[test]
fn packet_endpoint_errors_are_classified_without_hiding_failures() {
    fn io(code: i32) -> ServiceTransportError {
        ServiceTransportError::Io(std::io::Error::from_raw_os_error(code))
    }
    let cases = [
        (ServiceTransportError::Cancelled, EndpointExit::Cancelled),
        (ServiceTransportError::Deadline, EndpointExit::Stalled),
        (io(109), EndpointExit::PeerClosed(109)),
        (io(232), EndpointExit::PeerClosed(232)),
        (io(233), EndpointExit::Failed),
        (io(5), EndpointExit::Failed),
        (ServiceTransportError::MessageLength, EndpointExit::Failed),
        (ServiceTransportError::Closed, EndpointExit::Failed),
        (
            ServiceTransportError::Cleanup {
                operation: Box::new(ServiceTransportError::Cancelled),
                cleanup: Box::new(io(109)),
            },
            EndpointExit::Cancelled,
        ),
        (
            ServiceTransportError::Cleanup {
                operation: Box::new(ServiceTransportError::Cancelled),
                cleanup: Box::new(io(5)),
            },
            EndpointExit::Failed,
        ),
        (
            ServiceTransportError::Cleanup {
                operation: Box::new(ServiceTransportError::Deadline),
                cleanup: Box::new(io(109)),
            },
            EndpointExit::Failed,
        ),
    ];
    for (error, expected) in cases {
        let text = error.to_string();
        assert_eq!(classify(&Error::Transport(error)), expected, "{text}");
    }
    assert_eq!(classify(&Error::Packet), EndpointExit::Failed);

    let idle = Shared::new(Arc::new(AtomicBool::new(false)));
    assert!(matches!(
        endpoint_exit(PumpDirection::ToSystem, Error::Transport(io(109)), &idle),
        Err(Error::PeerClosed { code: 109 })
    ));
    assert!(
        endpoint_exit(
            PumpDirection::ToEngine,
            Error::Transport(ServiceTransportError::Cancelled),
            &idle
        )
        .is_err(),
        "cancellation that nobody requested is a failure"
    );
    assert!(matches!(
        endpoint_exit(
            PumpDirection::ToEngine,
            Error::Transport(ServiceTransportError::Deadline),
            &idle
        ),
        Err(Error::Stalled {
            direction: PumpDirection::ToEngine
        })
    ));
    idle.peer_closing.store(true, Ordering::SeqCst);
    endpoint_exit(PumpDirection::ToEngine, Error::Transport(io(232)), &idle).unwrap();
    assert_eq!(idle.peer_close_code.load(Ordering::SeqCst), 0);
    endpoint_exit(PumpDirection::ToSystem, Error::Transport(io(109)), &idle).unwrap();
    assert_eq!(idle.peer_close_code.load(Ordering::SeqCst), 109);
    idle.abort();
    endpoint_exit(
        PumpDirection::ToEngine,
        Error::Transport(ServiceTransportError::Cancelled),
        &idle,
    )
    .unwrap();
}

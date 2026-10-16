import CFWSharedProtocol
import Dispatch
import Foundation
import Synchronization
import Testing

@testable import CFWLibboxRuntime

private enum WatchdogTestError: Error, Equatable {
  case start
  case interrupt
}

/// Records the deadline action instead of arming a timer, so each test decides
/// when (and whether) the deadline fires.
private final class ManualStartDeadline: @unchecked Sendable {
  private let lock = NSLock()
  private var scheduled: [(instant: ContinuousClock.Instant, action: @Sendable () -> Void)] = []
  private var cancellations = 0

  var schedule: LibboxStartWatchdog.Schedule {
    { instant, action in
      self.lock.withLock { self.scheduled.append((instant, action)) }
      return { self.lock.withLock { self.cancellations += 1 } }
    }
  }

  var scheduledInstants: [ContinuousClock.Instant] { lock.withLock { scheduled.map(\.instant) } }
  var cancelCount: Int { lock.withLock { cancellations } }

  func fire() {
    let action = lock.withLock { scheduled[0].action }
    action()
  }
}

private final class InterruptRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0
  private let failure: WatchdogTestError?

  init(failure: WatchdogTestError? = nil) { self.failure = failure }

  var calls: Int { lock.withLock { count } }

  func interrupt() throws {
    lock.withLock { count += 1 }
    if let failure { throw failure }
  }
}

private let now = ContinuousClock.now
private let deadline = EngineStartDeadline(receivedAt: now)

private func watchdog(_ manual: ManualStartDeadline) -> LibboxStartWatchdog {
  LibboxStartWatchdog(now: { now }, schedule: manual.schedule)
}

@Test func startThatReturnsBeforeTheDeadlineIsNeverInterrupted() {
  let manual = ManualStartDeadline()
  let interrupts = InterruptRecorder()
  let outcome = watchdog(manual).run(
    deadline: deadline, interrupt: { try interrupts.interrupt() }, start: { 7 })
  guard case .completed(.success(7)) = outcome else {
    Issue.record("expected an in-time completion, got \(outcome)")
    return
  }
  #expect(manual.scheduledInstants == [deadline.instant])
  #expect(manual.cancelCount == 1)
  manual.fire()
  #expect(interrupts.calls == 0)
}

@Test func startErrorBeforeTheDeadlineIsReportedUnchanged() {
  let manual = ManualStartDeadline()
  let interrupts = InterruptRecorder()
  let outcome: LibboxStartWatchdog.Outcome<Void> = watchdog(manual).run(
    deadline: deadline, interrupt: { try interrupts.interrupt() },
    start: { throw WatchdogTestError.start })
  guard case .completed(.failure(let error)) = outcome else {
    Issue.record("expected the start error, got \(outcome)")
    return
  }
  #expect(error as? WatchdogTestError == .start)
  #expect(manual.cancelCount == 1)
  manual.fire()
  #expect(interrupts.calls == 0)
}

@Test func deadlineDuringStartInterruptsOnceAndKeepsWhatTheStartReturned() {
  let manual = ManualStartDeadline()
  let interrupts = InterruptRecorder()
  let outcome = watchdog(manual).run(
    deadline: deadline, interrupt: { try interrupts.interrupt() },
    start: { () -> Int in
      manual.fire()
      manual.fire()
      return 7
    })
  guard case .interrupted(start: .success(7), interruption: .success) = outcome else {
    Issue.record("expected an interrupted start, got \(outcome)")
    return
  }
  #expect(interrupts.calls == 1)
}

@Test func deadlineDuringAFailingStartKeepsTheStartsOwnError() {
  let manual = ManualStartDeadline()
  let interrupts = InterruptRecorder()
  let outcome: LibboxStartWatchdog.Outcome<Void> = watchdog(manual).run(
    deadline: deadline, interrupt: { try interrupts.interrupt() },
    start: {
      manual.fire()
      throw WatchdogTestError.start
    })
  guard case .interrupted(start: .failure(let error), interruption: .success) = outcome else {
    Issue.record("expected the start's own error beside the interrupt, got \(outcome)")
    return
  }
  #expect(error as? WatchdogTestError == .start)
  #expect(interrupts.calls == 1)
}

@Test func failedInterruptIsSurfacedToTheCaller() {
  let manual = ManualStartDeadline()
  let interrupts = InterruptRecorder(failure: .interrupt)
  let outcome = watchdog(manual).run(
    deadline: deadline, interrupt: { try interrupts.interrupt() },
    start: { () -> Int in
      manual.fire()
      return 7
    })
  guard case .interrupted(start: .success(7), interruption: .failure(let error)) = outcome else {
    Issue.record("expected the interrupt failure, got \(outcome)")
    return
  }
  #expect(error as? WatchdogTestError == .interrupt)
  #expect(interrupts.calls == 1)
}

@Test func startNeedsTheMinimumWindowBeforeTheDeadline() {
  // A deadline landing while libbox still builds the instance costs the rest of
  // the build, so a start with less than the window left fails before it begins.
  #expect(LibboxStartWatchdog.minimumStartWindow == .seconds(2))
  let window = LibboxStartWatchdog.minimumStartWindow
  for (remaining, starts) in [
    (window, true), (window - .nanoseconds(1), false), (.zero, false), (.seconds(-3), false),
  ] {
    let manual = ManualStartDeadline()
    let interrupts = InterruptRecorder()
    let startCalls = InterruptRecorder()
    let at = deadline.instant.advanced(by: .zero - remaining)
    let outcome = LibboxStartWatchdog(now: { at }, schedule: manual.schedule).run(
      deadline: deadline, interrupt: { try interrupts.interrupt() },
      start: { () -> Int in
        try startCalls.interrupt()
        return 7
      })
    switch outcome {
    case .completed(.success(7)):
      #expect(starts, "started with \(remaining) left")
      #expect(manual.scheduledInstants == [deadline.instant])
    case .notStarted:
      #expect(!starts, "refused with \(remaining) left")
      #expect(manual.scheduledInstants.isEmpty)
      #expect(startCalls.calls == 0)
    default:
      Issue.record("unexpected outcome \(outcome) with \(remaining) left")
    }
    #expect(interrupts.calls == 0)
  }
}

private final class OutcomeBox: @unchecked Sendable {
  private let lock = NSLock()
  private var interrupted = false
  private var stalled = false
  func record(_ outcome: LibboxStartWatchdog.Outcome<Int>) {
    if case .interrupted(start: .success(7), interruption: .success) = outcome {
      lock.withLock { interrupted = true }
    }
  }
  /// A wait inside the start or the interrupt gave up instead of being released.
  func recordStall() { lock.withLock { stalled = true } }
  var wasInterrupted: Bool { lock.withLock { interrupted } }
  var hasStalled: Bool { lock.withLock { stalled } }
}

@Test func runDoesNotReturnWhileAFiredInterruptIsStillRunning() {
  let manual = ManualStartDeadline()
  let interruptEntered = DispatchSemaphore(value: 0)
  let releaseInterrupt = DispatchSemaphore(value: 0)
  let runReturned = DispatchSemaphore(value: 0)
  let outcome = OutcomeBox()
  let subject = watchdog(manual)
  DispatchQueue.global().async {
    outcome.record(
      subject.run(
        deadline: deadline,
        interrupt: {
          interruptEntered.signal()
          if releaseInterrupt.wait(timeout: .now() + .seconds(10)) == .timedOut {
            outcome.recordStall()
          }
        },
        start: { () -> Int in
          DispatchQueue.global().async { manual.fire() }
          if interruptEntered.wait(timeout: .now() + .seconds(10)) == .timedOut {
            outcome.recordStall()
          }
          return 7
        }))
    runReturned.signal()
  }
  // The start has returned while the interrupt is still running: no return yet.
  #expect(runReturned.wait(timeout: .now() + .milliseconds(300)) == .timedOut)
  releaseInterrupt.signal()
  #expect(runReturned.wait(timeout: .now() + .seconds(15)) == .success)
  #expect(outcome.wasInterrupted)
  #expect(!outcome.hasStalled)
}

/// Releases two threads at once so the deadline firing and the start returning
/// genuinely race.
private final class StartingLine: Sendable {
  private let arrivals = Atomic<Int>(0)

  func arriveAndWait() {
    arrivals.add(1, ordering: .sequentiallyConsistent)
    while arrivals.load(ordering: .sequentiallyConsistent) < 2 {}
  }
}

@Test func completionRacingTheDeadlineHasExactlyOneConsistentOutcome() {
  for _ in 0..<2_000 {
    let manual = ManualStartDeadline()
    let interrupts = InterruptRecorder()
    let fired = DispatchSemaphore(value: 0)
    let line = StartingLine()
    let outcome = watchdog(manual).run(
      deadline: deadline, interrupt: { try interrupts.interrupt() },
      start: { () -> Int in
        DispatchQueue.global().async {
          line.arriveAndWait()
          manual.fire()
          fired.signal()
        }
        line.arriveAndWait()
        return 7
      })
    #expect(fired.wait(timeout: .now() + .seconds(5)) == .success)
    switch outcome {
    case .completed(.success(7)):
      #expect(interrupts.calls == 0)
    case .interrupted(start: .success(7), interruption: .success):
      #expect(interrupts.calls == 1)
    default:
      Issue.record("unexpected outcome \(outcome)")
    }
  }
}

@Test func productionDeadlineInterruptsABlockedStart() {
  let interruptRan = DispatchSemaphore(value: 0)
  let soon = EngineStartDeadline(
    receivedAt: ContinuousClock.now.advanced(
      by: LibboxStartWatchdog.minimumStartWindow + .milliseconds(200)
        - EngineStartBudget.ownerLibboxStart))
  let outcome = LibboxStartWatchdog().run(
    deadline: soon,
    interrupt: { interruptRan.signal() },
    start: { () -> Bool in
      interruptRan.wait(timeout: .now() + .seconds(10)) == .success
    })
  let lateness = soon.instant.duration(to: .now)
  guard case .interrupted(start: .success(true), interruption: .success) = outcome else {
    Issue.record("expected the production deadline to interrupt, got \(outcome)")
    return
  }
  #expect(lateness >= .zero)
  #expect(
    lateness < EngineStartBudget.deadlineTolerance + .milliseconds(250),
    "the deadline fired \(lateness) late")
}

/// The continuous clock, recording each sleep the watchdog asks it for and when
/// that sleep ends.
private struct RecordingContinuousClock: Clock {
  typealias Instant = ContinuousClock.Instant

  enum Event: Equatable, Sendable {
    case began(deadline: Instant, tolerance: Duration?)
    case ended
  }

  let events: AsyncStream<Event>.Continuation

  var now: Instant { ContinuousClock.now }
  var minimumResolution: Duration { ContinuousClock().minimumResolution }

  func sleep(until deadline: Instant, tolerance: Duration?) async throws {
    events.yield(.began(deadline: deadline, tolerance: tolerance))
    defer { events.yield(.ended) }
    try await ContinuousClock().sleep(until: deadline, tolerance: tolerance)
  }
}

/// Without an explicit tolerance the system may fire an 11-second sleep about a
/// second late, which the Host's waits do not leave room for. Cancelling the
/// deadline, as a start that returned in time does, ends the sleep at once.
@Test func productionDeadlineSleepsWithTheBudgetToleranceUntilCancelled() async throws {
  let (events, recorder) = AsyncStream.makeStream(of: RecordingContinuousClock.Event.self)
  let deadline = EngineStartDeadline(receivedAt: .now)
  let schedule = LibboxStartWatchdog.sleeping(on: RecordingContinuousClock(events: recorder))
  let cancel = schedule(deadline.instant) { Issue.record("a cancelled deadline fired") }
  // Ends the stream if the sleeper stops reporting, so the test fails instead
  // of hanging.
  let giveUp = Task {
    try await Task.sleep(for: .seconds(5))
    recorder.finish()
  }
  var observed = events.makeAsyncIterator()
  let began = await observed.next()
  #expect(
    began == .began(deadline: deadline.instant, tolerance: EngineStartBudget.deadlineTolerance))
  cancel()
  let ended = await observed.next()
  giveUp.cancel()
  #expect(ended == .ended, "cancelling the deadline did not end its sleep")
}

/// What a verdict tells the runtime, in a form tests can compare.
private enum StartMeaning: Equatable {
  case started
  case conflict(Int)
  case timedOut
  case failed(WatchdogTestError)
}

private enum InterruptMeaning: Equatable {
  case notFired
  case closed
  case failed(WatchdogTestError)
}

private func meaning(_ verdict: LibboxStartVerdict<Int>) -> (StartMeaning, InterruptMeaning)? {
  let start: StartMeaning
  switch verdict.start {
  case .success(nil):
    start = .started
  case .success(let conflict?):
    start = .conflict(conflict)
  case .failure(let error):
    if error as? LibboxRuntimeError == .serviceStartTimedOut {
      start = .timedOut
    } else if let error = error as? WatchdogTestError {
      start = .failed(error)
    } else {
      return nil
    }
  }
  switch verdict.interruption {
  case nil:
    return (start, .notFired)
  case .success:
    return (start, .closed)
  case .failure(let error):
    guard let error = error as? WatchdogTestError else { return nil }
    return (start, .failed(error))
  }
}

@Test func everyStartOutcomeHasOneMeaningForTheRuntime() {
  typealias Outcome = LibboxStartWatchdog.Outcome<Int?>
  let table: [(Outcome, StartMeaning, InterruptMeaning)] = [
    (.notStarted, .timedOut, .notFired),
    (.completed(.success(nil)), .started, .notFired),
    (.completed(.success(7)), .conflict(7), .notFired),
    (.completed(.failure(WatchdogTestError.start)), .failed(.start), .notFired),
    // libbox reports an interrupted start as success: that start timed out.
    (.interrupted(start: .success(nil), interruption: .success(())), .timedOut, .closed),
    (.interrupted(start: .success(7), interruption: .success(())), .conflict(7), .closed),
    (
      .interrupted(start: .failure(WatchdogTestError.start), interruption: .success(())),
      .failed(.start), .closed
    ),
    (
      .interrupted(start: .success(nil), interruption: .failure(WatchdogTestError.interrupt)),
      .timedOut, .failed(.interrupt)
    ),
  ]
  for (outcome, start, interruption) in table {
    let verdict: LibboxStartVerdict<Int> = outcome.verdict()
    guard let observed = meaning(verdict) else {
      Issue.record("\(outcome) produced an unexpected error")
      continue
    }
    #expect(observed.0 == start, "\(outcome)")
    #expect(observed.1 == interruption, "\(outcome)")
  }
}

@Test func timedOutStartNamesTheBudgetAndStaysDistinctFromAStartFailure() {
  let timedOut = LibboxRuntimeError.serviceStartTimedOut
  let description = timedOut.localizedDescription
  #expect(description.contains("11 seconds"))
  #expect(timedOut != .serviceStartFailed(description))
}

#if canImport(Libbox)
  /// Binds `descriptor` to a loopback TCP port (0 picks a free one) and returns
  /// the port.
  private func bindLoopback(_ descriptor: Int32, port: UInt16) throws -> UInt16 {
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    address.sin_port = port.bigEndian
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let bound = withUnsafeMutablePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
        Darwin.bind(descriptor, socketAddress, length) == 0
          && getsockname(descriptor, socketAddress, &length) == 0
      }
    }
    guard bound else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    return UInt16(bigEndian: address.sin_port)
  }

  /// Binds a fresh loopback socket to `port`, closes it, and returns the port.
  /// Binding fails with `EADDRINUSE` while a socket of this user is still bound
  /// to 127.0.0.1 at that port, which is where the linked configuration has
  /// libbox listen; `SO_REUSEADDR` keeps connections that were closed but linger
  /// in TIME_WAIT from failing it too.
  private func probeLoopbackPort(_ port: UInt16) throws -> UInt16 {
    let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { Darwin.close(descriptor) }
    var reuse: Int32 = 1
    guard
      setsockopt(
        descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size)) == 0
    else {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    return try bindLoopback(descriptor, port: port)
  }

  /// A loopback TCP server for linked starts, on plain sockets so that tearing
  /// down its connections logs nothing. It counts the connections it accepts
  /// and either holds them unanswered, so a download from it stalls until the
  /// client gives up, or answers each request once with `response`.
  private final class LoopbackServer: @unchecked Sendable {
    let port: UInt16
    private let listener: Int32
    private let response: Data?
    private let queue = DispatchQueue(label: "com.bill.clashformac.tests.loopback-server")
    private let lock = NSLock()
    private var connections: [Int32] = []
    private let acceptSource: any DispatchSourceRead

    /// `response` is the whole HTTP response written once a request's headers
    /// arrived; nil leaves every request unanswered.
    init(response: Data?) throws {
      self.response = response
      let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
      guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
      do {
        port = try bindLoopback(descriptor, port: 0)
        guard Darwin.listen(descriptor, 16) == 0,
          fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL) | O_NONBLOCK) == 0
        else {
          throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
      } catch {
        Darwin.close(descriptor)
        throw error
      }
      listener = descriptor
      acceptSource = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
      acceptSource.setEventHandler { [weak self] in self?.acceptPending() }
      acceptSource.setCancelHandler { Darwin.close(descriptor) }
      acceptSource.resume()
    }

    var acceptedConnections: Int { lock.withLock { connections.count } }

    func cancel() {
      acceptSource.cancel()
      queue.sync {
        lock.withLock {
          for connection in connections { Darwin.close(connection) }
          connections.removeAll()
        }
      }
    }

    private func acceptPending() {
      while true {
        let connection = Darwin.accept(listener, nil, nil)
        guard connection >= 0 else { return }
        lock.withLock { connections.append(connection) }
        if let response {
          Self.answer(connection, with: response)
        }
      }
    }

    /// Reads one request's headers, then writes the response and ends the
    /// stream. A connection that fails either step is reset, which fails the
    /// client's download visibly; a client that closed first fails the write
    /// instead of raising SIGPIPE in the test process.
    private static func answer(_ connection: Int32, with response: Data) {
      var timeout = timeval(tv_sec: 5, tv_usec: 0)
      var noSignal: Int32 = 1
      guard fcntl(connection, F_SETFL, fcntl(connection, F_GETFL) & ~O_NONBLOCK) == 0,
        setsockopt(
          connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
          == 0,
        setsockopt(
          connection, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
          == 0
      else {
        _ = Darwin.shutdown(connection, SHUT_RDWR)
        return
      }
      var request = Data()
      var buffer = [UInt8](repeating: 0, count: 4_096)
      while request.range(of: Data("\r\n\r\n".utf8)) == nil {
        let count = Darwin.read(connection, &buffer, buffer.count)
        guard count > 0 else {
          _ = Darwin.shutdown(connection, SHUT_RDWR)
          return
        }
        request.append(contentsOf: buffer[0..<count])
      }
      let written = response.withUnsafeBytes { bytes -> Bool in
        guard let base = bytes.baseAddress else { return false }
        var sent = 0
        while sent < bytes.count {
          let count = Darwin.write(connection, base + sent, bytes.count - sent)
          guard count > 0 else { return false }
          sent += count
        }
        return true
      }
      _ = Darwin.shutdown(connection, written ? SHUT_WR : SHUT_RDWR)
    }
  }

  /// One remote rule set of a linked configuration, downloaded through the
  /// outbound `detour` names.
  private struct LinkedRuleSet {
    let tag: String
    let url: String
    let format: String
    var detour = "direct"
  }

  /// The loopback ports of one linked System Proxy runtime.
  private struct LinkedEndpoints {
    let mixedPort: UInt16
    let controllerPort: UInt16

    init() throws {
      let mixed = try probeLoopbackPort(0)
      var controller = try probeLoopbackPort(0)
      while controller == mixed {
        controller = try probeLoopbackPort(0)
      }
      mixedPort = mixed
      controllerPort = controller
    }

    /// A configuration the runtime admits whose remote rule sets download from
    /// their URLs, with libbox's cache file at `cacheFile`. With `proxyPort`
    /// it also has a SOCKS outbound tagged `proxy` to that loopback port.
    func configuration(
      ruleSets: [LinkedRuleSet], cacheFile: URL, proxyPort: UInt16? = nil
    ) throws -> Data {
      var outbounds: [[String: Any]] = [["type": "direct", "tag": "direct"]]
      if let proxyPort {
        outbounds.append([
          "type": "socks", "tag": "proxy", "server": "127.0.0.1",
          "server_port": Int(proxyPort),
        ])
      }
      return try JSONSerialization.data(withJSONObject: [
        "log": ["level": "error"],
        "inbounds": [
          [
            "type": "mixed", "tag": "cfw-system-proxy", "listen": "127.0.0.1",
            "listen_port": Int(mixedPort),
          ]
        ],
        "outbounds": outbounds,
        "route": [
          "rule_set": ruleSets.map { ruleSet in
            [
              "type": "remote", "tag": ruleSet.tag, "format": ruleSet.format,
              "url": ruleSet.url, "download_detour": ruleSet.detour,
            ]
          },
          "rules": [
            ["rule_set": ruleSets.map(\.tag), "action": "route", "outbound": "direct"]
          ],
          "final": "direct",
        ],
        "experimental": [
          "cache_file": ["enabled": true, "path": cacheFile.path],
          "clash_api": [
            "external_controller": "127.0.0.1:\(controllerPort)", "secret": "linked-test",
          ],
        ],
      ])
    }
  }

  private final class StartResult: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Result<Void, any Error>?
    func record(_ result: Result<Void, any Error>) { lock.withLock { value = result } }
    var result: Result<Void, any Error>? { lock.withLock { value } }
  }

  /// A step expected to fail that started anyway leaves libbox running; stop
  /// it so the later steps and the cleanup still find an idle runtime.
  private func stopIfStarted(
    _ runtime: SourceBuiltLibboxServiceRuntime, _ result: Result<Void, any Error>
  ) {
    guard case .success = result else { return }
    do {
      try runtime.stop()
    } catch {
      Issue.record(error, "a start that should have failed did not stop")
    }
  }

  /// Every close of libbox's network monitor in a runtime given this fault
  /// fails with it, so libbox fails to close that runtime's instance.
  private struct LinkedMonitorCloseFault: LocalizedError {
    static let text = "linked test: the network monitor did not close"
    var errorDescription: String? { Self.text }
  }

  /// What stopping `runtime` threw, or nil when it stopped.
  private func closeFailure(
    of runtime: SourceBuiltLibboxServiceRuntime
  ) -> LibboxInstanceUnclosable? {
    do {
      try runtime.stop()
      return nil
    } catch {
      return error
    }
  }

  /// Starts on another queue so an interrupt that never ends the start fails
  /// the test instead of hanging the lane. Nil means the start never returned.
  private func boundedStart(
    _ runtime: SourceBuiltLibboxServiceRuntime, _ configuration: Data,
    deadline: EngineStartDeadline
  ) -> Result<Void, any Error>? {
    let returned = DispatchSemaphore(value: 0)
    let outcome = StartResult()
    DispatchQueue.global(qos: .userInitiated).async {
      outcome.record(
        Result {
          try runtime.start(
            configuration: configuration, packetFileDescriptor: nil, deadline: deadline)
        })
      returned.signal()
    }
    guard returned.wait(timeout: .now() + .seconds(20)) == .success else { return nil }
    return outcome.result
  }

  /// The real runtime ends every start in a state it can start from again. A
  /// start that fails before libbox starts the network leaves it idle; a stalled
  /// rule-set download is interrupted at the owner's deadline, while a rule set
  /// that finished downloading is kept for the next start; a download stalled
  /// at its proxy is interrupted alike; a start with too little time left never
  /// begins; and a later start from the kept rule set listens, then stops and
  /// releases its listeners. A runtime whose close fails, at a stop, at the
  /// interrupt or after a start's own failure, is spent instead: it reports
  /// that close failure from then on and never reaches libbox again.
  /// libbox takes its directories once per process, so this is the bundle's only
  /// test that starts it.
  @Test func linkedRuntimeBoundsEveryStartAndStaysStartable() throws {
    let stalled = try LoopbackServer(response: nil)
    defer { stalled.cancel() }
    let ruleSet = Data(#"{"version":1,"rules":[{"domain_suffix":["linked-test.invalid"]}]}"#.utf8)
    let headers =
      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
      + "Content-Length: \(ruleSet.count)\r\nConnection: close\r\n\r\n"
    let served = try LoopbackServer(response: Data(headers.utf8) + ruleSet)
    defer { served.cancel() }
    let stalledProxy = try LoopbackServer(response: nil)
    defer { stalledProxy.cancel() }
    let stalledSet = LinkedRuleSet(
      tag: "stalled", url: "http://127.0.0.1:\(stalled.port)/stalled.srs", format: "binary")
    let servedSet = LinkedRuleSet(
      tag: "served", url: "http://127.0.0.1:\(served.port)/linked.json", format: "source")
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer {
      do { try FileManager.default.removeItem(at: root) } catch { Issue.record(error) }
    }
    let directories = try LibboxRuntimeDirectories.prepare(container: root, role: .systemProxy)
    let runtime = try SourceBuiltLibboxServiceRuntime(role: .systemProxy, directories: directories)
    let endpoints = try LinkedEndpoints()
    let cache = root.appendingPathComponent("cache.db")

    // libbox cannot open a cache file that is a directory, so the start fails
    // before the network starts and libbox closes a monitor that never ran.
    let blockedCache = root.appendingPathComponent("blocked-cache.db", isDirectory: true)
    try FileManager.default.createDirectory(at: blockedCache, withIntermediateDirectories: false)
    let failed = try #require(
      boundedStart(
        runtime,
        try endpoints.configuration(ruleSets: [stalledSet], cacheFile: blockedCache),
        deadline: EngineStartDeadline(receivedAt: .now)),
      "a start that failed early never returned")
    stopIfStarted(runtime, failed)
    guard case .failure(let error) = failed,
      case .serviceStartFailed? = error as? LibboxRuntimeError
    else {
      Issue.record("expected a start failure whose cleanup succeeded, got \(failed)")
      return
    }

    // Each stalled start also carries a rule set that downloads at once.
    let stalledConfiguration = try endpoints.configuration(
      ruleSets: [servedSet, stalledSet], cacheFile: cache)
    for attempt in 1...2 {
      let deadline = EngineStartDeadline(
        receivedAt: ContinuousClock.now.advanced(
          by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
      let timedOut = try #require(
        boundedStart(runtime, stalledConfiguration, deadline: deadline),
        "the interrupt never ended stalled start \(attempt)")
      stopIfStarted(runtime, timedOut)
      let lateness = deadline.instant.duration(to: .now)
      #expect(throws: LibboxRuntimeError.serviceStartTimedOut) { try timedOut.get() }
      #expect(lateness >= .zero, "start \(attempt) returned \(lateness) before its deadline")
      #expect(
        lateness < EngineStartBudget.deadlineTolerance + EngineStartBudget.interruptAllowance,
        "start \(attempt) returned \(lateness) after its deadline")
      #expect(stalled.acceptedConnections == attempt, "the stall was not the rule-set download")
    }
    #expect(
      served.acceptedConnections == 1,
      "a rule set that finished downloading before the interrupt was not kept")

    // Rule sets download through the outbound their `download_detour` names,
    // in production the profile's selected node. A proxy that accepts the
    // connection and never answers must not hold the start past its deadline
    // either; the URL is the served one, so a download that skipped the proxy
    // would succeed.
    let proxiedSet = LinkedRuleSet(
      tag: "proxied", url: "http://127.0.0.1:\(served.port)/proxied.json", format: "source",
      detour: "proxy")
    let proxiedDeadline = EngineStartDeadline(
      receivedAt: ContinuousClock.now.advanced(
        by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
    let proxied = try #require(
      boundedStart(
        runtime,
        try endpoints.configuration(
          ruleSets: [proxiedSet], cacheFile: cache, proxyPort: stalledProxy.port),
        deadline: proxiedDeadline),
      "the interrupt never ended a start stalled at its proxy")
    stopIfStarted(runtime, proxied)
    let proxiedLateness = proxiedDeadline.instant.duration(to: .now)
    #expect(throws: LibboxRuntimeError.serviceStartTimedOut) { try proxied.get() }
    #expect(proxiedLateness >= .zero)
    #expect(
      proxiedLateness < EngineStartBudget.deadlineTolerance + EngineStartBudget.interruptAllowance,
      "a start stalled at its proxy returned \(proxiedLateness) after its deadline")
    #expect(stalledProxy.acceptedConnections == 1, "the stall was not the proxy")
    #expect(served.acceptedConnections == 1, "the proxied download reached the server")

    // With less than the minimum start window left the runtime never begins
    // the start: it times out without downloading anything.
    let tooLate = try #require(
      boundedStart(
        runtime, stalledConfiguration,
        deadline: EngineStartDeadline(
          receivedAt: ContinuousClock.now.advanced(
            by: .seconds(1) - EngineStartBudget.ownerLibboxStart))),
      "a start with too little time left never returned")
    stopIfStarted(runtime, tooLate)
    #expect(throws: LibboxRuntimeError.serviceStartTimedOut) { try tooLate.get() }
    #expect(stalled.acceptedConnections == 2, "a start that never began downloaded its rule set")

    let started = try #require(
      boundedStart(
        runtime,
        try endpoints.configuration(ruleSets: [servedSet], cacheFile: cache),
        deadline: EngineStartDeadline(receivedAt: .now)),
      "a start from the kept rule set never returned")
    try started.get()
    #expect(served.acceptedConnections == 1, "the start downloaded a rule set it had kept")
    try runtime.healthCheck()
    for port in [endpoints.mixedPort, endpoints.controllerPort] {
      #expect(throws: POSIXError(.EADDRINUSE), "libbox does not listen on \(port)") {
        _ = try probeLoopbackPort(port)
      }
    }
    try runtime.stop()
    for port in [endpoints.mixedPort, endpoints.controllerPort] {
      #expect(throws: Never.self, "libbox still listens on \(port)") {
        _ = try probeLoopbackPort(port)
      }
    }

    // libbox closes an instance once, so a close that fails leaves the runtime
    // spent. Its monitor fails here while libbox still closes every other part,
    // listeners included.
    let servedConfiguration = try endpoints.configuration(
      ruleSets: [servedSet], cacheFile: cache)
    let stopSpent = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorCloseFault: LinkedMonitorCloseFault())
    try #require(
      boundedStart(stopSpent, servedConfiguration, deadline: EngineStartDeadline(receivedAt: .now)),
      "a start whose close will fail never returned"
    ).get()
    let stopFailure = try #require(
      closeFailure(of: stopSpent), "a close whose network monitor failed reported success")
    #expect(stopFailure.closeFailure.contains(LinkedMonitorCloseFault.text))
    for port in [endpoints.mixedPort, endpoints.controllerPort] {
      #expect(throws: Never.self, "libbox still listens on \(port) after its failed close") {
        _ = try probeLoopbackPort(port)
      }
    }
    #expect(closeFailure(of: stopSpent) == stopFailure, "a later stop reached libbox again")
    #expect(throws: stopFailure) {
      try stopSpent.start(
        configuration: servedConfiguration, packetFileDescriptor: nil,
        deadline: EngineStartDeadline(receivedAt: .now))
    }

    // A stalled start whose close fails when it is interrupted is spent alike.
    let interruptSpent = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorCloseFault: LinkedMonitorCloseFault())
    let spentDeadline = EngineStartDeadline(
      receivedAt: ContinuousClock.now.advanced(
        by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
    let interrupted = try #require(
      boundedStart(interruptSpent, stalledConfiguration, deadline: spentDeadline),
      "the interrupt never ended a start whose close fails")
    stopIfStarted(interruptSpent, interrupted)
    guard case .failure(let error) = interrupted,
      let startFailure = error as? LibboxInstanceUnclosable
    else {
      Issue.record("expected the interrupted start to report its failed close, got \(interrupted)")
      return
    }
    #expect(stalled.acceptedConnections == 3, "the stall was not the rule-set download")
    #expect(closeFailure(of: interruptSpent) == startFailure)

    // A start that fails on its own closes its instance itself. When that close
    // fails libbox keeps the instance and cannot close it again, so the runtime
    // is spent rather than idle.
    let failedSpent = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorCloseFault: LinkedMonitorCloseFault())
    let ownFailure = try #require(
      boundedStart(
        failedSpent,
        try endpoints.configuration(ruleSets: [stalledSet], cacheFile: blockedCache),
        deadline: EngineStartDeadline(receivedAt: .now)),
      "a start that failed early and could not close never returned")
    stopIfStarted(failedSpent, ownFailure)
    guard case .failure(let ownError) = ownFailure,
      let ownCloseFailure = ownError as? LibboxInstanceUnclosable
    else {
      Issue.record("expected the failed start to report its failed close, got \(ownFailure)")
      return
    }
    #expect(stalled.acceptedConnections == 3, "a start that failed early downloaded its rule set")
    #expect(
      closeFailure(of: failedSpent) == ownCloseFailure,
      "the failed start did not leave the runtime spent")
  }
#endif

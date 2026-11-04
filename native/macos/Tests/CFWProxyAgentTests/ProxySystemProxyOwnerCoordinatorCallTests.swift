import CFWSharedProtocol
import Foundation
import Synchronization
import Testing

@testable import CFWCredentialTransport
@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Bounded checks and probes: calls past their reply, abandoned inside libbox,
// or that left their instance open, and the idle agent they retire.
// MARK: - Bounded checks and probes

/// Holds the first call of a fake check or probe inside "libbox" until the
/// test opens it; later calls return at once.
private final class FirstCallGate: @unchecked Sendable {
  private let lock = NSLock()
  private var calls = 0
  private let entered = DispatchSemaphore(value: 0)
  private let opened = DispatchSemaphore(value: 0)

  private let enteredLatch = AsyncTestLatch()

  func pass() {
    let first = lock.withLock { () -> Bool in
      calls += 1
      return calls == 1
    }
    guard first else { return }
    entered.signal()
    enteredLatch.signal()
    _ = opened.wait(timeout: .now() + .seconds(30))
  }

  func awaitEntry() -> Bool { entered.wait(timeout: .now() + .seconds(5)) == .success }
  /// Waits for the first call to enter without blocking a thread.
  func firstEntry() async throws { try await enteredLatch.wait() }
  func open() { opened.signal() }
  var callCount: Int { lock.withLock { calls } }
}

private struct GatedChecker: LibboxConfigurationChecking {
  let gate: FirstCallGate
  var failure: LibboxRuntimeError?

  func check(configuration: Data) throws {
    gate.pass()
    if let failure { throw failure }
  }
}

private struct GatedProbe: LibboxProfileProbing {
  let gate: FirstCallGate
  var failure: LibboxRuntimeError?

  func test(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) throws -> [ProfileProxyDelay] {
    gate.pass()
    if let failure { throw failure }
    return try proxies.map { try ProfileProxyDelay(name: $0, delay: 10, errorKind: nil) }
  }
}

/// Records each timer a bounded call arms, with its length, instead of
/// arming it; the test fires them.
private final class ManualCallTimers: @unchecked Sendable {
  private let lock = NSLock()
  private var armed: [(length: Duration, action: @Sendable () -> Void)] = []

  var afterAwake: LibboxStartWatchdog.AwakeTimer {
    { length, action in
      self.lock.withLock { self.armed.append((length, action)) }
      return {}
    }
  }

  var lengths: [Duration] { lock.withLock { armed.map(\.length) } }

  func fire(_ index: Int) {
    let action = lock.withLock { armed.indices.contains(index) ? armed[index].action : nil }
    guard let action else {
      Issue.record("no timer \(index) was armed")
      return
    }
    action()
  }
}

private final class XPCReplyRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [(Data?, NSError?)] = []
  private let replied = DispatchSemaphore(value: 0)

  private let repliedLatch = AsyncTestLatch()

  func record(_ data: Data?, _ error: NSError?) {
    lock.withLock { values.append((data, error)) }
    replied.signal()
    repliedLatch.signal()
  }

  func wait() -> Bool { replied.wait(timeout: .now() + .seconds(5)) == .success }
  /// Waits for the first reply without blocking a thread.
  func firstReply() async throws { try await repliedLatch.wait() }
  var first: (Data?, NSError?)? { lock.withLock { values.first } }
  var count: Int { lock.withLock { values.count } }
}

private func agentService(
  _ fixture: CoordinatorFixture, timers: ManualCallTimers, gate: FirstCallGate,
  checkFailure: LibboxRuntimeError? = nil, probeFailure: LibboxRuntimeError? = nil
) -> ProxyAgentService {
  ProxyAgentService(
    lifecycle: fixture.coordinator,
    configurationChecker: GatedChecker(gate: gate, failure: checkFailure),
    preferences: SCPreferencesSystemProxyPreferences(), journalStore: FakeJournalStore(),
    profileProbe: GatedProbe(gate: gate, failure: probeFailure),
    boundedCall: LibboxBoundedCall(
      afterAwake: timers.afterAwake, startCall: LibboxBoundedCall.onItsOwnQueue))
}

private func sendCheck(
  _ service: ProxyAgentService, _ descriptor: ConfigurationDescriptor
) throws -> XPCReplyRecorder {
  let recorder = XPCReplyRecorder()
  let request = RequestEnvelope(
    command: try NativeCommand(kind: .validateConfiguration, configuration: descriptor))
  service.validateConfiguration(Data("{}".utf8), request: try ProtocolCodec.encode(request)) {
    recorder.record($0, $1)
  }
  return recorder
}

/// The failure code a check's reply carries, or nil for an accepted check.
private func checkReplyCode(_ recorder: XPCReplyRecorder) throws -> String? {
  #expect(recorder.wait())
  let (data, error) = try #require(recorder.first)
  #expect(error == nil)
  let failure = try ProtocolCodec.decodeResponse(try #require(data)).failure
  if let failure { #expect(failure.isRetryable, "\(failure.code)") }
  return failure?.code
}

private func sendProbe(_ service: ProxyAgentService) throws -> XPCReplyRecorder {
  let recorder = XPCReplyRecorder()
  service.testProfileProxies(
    Data("{}".utf8), proxies: try JSONEncoder().encode(["p"]), timeoutMS: 500, targetURL: "",
    expectedStatus: ""
  ) { recorder.record($0, $1) }
  return recorder
}

/// The failure a probe's reply carries, or nil for a result.
private func probeReplyFailure(_ recorder: XPCReplyRecorder) throws -> ProfileProbeServiceFailure? {
  #expect(recorder.wait())
  return try probeFailure(of: recorder)
}

/// The failure a probe's reply carries, or nil for a result, awaited without
/// blocking a thread on the probe's lower-priority queue.
private func awaitedProbeFailure(
  _ recorder: XPCReplyRecorder
) async throws -> ProfileProbeServiceFailure? {
  try await recorder.firstReply()
  return try probeFailure(of: recorder)
}

private func probeFailure(of recorder: XPCReplyRecorder) throws -> ProfileProbeServiceFailure? {
  let (data, error) = try #require(recorder.first)
  guard let error else {
    #expect(data != nil)
    return nil
  }
  #expect(error.domain == ProfileProbeServiceFailure.domain)
  return ProfileProbeServiceFailure(rawValue: error.code)
}

extension ProxySystemProxyOwnerCoordinatorTests {
  /// A check still inside libbox at its reply answers with a timeout that may
  /// be retried, and keeps every later check out until it returns. One that
  /// returns before the limit retires nothing.
  @Test func aCheckPastItsReplyAnswersTimedOutAndKeepsTheNextOutUntilItReturns() throws {
    let fixture = try makeFixture()
    let timers = ManualCallTimers()
    let gate = FirstCallGate()
    let service = agentService(fixture, timers: timers, gate: gate)
    let held = try sendCheck(service, fixture.descriptor)
    #expect(gate.awaitEntry())
    #expect(held.count == 0)
    #expect(timers.lengths == [ProxyAgentCallBudget.configurationCheckReply])
    timers.fire(0)
    #expect(try checkReplyCode(held) == "configuration-check-timed-out")
    #expect(
      timers.lengths == [
        ProxyAgentCallBudget.configurationCheckReply, ProxyAgentCallBudget.abandonAfterReply,
      ])
    #expect(
      try checkReplyCode(try sendCheck(service, fixture.descriptor))
        == "configuration-check-timed-out")
    #expect(gate.callCount == 1)

    gate.open()
    let admittedBy = ContinuousClock.now.advanced(by: .seconds(2))
    var code: String? = "configuration-check-timed-out"
    while code == "configuration-check-timed-out", ContinuousClock.now < admittedBy {
      Thread.sleep(forTimeInterval: 0.01)
      code = try checkReplyCode(try sendCheck(service, fixture.descriptor))
    }
    #expect(code == nil)
    timers.fire(1)
    #expect(fixture.coordinator.callsLibbox)
    #expect(fixture.processEnds.values.isEmpty)
  }

  /// A check still inside libbox at its limit is abandoned: the idle agent
  /// retires and ends, and refuses every later check, probe and start before
  /// libbox or the Authority, with errors that may be retried.
  @Test func aCheckAbandonedInsideLibboxRetiresTheIdleAgent() throws {
    let fixture = try makeFixture()
    let timers = ManualCallTimers()
    let gate = FirstCallGate()
    defer { gate.open() }
    let service = agentService(fixture, timers: timers, gate: gate)
    let held = try sendCheck(service, fixture.descriptor)
    #expect(gate.awaitEntry())
    timers.fire(0)
    #expect(try checkReplyCode(held) == "configuration-check-timed-out")
    timers.fire(1)
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.retired(LibboxInstanceUnclosable(.callDidNotReturn))])
    #expect(!fixture.coordinator.callsLibbox)

    #expect(
      try checkReplyCode(try sendCheck(service, fixture.descriptor)) == "proxy-agent-ending")
    #expect(try probeReplyFailure(try sendProbe(service)) == .agentEnding)
    #expect(gate.callCount == 1)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [.failure(.agentEnding)])
    #expect(fixture.authority.bindCount == 0)
  }

  /// A probe still inside libbox at its limit is abandoned the same way: the
  /// idle agent retires and ends.
  @Test(.timeLimit(.minutes(1)))
  func aProbeAbandonedInsideLibboxRetiresTheIdleAgent() async throws {
    let fixture = try makeFixture()
    let timers = ManualCallTimers()
    let gate = FirstCallGate()
    defer { gate.open() }
    let service = agentService(fixture, timers: timers, gate: gate)
    let held = try sendProbe(service)
    try await gate.firstEntry()
    timers.fire(0)
    #expect(try await awaitedProbeFailure(held) == .timedOut)
    timers.fire(1)
    try await fixture.processEnds.firstEnd()
    #expect(fixture.processEnds.values == [.retired(LibboxInstanceUnclosable(.callDidNotReturn))])
    #expect(!fixture.coordinator.callsLibbox)
  }

  /// A probe still inside libbox at its reply answers with a timeout that may
  /// be retried, and the next probe is busy until the first returns. Probes
  /// run on a utility queue, so the test awaits their work instead of
  /// blocking on it.
  @Test(.timeLimit(.minutes(1)))
  func aProbePastItsReplyAnswersTimedOutAndKeepsTheNextOutUntilItReturns() async throws {
    let fixture = try makeFixture()
    let timers = ManualCallTimers()
    let gate = FirstCallGate()
    let service = agentService(fixture, timers: timers, gate: gate)
    let held = try sendProbe(service)
    try await gate.firstEntry()
    #expect(
      timers.lengths == [.milliseconds(500) + ProxyAgentCallBudget.profileProbeReplyAllowance])
    timers.fire(0)
    #expect(try probeReplyFailure(held) == .timedOut)
    #expect(try probeReplyFailure(try sendProbe(service)) == .busy)

    gate.open()
    let admittedBy = ContinuousClock.now.advanced(by: .seconds(2))
    var failure: ProfileProbeServiceFailure? = .busy
    while failure == .busy, ContinuousClock.now < admittedBy {
      try await Task.sleep(for: .milliseconds(10))
      failure = try await awaitedProbeFailure(try sendProbe(service))
    }
    #expect(failure == nil)
    #expect(fixture.coordinator.callsLibbox)
  }

  /// A probe whose instance libbox could not close leaves it in this process,
  /// so the idle agent retires and ends.
  @Test(.timeLimit(.minutes(1)))
  func aProbeThatLeftItsInstanceOpenRetiresTheIdleAgent() async throws {
    let fixture = try makeFixture()
    let gate = FirstCallGate()
    gate.open()
    let service = agentService(
      fixture, timers: ManualCallTimers(), gate: gate,
      probeFailure: .profileProbeCleanupFailed(LibboxDiagnostic("close: outbound")))
    let probe = try sendProbe(service)
    #expect(try await awaitedProbeFailure(probe) == .executionFailed)
    try await fixture.processEnds.firstEnd()
    #expect(
      fixture.processEnds.values == [
        .retired(LibboxInstanceUnclosable(closeFailure: "close: outbound"))
      ])
    #expect(!fixture.coordinator.callsLibbox)
  }

  /// A check or probe that returned only after its timed-out answer, its
  /// instance left open, retires the idle agent when it returns.
  @Test(.timeLimit(.minutes(1)), arguments: [false, true])
  func aCallThatLeftItsInstanceOpenAfterItsAnswerRetiresTheIdleAgent(probe: Bool) async throws {
    let fixture = try makeFixture()
    let timers = ManualCallTimers()
    let gate = FirstCallGate()
    let service = agentService(
      fixture, timers: timers, gate: gate,
      checkFailure: .configurationCheckCleanupFailed(LibboxDiagnostic("close: outbound")),
      probeFailure: .profileProbeCleanupFailed(LibboxDiagnostic("close: outbound")))
    if probe {
      let held = try sendProbe(service)
      try await gate.firstEntry()
      timers.fire(0)
      #expect(try await awaitedProbeFailure(held) == .timedOut)
    } else {
      let held = try sendCheck(service, fixture.descriptor)
      try await gate.firstEntry()
      timers.fire(0)
      #expect(try checkReplyCode(held) == "configuration-check-timed-out")
    }
    #expect(fixture.coordinator.callsLibbox)
    gate.open()
    try await fixture.processEnds.firstEnd()
    #expect(
      fixture.processEnds.values == [
        .retired(LibboxInstanceUnclosable(closeFailure: "close: outbound"))
      ])
    #expect(!fixture.coordinator.callsLibbox)
  }
}

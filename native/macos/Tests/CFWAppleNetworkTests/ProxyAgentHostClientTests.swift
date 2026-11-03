import CFWSharedProtocol
import CryptoKit
import Foundation
import Security
import Testing

@testable import CFWAppleNetwork

// The host's connection to the ProxyAgent: rotation and retirement, reply
// deadlines and the outstanding reply bound, and authorized starts.
private final class ProxyConnectionHarness: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [NSXPCConnection] = []
  private var requirements: [String] = []
  private var callbacks: [@Sendable (Result<Data, Error>) -> Void] = []
  private var responses: [Data] = []
  private var startRequests: [ProxyAgentStartRequest] = []
  private var startReplies: [@Sendable (Result<Data, Error>) -> Void] = []
  private var commands: [NativeCommand] = []
  let entered = ProxyAgentTestLatch()
  let startEntered = ProxyAgentTestLatch()
  let holdFirst: Bool

  init(holdFirst: Bool = false) { self.holdFirst = holdFirst }
  var connections: [NSXPCConnection] { lock.withLock { values } }
  var requirementValues: [String] { lock.withLock { requirements } }
  var requestCount: Int { lock.withLock { callbacks.count } }
  func reply(_ index: Int) {
    let pair = lock.withLock { (callbacks[index], responses[index]) }
    pair.0(.success(pair.1))
  }
  var recordedStartRequests: [ProxyAgentStartRequest] { lock.withLock { startRequests } }
  /// Each command the transport executed, in order.
  var executedCommands: [NativeCommand] { lock.withLock { commands } }
  func acceptStart(_ index: Int) throws {
    let (request, reply) = lock.withLock { (startRequests[index], startReplies[index]) }
    let envelope = try ProtocolCodec.decodeRequest(request.request)
    reply(
      .success(
        try JSONEncoder().encode(
          Installed40019TestResponseEnvelope(
            schemaVersion: NativeProtocolConstants.schemaVersion,
            requestID: envelope.requestID,
            result: try CommandResult(kind: .accepted)))))
  }
  var dependencies: ProxyAgentConnectionDependencies {
    .init(
      makeConnection: { _ in
        let connection = NSXPCConnection(
          machServiceName: "com.bill.clashformac.tests.never-activated")
        self.lock.withLock { self.values.append(connection) }
        return connection
      },
      prepareConnection: { _, requirement in
        self.lock.withLock { self.requirements.append(requirement) }
      },
      activateConnection: { _ in },
      execute: { _, data, reply in
        do {
          let request = try ProtocolCodec.decodeRequest(data)
          let result =
            request.command.kind == .snapshot
            ? try CommandResult(kind: .snapshot, snapshot: .off(sequence: 1))
            : try CommandResult(kind: .accepted)
          let response = try JSONEncoder().encode(
            Installed40019TestResponseEnvelope(
              schemaVersion: NativeProtocolConstants.schemaVersion,
              requestID: request.requestID,
              result: result))
          let index = self.lock.withLock {
            self.commands.append(request.command)
            self.callbacks.append(reply)
            self.responses.append(response)
            return self.callbacks.count - 1
          }
          self.entered.signal()
          if !self.holdFirst || index != 0 { reply(.success(response)) }
        } catch { reply(.failure(error)) }
      },
      startSystemProxy: { _, request, reply in
        self.lock.withLock {
          self.startRequests.append(request)
          self.startReplies.append(reply)
        }
        self.startEntered.signal()
      })
  }
}

private func connectionTestTransport(_ harness: ProxyConnectionHarness) throws
  -> AuthenticatedProxyAgentTransport
{
  try AuthenticatedProxyAgentTransport(
    machServiceName: "com.bill.clashformac.proxy-agent", teamIdentifier: "YKUPL7Z869",
    proxyAgentBundleIdentifier: "com.bill.clashformac.proxy-agent",
    currentCodeHash: try ServiceCodeHash(Data(repeating: 0x42, count: 20)),
    serviceController: FixedProxyAgentServiceController(status: .enabled),
    replyTimeout: .milliseconds(200),
    connectionDependencies: harness.dependencies)
}

/// Arms a manual deadline for every reply wait and records the length each
/// wait asked for, so a test can check which bound a request waits on.
private final class RecordedReplyDeadlines: @unchecked Sendable {
  private let lock = NSLock()
  private var waits: [(length: Duration, deadline: ManualDeadlineScheduler)] = []

  var make: @Sendable (Duration) -> CallbackDeadlineScheduler {
    { length in
      let deadline = ManualDeadlineScheduler()
      self.lock.withLock { self.waits.append((length, deadline)) }
      return deadline.scheduler
    }
  }

  var lengths: [Duration] { lock.withLock { waits.map(\.length) } }

  func fire(_ index: Int) {
    let deadline = lock.withLock { waits[index].deadline }
    deadline.fire(at: 0)
  }

  func isCancelled(_ index: Int) -> Bool {
    let deadline = lock.withLock { waits[index].deadline }
    return deadline.isCancelled(at: 0)
  }
}

private func deadlineTestTransport(
  _ harness: ProxyConnectionHarness, deadlines: RecordedReplyDeadlines
) throws -> AuthenticatedProxyAgentTransport {
  try AuthenticatedProxyAgentTransport(
    machServiceName: "com.bill.clashformac.proxy-agent", teamIdentifier: "YKUPL7Z869",
    proxyAgentBundleIdentifier: "com.bill.clashformac.proxy-agent",
    currentCodeHash: try ServiceCodeHash(Data(repeating: 0x42, count: 20)),
    serviceController: FixedProxyAgentServiceController(status: .enabled),
    makeReplyDeadline: deadlines.make,
    connectionDependencies: harness.dependencies)
}

/// Awaits `task`, cancelling it when the waiting test is cancelled, so a test's
/// time limit also ends a start that never returns.
private func outcome<Value: Sendable>(of task: Task<Value, any Error>) async throws -> Value {
  try await withTaskCancellationHandler {
    try await task.value
  } onCancel: {
    task.cancel()
  }
}

private struct ProxyStartFixture: Sendable {
  let configuration: Data
  let descriptor: ConfigurationDescriptor
  let authorization: HostPreparedSystemProxyStart
}

private func proxyStartFixture() throws -> ProxyStartFixture {
  let configuration = Data(
    #"{"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}"#.utf8)
  let descriptor = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: try appleCredentialAudience(),
    installationID: UUID(),
    epoch: 1,
    generation: 1,
    byteCount: UInt64(configuration.count),
    sha256: SHA256Digest(
      hex: SHA256.hash(data: configuration).map { String(format: "%02x", $0) }.joined()))
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(descriptor.installationID),
      epoch: descriptor.epoch,
      generation: descriptor.generation),
    mode: .systemProxy,
    configSHA256: descriptor.sha256,
    identitySHA256: descriptor.identitySHA256,
    ownerUID: 501,
    authorityRevision: 1)
  return ProxyStartFixture(
    configuration: configuration,
    descriptor: descriptor,
    authorization: HostPreparedSystemProxyStart(
      context: try ProxyOwnerContext(operation: operation, leaseID: AuthorityIdentifier(UUID())),
      capability: try OwnerCapability(
        copying: Data(repeating: 0x5, count: AuthorityV1Limits.capabilityBytes))))
}

@Suite(.serialized)
struct ProxyAgentHostClientTests {
  @Test(arguments: [false, true])
  func nativeConnectionEventRotatesOrdinarySnapshots(interrupted: Bool) async throws {
    let harness = ProxyConnectionHarness()
    let subject = try connectionTestTransport(harness)
    _ = try await subject.snapshot()
    let old = try #require(harness.connections.first)
    let event = try #require(interrupted ? old.interruptionHandler : old.invalidationHandler)
    let lateInvalidation = try #require(old.invalidationHandler)
    event()
    #expect(harness.requestCount == 1)
    _ = try await subject.snapshot()
    #expect(harness.connections.count == 2)
    #expect(harness.requestCount == 2)
    lateInvalidation()
    event()
    _ = try await subject.snapshot()
    #expect(harness.connections.count == 2)
    #expect(harness.requestCount == 3)
    #expect(harness.requirementValues.first == harness.requirementValues.last)
    #expect(harness.requirementValues.first?.contains("YKUPL7Z869") == true)
    #expect(harness.requirementValues.first?.contains("com.bill.clashformac.proxy-agent") == true)
  }

  @Test(arguments: [false, true])
  func nativeConnectionEventTerminatesInflightWithoutReplay(interrupted: Bool) async throws {
    let harness = ProxyConnectionHarness(holdFirst: true)
    let subject = try connectionTestTransport(harness)
    let pending = Task { try await subject.snapshot() }
    try await harness.entered.wait()
    let old = try #require(harness.connections.first)
    // Optional invocation lets the old implementation reach its bounded timeout,
    // proving the missing handler instead of leaving the test task unjoined.
    let event = interrupted ? old.interruptionHandler : old.invalidationHandler
    event?()
    do {
      _ = try await pending.value
      Issue.record("A retired request unexpectedly succeeded")
    } catch {
      #expect(error as? ProxyAgentHostError == .transportUnavailable("connection-retired"))
    }
    #expect(event != nil)
    #expect(harness.requestCount == 1)
    _ = try await subject.snapshot()
    #expect(harness.connections.count == 2)
    harness.reply(0)
    event?()
    _ = try await subject.snapshot()
    #expect(harness.connections.count == 2)
    #expect(harness.requestCount == 3)
  }

  /// Every production reply wait arms a real timer that fires after the length
  /// the wait asked for and no later than its leeway allows. The test awaits the
  /// firing instead of blocking a thread on the timer's queue.
  @Test func productionReplyDeadlineFiresAfterItsLength() async throws {
    let log = DeadlineFiringLog()
    let length = Duration.seconds(1)
    let armed = ContinuousClock.now
    let cancel = AuthenticatedProxyAgentTransport.productionReplyDeadline(length).schedule {
      log.record()
    }
    let firing = try await log.firstFiring(within: .seconds(5))
    let firedAt = try #require(firing, "the reply deadline never fired")
    let lateness = armed.duration(to: firedAt) - length
    #expect(lateness >= .zero)
    #expect(
      lateness < CallbackDeadlineScheduler.maximumLeeway + .milliseconds(400),
      "the deadline fired \(lateness) after its length")
    cancel()
  }

  /// The ProxyAgent answers a configuration check and a profile probe inside
  /// the Host's waits for them: its reply, its timer's tolerance and a second
  /// for delivering the request and the reply fit, for every probe timeout the
  /// protocol admits.
  @Test func theAgentsCheckAndProbeRepliesFitTheHostsWaits() {
    let delivery = Duration.seconds(1)
    #expect(
      ProxyAgentCallBudget.configurationCheckReply + EngineStartBudget.deadlineTolerance
        + delivery <= AuthenticatedProxyAgentTransport.defaultReplyTimeout)
    for timeoutMS in [UInt16(100), 101, 500, 1_000, 5_000, 9_999, 10_000] {
      #expect(
        .milliseconds(Int64(timeoutMS)) + ProxyAgentCallBudget.profileProbeReplyAllowance
          + EngineStartBudget.deadlineTolerance + delivery
          <= AuthenticatedProxyAgentTransport.profileProbeReplyTimeout(timeoutMS: timeoutMS),
        "\(timeoutMS)")
    }
    #expect(
      AuthenticatedProxyAgentTransport.profileProbeReplyTimeout(timeoutMS: 500)
        == .milliseconds(5_500))
  }

  /// The Host waits for a probe as long as that probe's own timeout allows,
  /// not for the ordinary reply wait.
  @Test(arguments: [UInt16(100), 10_000])
  func aProbeWaitsForItsOwnReplyTimeout(timeoutMS: UInt16) async throws {
    let harness = ProxyConnectionHarness()
    let deadlines = RecordedReplyDeadlines()
    let subject = try deadlineTestTransport(harness, deadlines: deadlines)
    // The harness's connections carry no ProxyAgent interface, so the probe
    // fails once it waited on its deadline.
    await #expect(throws: ProxyAgentHostError.self) {
      _ = try await subject.testProfileProxies(
        configuration: Data("{}".utf8), proxies: ["p"], timeoutMS: timeoutMS, targetURL: "",
        expectedStatus: "")
    }
    #expect(
      deadlines.lengths == [
        AuthenticatedProxyAgentTransport.profileProbeReplyTimeout(timeoutMS: timeoutMS)
      ])
  }

  /// A restore before a stop reaches the ProxyAgent as its own command, with
  /// the stop's exact configuration, over a connection that admits only this
  /// app's build, which alone understands it.
  @Test(.timeLimit(.minutes(1)))
  func aRestoreBeforeAStopIsItsOwnCommandForThisBuildOnly() async throws {
    let harness = ProxyConnectionHarness()
    let subject = try connectionTestTransport(harness)
    let fixture = try proxyStartFixture()
    _ = try await subject.snapshot()
    try await subject.restoreSettingsBeforeStop(configuration: fixture.descriptor)
    let commands = harness.executedCommands
    #expect(commands.map(\.kind) == [.snapshot, .restoreSettingsBeforeStop])
    #expect(commands.last?.configuration == fixture.descriptor)
    let currentBuild = "cdhash H\"" + String(repeating: "42", count: 20) + "\""
    #expect(harness.requirementValues.first?.contains(currentBuild) == false)
    #expect(harness.requirementValues.last?.contains(currentBuild) == true)
  }

  @Test(.timeLimit(.minutes(1)))
  func authorizedStartWaitsOnlyForTheEngineStartReplyDeadline() async throws {
    let harness = ProxyConnectionHarness()
    let deadlines = RecordedReplyDeadlines()
    let subject = try deadlineTestTransport(harness, deadlines: deadlines)
    let fixture = try proxyStartFixture()
    let pending = Task {
      try await subject.start(
        configuration: fixture.configuration,
        descriptor: fixture.descriptor,
        authorization: fixture.authorization)
    }
    defer { pending.cancel() }
    try await harness.startEntered.wait()
    try #require(deadlines.lengths == [EngineStartBudget.proxyAgentStartReply])
    deadlines.fire(0)
    await #expect(throws: ProxyAgentHostError.transportTimedOut) {
      try await outcome(of: pending)
    }

    _ = try await subject.snapshot()
    try await subject.stop(configuration: fixture.descriptor)
    #expect(
      deadlines.lengths == [
        EngineStartBudget.proxyAgentStartReply,
        AuthenticatedProxyAgentTransport.defaultReplyTimeout,
        AuthenticatedProxyAgentTransport.defaultReplyTimeout,
      ])
  }

  @Test(.timeLimit(.minutes(1)))
  func authorizedStartForwardsTheExactAuthorizationAndAcceptsTheAgentReply() async throws {
    let harness = ProxyConnectionHarness()
    let deadlines = RecordedReplyDeadlines()
    let subject = try deadlineTestTransport(harness, deadlines: deadlines)
    let fixture = try proxyStartFixture()
    let expectedContext = try AuthorityV1Codec.encodeCanonical(fixture.authorization.context)
    let pending = Task {
      try await subject.start(
        configuration: fixture.configuration,
        descriptor: fixture.descriptor,
        authorization: fixture.authorization)
    }
    defer { pending.cancel() }
    try await harness.startEntered.wait()
    let forwarded = try #require(harness.recordedStartRequests.first)
    #expect(forwarded.capability == Data(repeating: 0x5, count: AuthorityV1Limits.capabilityBytes))
    #expect(forwarded.context == expectedContext)
    #expect(forwarded.configuration == fixture.configuration)
    let request = try ProtocolCodec.decodeRequest(forwarded.request)
    #expect(request.command.kind == .startSystemProxy)
    #expect(request.command.configuration == fixture.descriptor)

    try harness.acceptStart(0)
    try await outcome(of: pending)
    try #require(deadlines.lengths == [EngineStartBudget.proxyAgentStartReply])
    #expect(deadlines.isCancelled(0), "the start reply must cancel its deadline")
    deadlines.fire(0)
    #expect(harness.recordedStartRequests.count == 1)
  }

  @Test func outstandingReplyRegistryAppliesExactBoundAndReleasesCapacity() throws {
    var registry = BoundedProxyAgentRequestRegistry(maximum: 2)
    let first = try registry.reserve()
    let second = try registry.reserve()
    #expect(registry.tokens.count == 2)
    #expect(throws: ProxyAgentHostError.transportCapacityExceeded) {
      _ = try registry.reserve()
    }

    registry.release(first)
    let replacement = try registry.reserve()
    #expect(registry.tokens == [second, replacement])
    registry.release(UUID())
    #expect(registry.tokens.count == 2)
  }

  @Test func timeoutCancellationTransportLossAndProtocolDriftRequireConnectionRotation() {
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.transportTimedOut))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.transportUnavailable("injected")))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: CancellationError()))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.malformedResponse))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.responseMismatch))
    #expect(
      !AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.transportCapacityExceeded))
  }

  @Test func retiringAConnectionFailsEveryConcurrentRequestAndInvalidatesExactlyOnce() {
    let invalidations = ProxyAgentTestCounter()
    let failures = ProxyAgentTestCounter()
    let lifecycle = ProxyAgentConnectionLifecycle {
      invalidations.increment()
    }
    let first = UUID()
    let second = UUID()
    #expect(lifecycle.register(token: first) { failures.increment() })
    #expect(lifecycle.register(token: second) { failures.increment() })
    #expect(lifecycle.pendingCount == 2)

    lifecycle.retire()
    lifecycle.retire()
    #expect(lifecycle.isRetired)
    #expect(lifecycle.pendingCount == 0)
    #expect(failures.count == 2)
    #expect(invalidations.count == 1)

    #expect(!lifecycle.register(token: UUID()) { failures.increment() })
    #expect(failures.count == 3)
  }

  @Test func lateReplyOnRetiredConnectionCannotCompleteReplacementGeneration() async throws {
    let oldLifecycle = ProxyAgentConnectionLifecycle {}
    let oldGate = CallbackContinuationGate<Int>()
    let oldInstalled = ProxyAgentTestLatch()
    let oldToken = UUID()
    let oldTask = Task<Int, Error> {
      try await withCheckedThrowingContinuation { continuation in
        oldGate.install(continuation)
        #expect(
          oldLifecycle.register(token: oldToken) {
            oldGate.finish(
              .failure(ProxyAgentHostError.transportUnavailable("connection-retired"))
            )
          }
        )
        oldInstalled.signal()
      }
    }
    try await oldInstalled.wait()
    oldLifecycle.retire()
    await #expect(throws: ProxyAgentHostError.self) {
      _ = try await oldTask.value
    }

    let replacementGate = CallbackContinuationGate<Int>()
    let replacementInstalled = ProxyAgentTestLatch()
    let replacementTask = Task<Int, Error> {
      try await withCheckedThrowingContinuation { continuation in
        replacementGate.install(continuation)
        replacementInstalled.signal()
      }
    }
    try await replacementInstalled.wait()
    oldGate.finish(.success(1))
    replacementGate.finish(.success(2))
    #expect(try await replacementTask.value == 2)
  }
}

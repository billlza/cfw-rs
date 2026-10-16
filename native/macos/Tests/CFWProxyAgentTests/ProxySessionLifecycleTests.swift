import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

private enum ForcedProxyFailure: Error {
  case requested
}

private struct SecretEchoFailure: LocalizedError {
  let secret: String
  var errorDescription: String? { "libbox echoed secret: \(secret)" }
}

private struct SecretEchoConfigurationChecker: LibboxConfigurationChecking {
  let secret: String

  func check(configuration: Data) throws {
    _ = configuration
    throw SecretEchoFailure(secret: secret)
  }
}

/// Keeps this validation-only service test behind the same Authority-owned
/// surface as production. An accidental start fails explicitly instead of
/// bypassing the one-use owner authorization contract.
private final class ValidationOnlyProxyOwner: ProxySystemProxyOwning, @unchecked Sendable {
  private let lifecycle: ProxySessionLifecycle
  private let lock = NSLock()
  private var startCountValue = 0

  init(lifecycle: ProxySessionLifecycle) {
    self.lifecycle = lifecycle
  }

  func start(
    configuration: SensitiveDataBuffer,
    descriptor: ConfigurationDescriptor,
    authorization: ProxyOwnerAuthorization,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    lock.withLock { startCountValue += 1 }
    configuration.erase()
    _ = descriptor
    authorization.erase()
    completionHandler(
      .failure(.engineLease("Validation-only owner cannot authorize a start.")))
  }

  var startCount: Int { lock.withLock { startCountValue } }

  func stop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    lifecycle.stop(
      expectedConfiguration: expectedConfiguration,
      completionHandler: completionHandler)
  }

  func snapshot(
    completionHandler: @escaping @Sendable (EngineSnapshot) -> Void
  ) {
    lifecycle.snapshot(completionHandler: completionHandler)
  }

  func restoreSettingsAfterAuthorization(completionHandler: @escaping @Sendable () -> Void) {
    lifecycle.restoreSettingsAfterAuthorization(completionHandler: completionHandler)
  }
}

@Test func proxyStartRejectsMismatchedRuntimeBytesBeforeOwnerBinding() throws {
  let owner = ValidationOnlyProxyOwner(lifecycle: makeFixture().lifecycle)
  let service = ProxyAgentService(
    lifecycle: owner,
    configurationChecker: SecretEchoConfigurationChecker(secret: "unused"),
    preferences: SCPreferencesSystemProxyPreferences(),
    journalStore: FakeJournalStore()
  )
  let configurationDescriptor = try descriptor()
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(configurationDescriptor.installationID),
      epoch: configurationDescriptor.epoch,
      generation: configurationDescriptor.generation),
    mode: .systemProxy,
    configSHA256: configurationDescriptor.sha256,
    identitySHA256: configurationDescriptor.identitySHA256,
    ownerUID: 501,
    authorityRevision: 1)
  let context = try ProxyOwnerContext(
    operation: operation,
    leaseID: AuthorityIdentifier(UUID()))
  let request = RequestEnvelope(
    command: try NativeCommand(
      kind: .startSystemProxy,
      configuration: configurationDescriptor))
  var responseData: Data?
  var responseError: NSError?

  service.startSystemProxy(
    Data(repeating: 0x5, count: AuthorityV1Limits.capabilityBytes),
    context: try AuthorityV1Codec.encodeCanonical(context),
    configuration: Data("{}".utf8),
    request: try ProtocolCodec.encode(request)
  ) { data, error in
    responseData = data
    responseError = error
  }

  #expect(responseError == nil)
  let response = try ProtocolCodec.decodeResponse(try #require(responseData))
  #expect(response.failure?.code == "invalid-runtime-configuration")
  #expect(owner.startCount == 0)
}

/// Holds the send barrier a connection runs once its earlier sends went out.
private final class HeldSendBarrier: ProxyAgentSendBarrier, @unchecked Sendable {
  private let lock = NSLock()
  private var barrier: (@Sendable () -> Void)?

  func scheduleSendBarrierBlock(_ block: @escaping @Sendable () -> Void) {
    lock.withLock { barrier = block }
  }

  var isScheduled: Bool { lock.withLock { barrier != nil } }

  func sendPendingMessages() {
    let barrier = lock.withLock { () -> (@Sendable () -> Void)? in
      let block = self.barrier
      self.barrier = nil
      return block
    }
    barrier?()
  }
}

private final class ExitRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let exited = DispatchSemaphore(value: 0)
  private var statuses: [Int32] = []

  func record(_ status: Int32) {
    lock.withLock { statuses.append(status) }
    exited.signal()
  }

  func wait(for timeout: DispatchTimeInterval = .seconds(1)) -> Bool {
    exited.wait(timeout: .now() + timeout) == .success
  }

  var values: [Int32] { lock.withLock { statuses } }
}

/// Records each wait the process end asks for instead of waiting, so each test
/// decides when it ends.
private final class ManualExitClock: @unchecked Sendable {
  private let lock = NSLock()
  private var current: DispatchTime
  private var scheduled: [(deadline: DispatchTime, work: @Sendable () -> Void)] = []

  init(_ start: DispatchTime) { current = start }

  var now: @Sendable () -> DispatchTime { { self.lock.withLock { self.current } } }

  var schedule: ProxyAgentProcessExit.Schedule {
    { deadline, work in self.lock.withLock { self.scheduled.append((deadline, work)) } }
  }

  var deadlines: [DispatchTime] { lock.withLock { scheduled.map(\.deadline) } }

  func move(to instant: DispatchTime) { lock.withLock { current = instant } }

  /// Runs the `index`-th scheduled work, as its timer would.
  func fire(_ index: Int) {
    let work = lock.withLock { scheduled[index].work }
    work()
  }
}

private let launch = DispatchTime(uptimeNanoseconds: 1_000_000_000_000)
private let unclosable = LibboxInstanceUnclosable(closeFailure: "close network: monitor")

private func processExit(
  _ clock: ManualExitClock, connections: [HeldSendBarrier], exits: ExitRecorder
) -> ProxyAgentProcessExit {
  ProxyAgentProcessExit(
    openConnections: { connections.map { $0 as any ProxyAgentSendBarrier } },
    launchedAt: launch, now: clock.now,
    schedule: clock.schedule, exit: { exits.record($0) })
}

@Test func endingTheAgentExitsOnlyOnceEveryOpenConnectionSentItsReplies() {
  let first = HeldSendBarrier()
  let second = HeldSendBarrier()
  let exits = ExitRecorder()
  let clock = ManualExitClock(launch + .seconds(60))
  processExit(clock, connections: [first, second], exits: exits).end(after: unclosable)
  // It has run long enough already, so it sends its replies at once.
  #expect(clock.deadlines == [launch + .seconds(60)])
  clock.fire(0)
  #expect(first.isScheduled)
  #expect(second.isScheduled)
  first.sendPendingMessages()
  #expect(!exits.wait(for: .milliseconds(200)), "the agent exited before every reply was sent")
  second.sendPendingMessages()
  #expect(exits.wait())
  #expect(exits.values == [EX_SOFTWARE])
}

@Test func endingTheAgentWithoutAnOpenConnectionExitsAtOnce() {
  let exits = ExitRecorder()
  let clock = ManualExitClock(launch + .seconds(60))
  processExit(clock, connections: [], exits: exits).end(after: unclosable)
  clock.fire(0)
  #expect(exits.wait())
  #expect(exits.values == [EX_SOFTWARE])
}

/// launchd starts an on-demand agent again no sooner than its restart throttle
/// after it last started it, and holds every request for it until then, past
/// the Host's five-second reply wait. A spent agent that started recently keeps
/// answering until its successor can start at once.
@Test func aRecentlyStartedAgentEndsOnlyWhenLaunchdWouldStartItAgainAtOnce() {
  #expect(ProxyAgentProcessExit.launchdRestartThrottle == .seconds(10))
  #expect(ProxyAgentProcessExit.minimumLifetime == .seconds(11))
  let exits = ExitRecorder()
  let clock = ManualExitClock(launch + .seconds(3))
  processExit(clock, connections: [], exits: exits).end(after: unclosable)
  #expect(clock.deadlines == [launch + ProxyAgentProcessExit.minimumLifetime])
  #expect(!exits.wait(for: .milliseconds(100)))
  clock.move(to: launch + ProxyAgentProcessExit.minimumLifetime)
  clock.fire(0)
  #expect(exits.wait())
  #expect(exits.values == [EX_SOFTWARE])
}

/// A connection whose earlier sends never go out holds replies its Host has
/// stopped waiting for, so the agent ends once the limit passed, and only once.
@Test func aConnectionThatNeverSendsItsRepliesDelaysTheEndOnlyUntilTheLimit() throws {
  #expect(ProxyAgentProcessExit.sendBarrierLimit == .seconds(5))
  let stuck = HeldSendBarrier()
  let exits = ExitRecorder()
  let ended = launch + .seconds(30)
  let clock = ManualExitClock(ended)
  processExit(clock, connections: [stuck], exits: exits).end(after: unclosable)
  clock.fire(0)
  #expect(stuck.isScheduled)
  try #require(clock.deadlines == [ended, ended + ProxyAgentProcessExit.sendBarrierLimit])
  #expect(!exits.wait(for: .milliseconds(100)))
  clock.fire(1)
  #expect(exits.wait())
  stuck.sendPendingMessages()
  #expect(!exits.wait(for: .milliseconds(100)), "the agent ended twice")
  #expect(exits.values == [EX_SOFTWARE])
}

/// The agent's launchd job sets no restart throttle of its own, so launchd's
/// default is the one the process end waits out.
@Test func proxyAgentJobKeepsLaunchdsDefaultRestartThrottle() throws {
  let plist = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("Config/com.bill.clashformac.proxy-agent.plist")
  let job = try #require(
    try PropertyListSerialization.propertyList(from: Data(contentsOf: plist), format: nil)
      as? [String: Any])
  #expect(job["Label"] as? String == "com.bill.clashformac.proxy-agent")
  #expect(job["ThrottleInterval"] == nil)
  #expect(job["KeepAlive"] == nil, "launchd would restart the ended agent on its own")
  #expect((job["MachServices"] as? [String: Any])?["com.bill.clashformac.proxy-agent"] != nil)
}

@objc private protocol ConnectionProbe {
  func ping(withReply reply: @escaping @Sendable () -> Void)
}

private final class ConnectionProbeService: NSObject, ConnectionProbe {
  func ping(withReply reply: @escaping @Sendable () -> Void) { reply() }
}

private final class TrackingListenerDelegate: NSObject, NSXPCListenerDelegate {
  private let connections: ProxyAgentConnections
  private let service = ConnectionProbeService()

  init(connections: ProxyAgentConnections) {
    self.connections = connections
  }

  func listener(
    _ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection
  ) -> Bool {
    connection.exportedInterface = NSXPCInterface(with: ConnectionProbe.self)
    connection.exportedObject = service
    connections.track(connection)
    connection.resume()
    return true
  }
}

/// Ending the ProxyAgent waits for a send barrier on every connection it
/// tracks. A tracked connection runs one while open and leaves once
/// invalidated, and libxpc runs a barrier issued on a cancelled connection at
/// once, so a connection that ends while the agent ends cannot hold it back.
@Test(.timeLimit(.minutes(1)))
func trackedConnectionRunsSendBarriersAndLeavesWhenInvalidated() async throws {
  let connections = ProxyAgentConnections()
  let delegate = TrackingListenerDelegate(connections: connections)
  let listener = NSXPCListener.anonymous()
  listener.delegate = delegate
  listener.resume()
  defer { listener.invalidate() }
  let client = NSXPCConnection(listenerEndpoint: listener.endpoint)
  client.remoteObjectInterface = NSXPCInterface(with: ConnectionProbe.self)
  client.resume()
  let probe = try #require(
    client.remoteObjectProxyWithErrorHandler { _ in } as? any ConnectionProbe)
  await withCheckedContinuation { (replied: CheckedContinuation<Void, Never>) in
    probe.ping { replied.resume() }
  }
  let open = connections.open
  #expect(open.count == 1)
  let accepted = try #require(open.first)
  await withCheckedContinuation { (sent: CheckedContinuation<Void, Never>) in
    accepted.scheduleSendBarrierBlock { sent.resume() }
  }

  client.invalidate()
  let deadline = ContinuousClock.now.advanced(by: .seconds(2))
  while !connections.open.isEmpty, ContinuousClock.now < deadline {
    try await Task.sleep(for: .milliseconds(10))
  }
  #expect(connections.open.isEmpty)
  await withCheckedContinuation { (ran: CheckedContinuation<Void, Never>) in
    accepted.scheduleSendBarrierBlock { ran.resume() }
  }
  withExtendedLifetime(delegate) {}
}

/// Test-only adapter that always supplies a fresh one-use in-memory template.
/// Production has no descriptor-only start overload and cannot read a template
/// back from disk.
extension ProxySessionLifecycle {
  fileprivate func start(
    configuration descriptor: ConfigurationDescriptor,
    completionHandler:
      @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    start(
      configuration: SensitiveDataBuffer(copying: Data("{}".utf8)),
      descriptor: descriptor,
      deadline: EngineStartDeadline(receivedAt: .now),
      completionHandler: completionHandler)
  }
}

/// Every failure the ProxyAgent reports, with the code and retry flag it
/// crosses XPC with. The Host decides by these alone, for example that a stop
/// without a session found an owner that ended while a stale stop did not.
private let lifecycleFailureWire: [(failure: ProxySessionLifecycleError, code: String)] = [
  (.invalidConfigurationSlot, "invalid-configuration-slot"),
  (.lifecycleConflict, "proxy-lifecycle-conflict"),
  (.startupCancelled, "proxy-startup-cancelled"),
  (.staleStopRequest, "stale-stop-request"),
  (.stopWithoutSession, "proxy-stop-without-session"),
  (.recoveryBlocked("detail"), "proxy-recovery-blocked"),
  (.authorizationRequired, "system-proxy-authorization-required"),
  (.engineLease("detail"), "proxy-engine-lease-failed"),
  (.configuration("detail"), "proxy-configuration-failed"),
  (.engineCreation("detail"), "proxy-engine-creation-failed"),
  (.engineStart("detail"), "proxy-engine-start-failed"),
  (.engineStartTimedOut, "proxy-engine-start-timed-out"),
  (.endpointConflict(role: .mixed, port: 7890), "mixed-endpoint-in-use"),
  (.endpointConflict(role: .controller, port: 9090), "controller-endpoint-in-use"),
  (.listenerReadinessTimedOut, "proxy-listener-readiness-timeout"),
  (.engineUnclosable(LibboxInstanceUnclosable(closeFailure: "detail")), "proxy-engine-unclosable"),
  (.engineFailed(ProxyEngineFailure(code: "detail", message: "detail")), "proxy-engine-crashed"),
  (.preferences("detail"), "system-proxy-preferences-failed"),
  (.existingSystemProxy, "existing-system-proxy"),
  (.ownershipJournal("detail"), "proxy-ownership-journal-failed"),
  (.ownershipConflict([]), "system-proxy-ownership-conflict"),
  (.cleanupFailed(original: "detail", cleanup: ["detail"]), "proxy-cleanup-failed"),
]

/// The engine protocol admits only lowercase letters, digits and hyphens in a
/// code, and a reply it cannot encode reaches the Host as a broken connection.
/// No lifecycle failure says a retry may succeed: each needs a new start or
/// the user's action.
@Test func everyLifecycleFailureCrossesXPCUnderItsOwnCode() throws {
  let failures =
    lifecycleFailureWire
    + AuthorityErrorCode.allCases.map { code in
      (
        failure: ProxySessionLifecycleError.authority(code),
        code: "authority-" + code.rawValue.replacingOccurrences(of: "_", with: "-")
      )
    }
  for (failure, code) in failures {
    let envelope = ResponseEnvelope(requestID: RequestID(), failure: failure.engineFailure)
    let encoded: Data
    do {
      encoded = try ProtocolCodec.encode(envelope)
    } catch {
      Issue.record("\(failure) cannot be sent to the Host: \(error)")
      continue
    }
    let received = try #require(try ProtocolCodec.decodeResponse(encoded).failure)
    #expect(received == failure.engineFailure)
    #expect(received.code == code, "\(failure)")
    #expect(!received.isRetryable, "\(failure)")
  }
}

/// A stop reaching an agent with no session and no record of the stop's
/// generation, as after its predecessor ended, is answered under the code the
/// Host takes for an ended owner.
@Test func aStopWithoutASessionCrossesXPCAsSuch() throws {
  let service = ProxyAgentService(
    lifecycle: ValidationOnlyProxyOwner(lifecycle: makeFixture().lifecycle),
    configurationChecker: SourceBuiltLibboxConfigurationChecker(),
    preferences: SCPreferencesSystemProxyPreferences(),
    journalStore: FakeJournalStore()
  )
  let request = RequestEnvelope(
    command: try NativeCommand(kind: .stop, configuration: descriptor()))
  let replied = DispatchSemaphore(value: 0)
  let reply = Mutex<(Data?, NSError?)>((nil, nil))
  service.execute(try ProtocolCodec.encode(request)) { data, error in
    reply.withLock { $0 = (data, error) }
    replied.signal()
  }
  #expect(replied.wait(timeout: .now() + 5) == .success)
  let (data, error) = reply.withLock { $0 }
  #expect(error == nil)
  let response = try ProtocolCodec.decodeResponse(try #require(data))
  #expect(response.requestID == request.requestID)
  let failure = try #require(response.failure)
  #expect(failure.code == "proxy-stop-without-session")
  #expect(!failure.isRetryable)
}

/// libbox's close text can name servers and paths. However an error that
/// carries it is printed, described or sent, the text stays inside libbox's
/// own type.
@Test func libboxCloseTextNeverReachesTheAgentsErrorsOrReplies() throws {
  let canary = "close outbound proxy-canary.example:443 at /Users/someone/cache.db"
  let unclosable = LibboxInstanceUnclosable(closeFailure: canary)
  let failures: [ProxySessionLifecycleError] = [
    .engineUnclosable(unclosable),
    .cleanupFailed(
      original: String(describing: ProxySessionLifecycleError.engineUnclosable(unclosable)),
      cleanup: [String(reflecting: ProxySessionLifecycleError.engineUnclosable(unclosable))]),
  ]
  for failure in failures {
    var dumped = ""
    dump(failure, to: &dumped)
    for rendering in [
      String(describing: failure), String(reflecting: failure), "\(failure)", dumped,
      failure.localizedDescription, (failure as NSError).description,
      String(describing: (failure as NSError).userInfo),
      String(
        decoding: try ProtocolCodec.encode(
          ResponseEnvelope(requestID: RequestID(), failure: failure.engineFailure)), as: UTF8.self),
    ] {
      #expect(!rendering.contains("proxy-canary"), "\(rendering)")
    }
  }
  #expect(!unclosable.localizedDescription.contains("proxy-canary"))
  #expect(!String(describing: unclosable).contains("proxy-canary"))
}

private struct CleanupFailingConfigurationChecker: LibboxConfigurationChecking {
  func check(configuration: Data) throws {
    throw LibboxRuntimeError.configurationCheckCleanupFailed(
      LibboxDiagnostic("close network: close interface monitor: proxy-canary"))
  }
}

/// libbox accepted the configuration but could not close the instance it built
/// to check it. That is no rejection of the profile, so the Host may ask again.
@Test func validationWhoseCheckCouldNotCloseIsRetryableAndNoRejection() throws {
  let service = ProxyAgentService(
    lifecycle: ValidationOnlyProxyOwner(lifecycle: makeFixture().lifecycle),
    configurationChecker: CleanupFailingConfigurationChecker(),
    preferences: SCPreferencesSystemProxyPreferences(),
    journalStore: FakeJournalStore()
  )
  let request = RequestEnvelope(
    command: try NativeCommand(kind: .validateConfiguration, configuration: descriptor()))
  var responseData: Data?
  var responseError: NSError?
  service.validateConfiguration(Data("{}".utf8), request: try ProtocolCodec.encode(request)) {
    data, error in
    responseData = data
    responseError = error
  }
  #expect(responseError == nil)
  let data = try #require(responseData)
  #expect(!String(decoding: data, as: UTF8.self).contains("proxy-canary"))
  let failure = try #require(try ProtocolCodec.decodeResponse(data).failure)
  #expect(failure.code == "configuration-check-cleanup-failed")
  #expect(failure.isRetryable)
}

/// Only a configuration libbox read and refused is a rejected profile. A check
/// libbox could not answer, including one that broke libbox's own API by
/// returning nothing, is no verdict on the profile.
@Test func everyCheckFailureTellsTheHostWhetherTheProfileWasRejected() {
  let diagnostic = LibboxDiagnostic("detail")
  let expected: [(LibboxRuntimeError, ProxyAgentFailureCode)] = [
    (.invalidConfigurationSize(0), .configurationRejected),
    (.invalidConfigurationEncoding, .configurationRejected),
    (.invalidConfigurationJSON, .configurationRejected),
    (.configurationCheckFailed(diagnostic), .configurationRejected),
    (.libboxUnavailable, .validatorUnavailable),
    (.missingBundleSetting("key"), .validatorUnavailable),
    (.appGroupUnavailable("group"), .validatorUnavailable),
    (.unsafeRuntimeDirectory("path"), .validatorUnavailable),
    (.setupConflict, .validatorUnavailable),
    (.setupFailed(diagnostic), .validatorUnavailable),
    (.configurationCheckCleanupFailed(diagnostic), .configurationCheckCleanupFailed),
    (.configurationCheckReturnedNothing, .validatorFailed),
    (.unexpectedPacketDescriptor, .validatorFailed),
    (.missingPacketDescriptor, .validatorFailed),
    (.packetDescriptorAlreadyTransferred, .validatorFailed),
    (.unsupportedPlatformOperation("operation"), .validatorFailed),
    (.networkMonitorAlreadyStarted, .validatorFailed),
    (.networkMonitorUnavailable, .validatorFailed),
    (.networkMonitorTimedOut, .validatorFailed),
    (.alreadyStarted, .validatorFailed),
    (.serverCreationFailed(diagnostic), .validatorFailed),
    (.serviceStartFailed(diagnostic), .validatorFailed),
    (.serviceStartTimedOut, .validatorFailed),
    (.invalidRuntimeEndpoints, .validatorFailed),
    (.invalidEndpointConflict(kind: 0, port: 0), .validatorFailed),
    (.endpointConflict(role: .mixed, port: 7890), .validatorFailed),
    (.serviceNotRunning(state: 0, message: diagnostic), .validatorFailed),
  ]
  for (error, code) in expected {
    let failure = ProxyAgentService.validationFailure(for: error)
    #expect(failure.code == code.rawValue, "\(error)")
    #expect(failure.isRetryable == (code != .configurationRejected), "\(error)")
  }
}

@Test func proxyValidationResponseNeverEchoesUnderlyingSecretError() throws {
  let secret = "credential-that-must-never-leave-agent"
  let service = ProxyAgentService(
    lifecycle: ValidationOnlyProxyOwner(lifecycle: makeFixture().lifecycle),
    configurationChecker: SecretEchoConfigurationChecker(secret: secret),
    preferences: SCPreferencesSystemProxyPreferences(),
    journalStore: FakeJournalStore()
  )
  let request = RequestEnvelope(
    command: try NativeCommand(
      kind: .validateConfiguration,
      configuration: descriptor()
    )
  )
  var responseData: Data?
  var responseError: NSError?
  service.validateConfiguration(
    Data("{\"password\":\"\(secret)\"}".utf8),
    request: try ProtocolCodec.encode(request)
  ) { data, error in
    responseData = data
    responseError = error
  }

  #expect(responseError == nil)
  let data = try #require(responseData)
  #expect(!String(decoding: data, as: UTF8.self).contains(secret))
  let response = try ProtocolCodec.decodeResponse(data)
  #expect(response.failure?.code == "configuration-validator-failed")
  #expect(
    response.failure?.message
      == "Configuration validation failed at an explicit internal boundary."
  )
}

private final class FakeProxyEngine: ProxyEngine, @unchecked Sendable {
  private let lock = NSLock()
  private let started = DispatchSemaphore(value: 0)
  private var eventHandler: (@Sendable (ProxyEngineEvent) -> Void)?
  private var startCountValue = 0
  private var stopCountValue = 0
  private var stopFailure: LibboxInstanceUnclosable?

  var startCount: Int {
    lock.withLock { startCountValue }
  }

  var stopCount: Int {
    lock.withLock { stopCountValue }
  }

  func start(
    configuration: Data,
    deadline: EngineStartDeadline,
    eventHandler: @escaping @Sendable (ProxyEngineEvent) -> Void
  ) throws {
    lock.withLock {
      startCountValue += 1
      self.eventHandler = eventHandler
    }
    started.signal()
  }

  func stop() throws(LibboxInstanceUnclosable) {
    let failure = lock.withLock { () -> LibboxInstanceUnclosable? in
      stopCountValue += 1
      return stopFailure
    }
    if let failure {
      throw failure
    }
  }

  func healthCheck() throws {}

  /// Makes this and every later stop throw `failure`, as an engine whose
  /// libbox instance could not be closed does.
  func failStops(with failure: LibboxInstanceUnclosable) {
    lock.withLock { stopFailure = failure }
  }

  func waitUntilStarted() -> Bool {
    started.wait(timeout: .now() + 1) == .success
  }

  func emit(_ event: ProxyEngineEvent) {
    let eventHandler = lock.withLock { self.eventHandler }
    eventHandler?(event)
  }
}

private struct FakeProxyEngineFactory: ProxyEngineFactory {
  let engine: FakeProxyEngine
  let creationFails: Bool

  func makeEngine(configuration: Data) throws -> any ProxyEngine {
    if creationFails {
      throw ForcedProxyFailure.requested
    }
    return engine
  }
}

private final class FakeLease: ProxyEngineLeaseHolding, @unchecked Sendable {
  private let lock = NSLock()
  private var releaseCountValue = 0

  var releaseCount: Int {
    lock.withLock { releaseCountValue }
  }

  func release() throws {
    lock.withLock {
      releaseCountValue += 1
    }
  }
}

private final class FakeJournalStore: ProxyOwnershipJournalStoring, @unchecked Sendable {
  private let lock = NSLock()
  private var journalValue: ProxyOwnershipJournal?
  private var saveCountValue = 0
  private var removeCountValue = 0

  init(journal: ProxyOwnershipJournal? = nil) {
    journalValue = journal
  }

  var journal: ProxyOwnershipJournal? {
    lock.withLock { journalValue }
  }

  var saveCount: Int {
    lock.withLock { saveCountValue }
  }

  var removeCount: Int {
    lock.withLock { removeCountValue }
  }

  func load() throws -> ProxyOwnershipJournal? {
    lock.withLock { journalValue }
  }

  func save(_ journal: ProxyOwnershipJournal) throws {
    lock.withLock {
      saveCountValue += 1
      journalValue = journal
    }
  }

  func remove() throws {
    lock.withLock {
      removeCountValue += 1
      journalValue = nil
    }
  }
}

private final class MemoryLifecycleJournalDataStore: JournalDataStoring, @unchecked Sendable {
  private let lock = NSLock()
  private var data: Data?
  private var loadFailure: JournalAuthenticationError?
  private var saveFailure: JournalAuthenticationError?

  func load() throws(JournalAuthenticationError) -> Data? {
    lock.lock()
    defer { lock.unlock() }
    if let loadFailure {
      throw loadFailure
    }
    return data
  }

  func save(_ data: Data) throws(JournalAuthenticationError) {
    lock.lock()
    defer { lock.unlock() }
    if let saveFailure {
      throw saveFailure
    }
    self.data = data
  }

  func remove() throws(JournalAuthenticationError) {
    lock.withLock {
      data = nil
    }
  }

  func failLoads(with error: JournalAuthenticationError) {
    lock.withLock {
      loadFailure = error
    }
  }

  func failSaves(with error: JournalAuthenticationError) {
    lock.withLock {
      saveFailure = error
    }
  }
}

private final class FakeSystemProxyPreferences: SystemProxyPreferences, @unchecked Sendable {
  private let authorizationFailure: SystemProxyPreferencesError?
  func requireAuthorization() throws {
    if let authorizationFailure { throw authorizationFailure }
  }
  private let lock = NSLock()
  private var values: [SystemProxyField: ProxyPreferenceValue]
  private var prepareCountValue = 0
  private var applyCountValue = 0
  private var restoreCountValue = 0
  private var restoreFailuresRemaining = 0
  private let prepareFailure: SystemProxyPreferencesError?
  var applyFailsAfterPartialMutation = false

  init(
    values: [SystemProxyField: ProxyPreferenceValue] = [:],
    prepareFailure: SystemProxyPreferencesError? = nil,
    authorizationFailure: SystemProxyPreferencesError? = nil
  ) {
    self.values = values
    self.prepareFailure = prepareFailure
    self.authorizationFailure = authorizationFailure
  }

  var prepareCount: Int {
    lock.withLock { prepareCountValue }
  }

  var applyCount: Int {
    lock.withLock { applyCountValue }
  }

  var restoreCount: Int {
    lock.withLock { restoreCountValue }
  }

  func failNextRestore() {
    lock.withLock {
      restoreFailuresRemaining += 1
    }
  }

  func currentValue(_ field: SystemProxyField) -> ProxyPreferenceValue? {
    lock.withLock { values[field] }
  }

  func setExternalValue(_ value: ProxyPreferenceValue?, field: SystemProxyField) {
    lock.withLock {
      set(value, field: field)
    }
  }

  func prepareOwnership(
    configuration: ConfigurationDescriptor,
    endpoint: MixedListenerEndpoint
  ) throws -> ProxyOwnershipJournal {
    try lock.withLock {
      prepareCountValue += 1
      if let prepareFailure { throw prepareFailure }
      return try Self.journal(
        configuration: configuration,
        endpoint: endpoint,
        originalValues: values
      )
    }
  }

  func apply(_ journal: ProxyOwnershipJournal) throws {
    try lock.withLock {
      applyCountValue += 1
      var changedFields = 0
      for service in journal.services {
        for field in service.fields {
          values[field.field] = field.appliedValue
          changedFields += 1
          if applyFailsAfterPartialMutation, changedFields == 1 {
            throw ForcedProxyFailure.requested
          }
        }
      }
    }
  }

  func restore(_ journal: ProxyOwnershipJournal) throws -> ProxyRestoreResult {
    try lock.withLock {
      restoreCountValue += 1
      if restoreFailuresRemaining > 0 {
        restoreFailuresRemaining -= 1
        throw ForcedProxyFailure.requested
      }
      var conflicts: [ProxyOwnershipConflict] = []
      for service in journal.services {
        for field in service.fields {
          let current = values[field.field]
          if current == field.appliedValue {
            set(field.originalValue, field: field.field)
          } else if current != field.originalValue {
            conflicts.append(
              ProxyOwnershipConflict(
                serviceID: service.serviceID,
                field: field.field,
                reason: .valueChanged(current: current)
              )
            )
          }
        }
      }
      return ProxyRestoreResult(conflicts: conflicts)
    }
  }

  private func set(_ value: ProxyPreferenceValue?, field: SystemProxyField) {
    if let value {
      values[field] = value
    } else {
      values.removeValue(forKey: field)
    }
  }

  static func journal(
    configuration: ConfigurationDescriptor,
    endpoint: MixedListenerEndpoint,
    originalValues: [SystemProxyField: ProxyPreferenceValue]
  ) throws -> ProxyOwnershipJournal {
    let applied: [SystemProxyField: ProxyPreferenceValue] = [
      .httpEnabled: .integer(1),
      .httpHost: .string(endpoint.host),
      .httpPort: .integer(Int(endpoint.port)),
      .httpsEnabled: .integer(1),
      .httpsHost: .string(endpoint.host),
      .httpsPort: .integer(Int(endpoint.port)),
      .socksEnabled: .integer(1),
      .socksHost: .string(endpoint.host),
      .socksPort: .integer(Int(endpoint.port)),
      .proxyAutoConfigEnabled: .integer(0),
      .proxyAutoDiscoveryEnabled: .integer(0),
    ]
    let fields = try SystemProxyField.allCases.map { field in
      guard let appliedValue = applied[field] else {
        throw ForcedProxyFailure.requested
      }
      return OwnedSystemProxyField(
        field: field,
        originalValue: originalValues[field],
        appliedValue: appliedValue
      )
    }
    return try ProxyOwnershipJournal(
      phase: .prepared,
      configuration: configuration,
      services: [try SystemProxyServiceOwnership(serviceID: "service-1", fields: fields)]
    )
  }
}

private enum OperationOutcome: Equatable {
  case success
  case failure(ProxySessionLifecycleError)
}

private final class OperationRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let completed = DispatchSemaphore(value: 0)
  private var outcomes: [OperationOutcome] = []

  func record(_ result: Result<Void, ProxySessionLifecycleError>) {
    lock.withLock {
      switch result {
      case .success: outcomes.append(.success)
      case .failure(let error): outcomes.append(.failure(error))
      }
    }
    completed.signal()
  }

  func wait() -> Bool {
    completed.wait(timeout: .now() + 1) == .success
  }

  var values: [OperationOutcome] {
    lock.withLock { outcomes }
  }
}

/// What happened, in order: completions the test records and ended processes.
private final class EventLog: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []

  func record(_ event: String) {
    lock.withLock { events.append(event) }
  }

  var values: [String] {
    lock.withLock { events }
  }
}

private final class EndProcessRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let ended = DispatchSemaphore(value: 0)
  private var failures: [LibboxInstanceUnclosable] = []

  func record(_ failure: LibboxInstanceUnclosable) {
    lock.withLock { failures.append(failure) }
    ended.signal()
  }

  func wait() -> Bool {
    ended.wait(timeout: .now() + 1) == .success
  }

  var values: [LibboxInstanceUnclosable] {
    lock.withLock { failures }
  }
}

private struct ProxyFixture {
  let lifecycle: ProxySessionLifecycle
  let engine: FakeProxyEngine
  let lease: FakeLease
  let preferences: FakeSystemProxyPreferences
  let journalStore: FakeJournalStore
  let endRecorder: EndProcessRecorder
  let events: EventLog
}

/// A runtime whose start ran past its deadline and was interrupted.
private final class TimedOutLibboxRuntime: LibboxServiceRuntime, @unchecked Sendable {
  private let lock = NSLock()
  private var stopCountValue = 0
  private var startDeadlines: [EngineStartDeadline] = []

  var stopCount: Int { lock.withLock { stopCountValue } }
  var deadlines: [EngineStartDeadline] { lock.withLock { startDeadlines } }

  func start(configuration: Data, packetFileDescriptor: Int32?, deadline: EngineStartDeadline)
    throws
  {
    lock.withLock { startDeadlines.append(deadline) }
    throw LibboxRuntimeError.serviceStartTimedOut
  }

  func stop() throws(LibboxInstanceUnclosable) { lock.withLock { stopCountValue += 1 } }
  func healthCheck() throws {}
  func resetNetwork() {}
}

/// A runtime whose failed start libbox could not close: the start throws the
/// close failure, and so does every stop.
private final class UnclosableLibboxRuntime: LibboxServiceRuntime, @unchecked Sendable {
  private let lock = NSLock()
  private let closeFailure: LibboxInstanceUnclosable
  private var startCountValue = 0
  private var stopCountValue = 0

  init(closeFailure: LibboxInstanceUnclosable) {
    self.closeFailure = closeFailure
  }

  var startCount: Int { lock.withLock { startCountValue } }
  var stopCount: Int { lock.withLock { stopCountValue } }

  func start(configuration: Data, packetFileDescriptor: Int32?, deadline: EngineStartDeadline)
    throws
  {
    lock.withLock { startCountValue += 1 }
    throw closeFailure
  }

  func stop() throws(LibboxInstanceUnclosable) {
    lock.withLock { stopCountValue += 1 }
    throw closeFailure
  }

  func healthCheck() throws {}
  func resetNetwork() {}
}

private struct StubLibboxRuntimeFactory: LibboxServiceRuntimeFactory {
  let runtime: any LibboxServiceRuntime & Sendable

  func makeRuntime(role: LibboxRuntimeRole) throws -> any LibboxServiceRuntime { runtime }
}

/// The smallest configuration the real engine admits: an app-owned controller
/// and the System Proxy mixed listener.
private func receiptConfiguration() -> Data {
  Data(
    #"{"experimental":{"clash_api":{"external_controller":"127.0.0.1:9091","secret":"s"}},"inbounds":[{"type":"mixed","tag":"cfw-system-proxy","listen":"127.0.0.1","listen_port":7891}]}"#
      .utf8)
}

private func descriptor(generation: UInt64 = 1, slot: ConfigurationSlot = .systemProxy) throws
  -> ConfigurationDescriptor
{
  guard
    let installationID = UUID(
      uuidString: "11111111-1111-1111-1111-111111111111"
    )
  else {
    throw ForcedProxyFailure.requested
  }
  return try ConfigurationDescriptor(
    slot: slot,
    tunnelOptions: nil,
    credentialAudience: CredentialAudience(
      profileID: installationID,
      profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
    installationID: installationID,
    epoch: 1,
    generation: generation,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )
}

private func makeFixture(
  creationFails: Bool = false,
  preferences: FakeSystemProxyPreferences = FakeSystemProxyPreferences(),
  journalStore: FakeJournalStore = FakeJournalStore(),
  readinessTimeout: TimeInterval = 60
) -> ProxyFixture {
  let engine = FakeProxyEngine()
  let lease = FakeLease()
  let endRecorder = EndProcessRecorder()
  let events = EventLog()
  let lifecycle = ProxySessionLifecycle(
    dependencies: ProxySessionDependencies(
      prepareOwnership: { _ in
        PreparedProxyOwnership(lease: lease)
      },
      recoverCleanupLease: { _ in lease },
      engineFactory: FakeProxyEngineFactory(
        engine: engine,
        creationFails: creationFails
      ),
      preferences: preferences,
      journalStore: journalStore,
      readinessTimeout: readinessTimeout,
      endProcess: { failure in
        events.record("end")
        endRecorder.record(failure)
      }
    )
  )
  return ProxyFixture(
    lifecycle: lifecycle,
    engine: engine,
    lease: lease,
    preferences: preferences,
    journalStore: journalStore,
    endRecorder: endRecorder,
    events: events
  )
}

/// Runs the restore that follows granted rights and waits until it finished.
private func restoreAfterAuthorization(_ lifecycle: ProxySessionLifecycle) -> Bool {
  let finished = DispatchSemaphore(value: 0)
  lifecycle.restoreSettingsAfterAuthorization { finished.signal() }
  return finished.wait(timeout: .now() + 1) == .success
}

private func readyEndpoint() throws -> MixedListenerEndpoint {
  try MixedListenerEndpoint(host: "127.0.0.1", port: 7_890)
}

private func keychainRecoveryStore(
  dataStore: any JournalDataStoring
) -> KeychainProxyOwnershipJournalStore {
  KeychainProxyOwnershipJournalStore(testingDataStore: dataStore)
}

private func recoveryLifecycle(
  preferences: FakeSystemProxyPreferences,
  journalStore: any ProxyOwnershipJournalStoring
) -> ProxySessionLifecycle {
  let engine = FakeProxyEngine()
  let lease = FakeLease()
  return ProxySessionLifecycle(
    dependencies: ProxySessionDependencies(
      prepareOwnership: { _ in
        PreparedProxyOwnership(lease: lease)
      },
      recoverCleanupLease: { _ in lease },
      engineFactory: FakeProxyEngineFactory(engine: engine, creationFails: false),
      preferences: preferences,
      journalStore: journalStore,
      readinessTimeout: 60,
      endProcess: { _ in Issue.record("every engine in this test closes") }
    )
  )
}

@Suite(.serialized)
struct ProxySessionLifecycleTests {
  @Test func localProxyStartsWithoutNetworkAuthorizationAndNeverWritesPreferences() throws {
    let preferences = FakeSystemProxyPreferences(
      values: [.httpHost: .string("other-app"), .httpPort: .integer(7890)],
      authorizationFailure: .authorizationDenied(-60007))
    let fixture = makeFixture(preferences: preferences)
    let configuration = try descriptor(slot: .localProxy)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    #expect(start.values.isEmpty)
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    #expect(fixture.lifecycle.testingSnapshot().mode == .localProxy)
    #expect(preferences.prepareCount == 0)
    #expect(preferences.applyCount == 0)
    #expect(fixture.journalStore.saveCount == 0)

    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(preferences.restoreCount == 0)
    #expect(preferences.currentValue(.httpHost) == .string("other-app"))
    #expect(preferences.currentValue(.httpPort) == .integer(7890))
    #expect(fixture.lifecycle.testingSnapshot().mode == .off)
  }

  @Test func localProxyStopRequiresExactModeAndEndsTheProcessWhenItsEngineCannotClose() throws {
    let fixture = makeFixture()
    let configuration = try descriptor(slot: .localProxy)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    let wrongMode = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: try descriptor()) { wrongMode.record($0) }
    #expect(wrongMode.wait())
    #expect(wrongMode.values == [.failure(.staleStopRequest)])
    #expect(fixture.engine.stopCount == 0)
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)
    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { result in
      fixture.events.record("stop")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(fixture.endRecorder.wait())
    #expect(failedStop.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(fixture.events.values == ["stop", "end"])
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
    #expect(fixture.lifecycle.testingSnapshot().mode == .localProxy)
    #expect(fixture.lease.releaseCount == 0)

    // libbox closes an instance once, so a retry reports the same cause without
    // reaching the engine or ending the process again.
    let retry = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.failure(.engineUnclosable(closeFailure))])
    _ = fixture.lifecycle.testingSnapshot()
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.endRecorder.values == [closeFailure])
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.preferences.restoreCount == 0)
  }

  @Test func legacyJournalKeepsItsIdentityAndRecoversBeforeLocalProxyStart() throws {
    // This is the pre-LocalProxy descriptor wire shape. Its identity is retained,
    // not recomputed with the new configuration identity schema.
    let legacyDescriptor = Data(
      #"{"slot":"systemProxy","credentialAudience":{"profile_id":"11111111-1111-1111-1111-111111111111","profile_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"installationID":"11111111-1111-1111-1111-111111111111","epoch":1,"generation":1,"byteCount":2,"sha256":"0000000000000000000000000000000000000000000000000000000000000000","identitySHA256":"1111111111111111111111111111111111111111111111111111111111111111","credentialSlots":[]}"#
        .utf8)
    let oldConfiguration = try JSONDecoder().decode(
      ConfigurationDescriptor.self, from: legacyDescriptor)
    let oldJournal = try FakeSystemProxyPreferences.journal(
      configuration: oldConfiguration, endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let services = String(decoding: try JSONEncoder().encode(oldJournal.services), as: UTF8.self)
    let legacyJournal = Data(
      "{\"schemaVersion\":1,\"phase\":\"applied\",\"configuration\":\(String(decoding: legacyDescriptor, as: UTF8.self)),\"services\":\(services)}"
        .utf8)
    let recovered = try JSONDecoder().decode(ProxyOwnershipJournal.self, from: legacyJournal)
    #expect(recovered.configuration.identitySHA256.hex == String(repeating: "11", count: 32))
    #expect(recovered.configuration.slot == .systemProxy)
    let preferences = FakeSystemProxyPreferences()
    try preferences.apply(recovered)
    let store = FakeJournalStore(journal: recovered)
    let fixture = makeFixture(preferences: preferences, journalStore: store)
    #expect(preferences.restoreCount == 1)
    #expect(store.journal == nil)
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor(generation: 2, slot: .localProxy)) {
      start.record($0)
    }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    #expect(store.saveCount == 0)
    #expect(preferences.applyCount == 1)
    #expect(preferences.restoreCount == 1)
  }

  @Test func unresolvedOldOwnershipPreventsLocalProxyStart() throws {
    let journal = try FakeSystemProxyPreferences.journal(
      configuration: descriptor(), endpoint: readyEndpoint(), originalValues: [:]
    ).markingApplied()
    let preferences = FakeSystemProxyPreferences()
    preferences.failNextRestore()
    let store = FakeJournalStore(journal: journal)
    let fixture = makeFixture(preferences: preferences, journalStore: store)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor(generation: 2, slot: .localProxy)) {
      start.record($0)
    }
    #expect(start.wait())
    #expect(start.values == [.failure(.lifecycleConflict)])
    #expect(fixture.engine.startCount == 0)
    #expect(store.journal == journal)
  }

  @Test func ungrantedAuthorizationStartsNoEngineAndWritesNoPreferences() throws {
    let preferences = FakeSystemProxyPreferences(
      authorizationFailure: .authorizationDenied(-60007))
    let fixture = makeFixture(preferences: preferences)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [.failure(.authorizationRequired)])
    #expect(fixture.engine.startCount == 0)
    #expect(preferences.prepareCount == 0)
    #expect(preferences.applyCount == 0)
    #expect(fixture.journalStore.journal == nil)
  }

  @Test func existingProxyFailurePreservesTheCauseAndMakesNoPreferenceWrite() throws {
    let preferences = FakeSystemProxyPreferences(
      values: [.httpEnabled: .integer(1), .httpPort: .integer(7_890)],
      prepareFailure: .existingProxyConfiguration(serviceID: "other-app", field: .httpEnabled))
    let fixture = makeFixture(preferences: preferences)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.failure(.existingSystemProxy)])
    #expect(
      ProxySessionLifecycleError.existingSystemProxy.engineFailure.code == "existing-system-proxy")
    #expect(preferences.applyCount == 0)
    #expect(preferences.restoreCount == 0)
    #expect(preferences.currentValue(.httpPort) == .integer(7_890))
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.journalStore.journal == nil)
  }

  @Test func preferencesAreNotAppliedBeforeMixedListenerReadiness() throws {
    let fixture = makeFixture()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())

    #expect(fixture.preferences.prepareCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(start.values.isEmpty)

    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    #expect(fixture.preferences.applyCount == 1)
    #expect(fixture.journalStore.journal?.phase == .applied)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .proxyActive)
  }

  @Test func applyFailureRollsBackPreferencesAndStopsEngine() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    preferences.applyFailsAfterPartialMutation = true
    let fixture = makeFixture(preferences: preferences)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(preferences.restoreCount == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
  }

  @Test func externalModificationIsPreservedAndReportedAsOwnershipConflict() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let fixture = makeFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    preferences.setExternalValue(.string("external"), field: .httpHost)
    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { stop.record($0) }
    #expect(stop.wait())
    guard case .failure(.ownershipConflict(let conflicts)) = stop.values[0] else {
      Issue.record("Expected an explicit ownership conflict")
      return
    }
    #expect(conflicts.count == 1)
    #expect(conflicts[0].field == .httpHost)
    #expect(preferences.currentValue(.httpHost) == .string("external"))
    #expect(preferences.currentValue(.httpsHost) == nil)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.journalStore.journal != nil)

    let repeatedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) {
      repeatedStop.record($0)
    }
    #expect(repeatedStop.wait())
    guard case .failure(.ownershipConflict) = repeatedStop.values[0] else {
      Issue.record("Repeated stop must retain the ownership conflict")
      return
    }
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)

    let blockedStart = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) {
      blockedStart.record($0)
    }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.failure(.lifecycleConflict)])

    preferences.setExternalValue(.string("original"), field: .httpHost)
    let resolvedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { resolvedStop.record($0) }
    #expect(resolvedStop.wait())
    #expect(resolvedStop.values == [.success])
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.journalStore.journal == nil)
  }

  @Test func engineCrashRestoresPreferencesAndReleasesLease() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let fixture = makeFixture(preferences: preferences)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    fixture.engine.emit(
      .failed(ProxyEngineFailure(code: "engine-exited", message: "terminated"))
    )
    _ = fixture.lifecycle.testingSnapshot()

    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(preferences.restoreCount == 1)
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
  }

  @Test func engineCrashBeforeReadinessNeverPublishesProxySettings() throws {
    let fixture = makeFixture()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())

    let failure = ProxyEngineFailure(code: "startup-crash", message: "terminated")
    fixture.engine.emit(.failed(failure))
    #expect(start.wait())

    #expect(start.values == [.failure(.engineFailed(failure))])
    #expect(fixture.preferences.prepareCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
  }

  @Test func libboxStartTimeoutFailsTheStartCleanlyWithItsOwnCause() throws {
    let runtime = TimedOutLibboxRuntime()
    let lease = FakeLease()
    let preferences = FakeSystemProxyPreferences()
    let lifecycle = ProxySessionLifecycle(
      dependencies: ProxySessionDependencies(
        prepareOwnership: { _ in PreparedProxyOwnership(lease: lease) },
        resolveConfiguration: { _, _ in receiptConfiguration() },
        recoverCleanupLease: { _ in lease },
        engineFactory: LibboxProxyEngineFactory(
          runtimeFactory: StubLibboxRuntimeFactory(runtime: runtime)),
        preferences: preferences,
        journalStore: FakeJournalStore(),
        readinessTimeout: 60,
        endProcess: { _ in Issue.record("a runtime that timed out still closes") }))
    let configuration = try descriptor()
    let deadline = EngineStartDeadline(receivedAt: .now)
    let start = OperationRecorder()
    lifecycle.start(
      configuration: SensitiveDataBuffer(copying: Data("{}".utf8)),
      descriptor: configuration,
      deadline: deadline
    ) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [.failure(.engineStartTimedOut)])
    #expect(runtime.deadlines == [deadline])
    #expect(runtime.stopCount == 1)
    #expect(lease.releaseCount == 1)
    #expect(preferences.prepareCount == 0)
    #expect(preferences.applyCount == 0)
    #expect(
      lifecycle.testingSnapshot().state.failure?.code
        == ProxyAgentFailureCode.engineStartTimedOut.rawValue)

    let stop = OperationRecorder()
    lifecycle.stop(expectedConfiguration: configuration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(lifecycle.testingSnapshot().mode == .off)
    #expect(runtime.stopCount == 1)
  }

  @Test func listenerReadinessTimeoutStopsEngineWithoutPublishingPreferences() throws {
    let fixture = makeFixture(readinessTimeout: 0.01)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    #expect(start.wait())

    #expect(start.values == [.failure(.listenerReadinessTimedOut)])
    #expect(fixture.preferences.prepareCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
  }

  /// A stop that reaches no session says so, so the Host can tell an owner that
  /// ended, whose successor holds nothing, from one holding another generation.
  @Test func stopWithoutASessionIsToldApartFromAStaleStop() throws {
    let fixture = makeFixture()
    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: try descriptor(generation: 1)) {
      stop.record($0)
    }
    #expect(stop.wait())
    #expect(stop.values == [.failure(.stopWithoutSession)])
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func staleStopDoesNotTouchActiveRuntimeOrPreferences() throws {
    let fixture = makeFixture()
    let activeConfiguration = try descriptor(generation: 1)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: try descriptor(generation: 2)) {
      stop.record($0)
    }
    #expect(stop.wait())
    #expect(stop.values == [.failure(.staleStopRequest)])
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.preferences.restoreCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .proxyActive)
  }

  @Test func repeatedStopAfterSuccessfulCleanupIsIdempotent() throws {
    let fixture = makeFixture()
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    let firstStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { firstStop.record($0) }
    #expect(firstStop.wait())
    let secondStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { secondStop.record($0) }
    #expect(secondStop.wait())

    #expect(firstStop.values == [.success])
    #expect(secondStop.values == [.success])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func lateReadyCallbackAfterStopCannotApplyPreferences() throws {
    let fixture = makeFixture()
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())

    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { stop.record($0) }
    #expect(stop.wait())
    #expect(start.wait())
    #expect(start.values == [.failure(.startupCancelled)])
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    _ = fixture.lifecycle.testingSnapshot()

    #expect(fixture.preferences.prepareCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func unclosableEngineEndsTheProcessAfterItsSettingsAreRestored() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let fixture = makeFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    #expect(preferences.currentValue(.httpHost) == .string("127.0.0.1"))
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)

    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { result in
      fixture.events.record("stop")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(fixture.endRecorder.wait())
    #expect(failedStop.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(fixture.events.values == ["stop", "end"])
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.lease.releaseCount == 0)
    let failed = fixture.lifecycle.testingSnapshot()
    #expect(failed.state.kind == .failed)
    #expect(failed.state.failure?.code == "proxy-engine-unclosable")

    // Nothing the engine reports afterwards revives the session.
    fixture.engine.emit(.failed(ProxyEngineFailure(code: "crash", message: "Runtime exited.")))
    let retry = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.failure(.engineUnclosable(closeFailure))])
    let blockedStart = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.failure(.engineUnclosable(closeFailure))])
    _ = fixture.lifecycle.testingSnapshot()
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.engine.startCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(preferences.restoreCount == 1)
    #expect(fixture.endRecorder.values == [closeFailure])
  }

  @Test func unclosableEngineKeepsTheProcessUntilItsSettingsAreRestored() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let fixture = makeFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)
    preferences.failNextRestore()

    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { result in
      fixture.events.record("stop")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(failedStop.values == [.failure(.engineUnclosable(closeFailure))])
    _ = fixture.lifecycle.testingSnapshot()
    // Only this process holds the authorization to restore the settings
    // without asking the user again, so it stays until they are restored.
    #expect(fixture.endRecorder.values.isEmpty)
    #expect(fixture.journalStore.journal != nil)
    #expect(preferences.currentValue(.httpHost) == .string("127.0.0.1"))

    let retry = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { result in
      fixture.events.record("stop")
      retry.record(result)
    }
    #expect(retry.wait())
    #expect(fixture.endRecorder.wait())
    #expect(retry.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(fixture.events.values == ["stop", "stop", "end"])
    #expect(preferences.restoreCount == 2)
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.endRecorder.values == [closeFailure])
  }

  @Test func unclosableRuntimeFailsTheStartAndLeavesTheAgentSpent() throws {
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close failed service")
    let runtime = UnclosableLibboxRuntime(closeFailure: closeFailure)
    let lease = FakeLease()
    let events = EventLog()
    let ends = EndProcessRecorder()
    let lifecycle = ProxySessionLifecycle(
      dependencies: ProxySessionDependencies(
        prepareOwnership: { _ in PreparedProxyOwnership(lease: lease) },
        resolveConfiguration: { _, _ in receiptConfiguration() },
        recoverCleanupLease: { _ in lease },
        engineFactory: LibboxProxyEngineFactory(
          runtimeFactory: StubLibboxRuntimeFactory(runtime: runtime)),
        preferences: FakeSystemProxyPreferences(),
        journalStore: FakeJournalStore(),
        readinessTimeout: 60,
        endProcess: { failure in
          events.record("end")
          ends.record(failure)
        }))
    let configuration = try descriptor()
    let start = OperationRecorder()
    lifecycle.start(
      configuration: SensitiveDataBuffer(copying: Data("{}".utf8)),
      descriptor: configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { result in
      events.record("start")
      start.record(result)
    }
    #expect(start.wait())
    #expect(ends.wait())
    #expect(start.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(events.values == ["start", "end"])
    #expect(lifecycle.testingSnapshot().state.failure?.code == "proxy-engine-unclosable")
    #expect(lease.releaseCount == 0)

    let blockedStart = OperationRecorder()
    lifecycle.start(configuration: configuration) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.failure(.engineUnclosable(closeFailure))])
    let stop = OperationRecorder()
    lifecycle.stop(expectedConfiguration: configuration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.failure(.engineUnclosable(closeFailure))])
    _ = lifecycle.testingSnapshot()
    #expect(runtime.startCount == 1)
    #expect(runtime.stopCount == 1)
    #expect(ends.values == [closeFailure])
  }

  @Test func missingLibboxFailsBeforeLeaseOrPreferences() throws {
    let fixture = makeFixture(creationFails: true)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.engineCreation) = start.values[0] else {
      Issue.record("Expected fail-closed engine creation failure")
      return
    }
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.preferences.prepareCount == 0)
    #expect(fixture.preferences.applyCount == 0)
  }

  @Test func persistedJournalIsRecoveredBeforeNewCommands() throws {
    let activeConfiguration = try descriptor()
    let endpoint = try readyEndpoint()
    let prepared = try FakeSystemProxyPreferences.journal(
      configuration: activeConfiguration,
      endpoint: endpoint,
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeSystemProxyPreferences()
    try preferences.apply(prepared)
    let journalStore = FakeJournalStore(journal: prepared)

    let fixture = makeFixture(preferences: preferences, journalStore: journalStore)

    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(preferences.restoreCount == 1)
    #expect(journalStore.journal == nil)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func failedRestorePublicationRetainsJournalUntilExplicitRetry() throws {
    let configuration = try descriptor()
    let journal = try FakeSystemProxyPreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    preferences.failNextRestore()
    let journalStore = FakeJournalStore(journal: journal)
    let fixture = makeFixture(preferences: preferences, journalStore: journalStore)

    #expect(preferences.restoreCount == 1)
    #expect(journalStore.journal == journal)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    let retry = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(preferences.restoreCount == 2)
    #expect(journalStore.journal == nil)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  /// A launch whose recovery could not restore the settings, for example
  /// because the agent had no rights yet, restores them once the user grants
  /// the rights, which the Host asks for before every Off and before quitting.
  @Test func failedRecoveryRestoresOnceTheUserGrantsTheRights() throws {
    let configuration = try descriptor()
    let journal = try FakeSystemProxyPreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    preferences.failNextRestore()
    let journalStore = FakeJournalStore(journal: journal)
    let fixture = makeFixture(preferences: preferences, journalStore: journalStore)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(preferences.restoreCount == 2)
    #expect(journalStore.journal == nil)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
    // The Host's Off for that generation then succeeds without restoring again.
    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(preferences.restoreCount == 2)
  }

  @Test func restoreThatStillFailsAfterAuthorizationKeepsItsJournal() throws {
    let configuration = try descriptor()
    let journal = try FakeSystemProxyPreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    preferences.failNextRestore()
    preferences.failNextRestore()
    let journalStore = FakeJournalStore(journal: journal)
    let fixture = makeFixture(preferences: preferences, journalStore: journalStore)

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(preferences.restoreCount == 2)
    #expect(journalStore.journal == journal)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
  }

  /// A spent agent whose restore failed restores the settings once the user
  /// grants the rights again, and then ends.
  @Test func spentAgentRestoresOnceTheUserGrantsTheRightsThenEnds() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let fixture = makeFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)
    preferences.failNextRestore()
    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { failedStop.record($0) }
    #expect(failedStop.wait())
    #expect(fixture.journalStore.journal != nil)
    #expect(fixture.endRecorder.values.isEmpty)

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(fixture.endRecorder.wait())
    #expect(preferences.restoreCount == 2)
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.endRecorder.values == [closeFailure])
  }

  /// A stop whose engine stopped but whose restore failed leaves the session
  /// failed with its journal; the rights the user grants restore the settings,
  /// and the Host's Off for that generation then succeeds without restoring
  /// again.
  @Test func aStopWhoseRestoreFailedRestoresOnceTheUserGrantsTheRights() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let fixture = makeFixture(preferences: preferences)
    let configuration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    preferences.failNextRestore()
    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { failedStop.record($0) }
    #expect(failedStop.wait())
    #expect(failedStop.values != [.success])
    #expect(fixture.journalStore.journal != nil)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(preferences.restoreCount == 2)
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(preferences.restoreCount == 2)
  }

  /// A spent agent ends only once its settings are restored: rights that still
  /// do not restore them leave it running with its journal.
  @Test func aSpentAgentWhoseRestoreStillFailsKeepsRunning() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let fixture = makeFixture(preferences: preferences)
    let configuration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    fixture.engine.failStops(
      with: LibboxInstanceUnclosable(closeFailure: "close network: monitor"))
    preferences.failNextRestore()
    preferences.failNextRestore()
    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { failedStop.record($0) }
    #expect(failedStop.wait())

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    // Anything the restore queued behind itself has run by now.
    _ = fixture.lifecycle.testingSnapshot()
    #expect(preferences.restoreCount == 2)
    #expect(fixture.journalStore.journal != nil)
    #expect(fixture.endRecorder.values.isEmpty)
  }

  @Test func grantedRightsWithNothingLeftToRestoreChangeNothing() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let fixture = makeFixture(preferences: preferences)
    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(preferences.restoreCount == 0)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lifecycle.testingSnapshot() == .off)
  }

  /// Granted rights change nothing for a session whose engine runs: its
  /// settings stay applied until it stops.
  @Test func grantedRightsLeaveARunningSessionsSettingsApplied() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let fixture = makeFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(preferences.restoreCount == 0)
    #expect(fixture.journalStore.journal != nil)
    #expect(preferences.currentValue(.httpHost) == .string("127.0.0.1"))
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .proxyActive)
  }

  @Test func preparedKeychainJournalRecoversCrashAfterPreferencesApply() throws {
    let configuration = try descriptor()
    let preparedJournal = try FakeSystemProxyPreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    )
    let preferences = FakeSystemProxyPreferences()
    try preferences.apply(preparedJournal)
    let dataStore = MemoryLifecycleJournalDataStore()
    let initialStore = keychainRecoveryStore(dataStore: dataStore)
    try initialStore.save(preparedJournal)

    let restartedStore = keychainRecoveryStore(dataStore: dataStore)
    let lifecycle = recoveryLifecycle(
      preferences: preferences,
      journalStore: restartedStore
    )

    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(preferences.restoreCount == 1)
    #expect(try restartedStore.load() == nil)
    #expect(lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func unavailableKeychainBlocksRecoveryWithoutChangingPreferences() throws {
    let configuration = try descriptor()
    let journal = try FakeSystemProxyPreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeSystemProxyPreferences()
    try preferences.apply(journal)
    let dataStore = MemoryLifecycleJournalDataStore()
    let unavailableStore = keychainRecoveryStore(dataStore: dataStore)
    try unavailableStore.save(journal)
    dataStore.failLoads(with: .keychainReadFailed(errSecInteractionNotAllowed))

    let lifecycle = recoveryLifecycle(
      preferences: preferences,
      journalStore: unavailableStore
    )

    #expect(preferences.currentValue(.httpHost) == .string("127.0.0.1"))
    #expect(preferences.restoreCount == 0)
    #expect(lifecycle.testingSnapshot().state.kind == .failed)

    let start = OperationRecorder()
    lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(start.wait())
    guard case .failure(.recoveryBlocked) = start.values[0] else {
      Issue.record("Expected authentication failure to block all new starts")
      return
    }
    #expect(preferences.applyCount == 1)
    #expect(preferences.restoreCount == 0)
  }

  @Test func unavailableKeychainBlocksActivationBeforeChangingPreferences() throws {
    let dataStore = MemoryLifecycleJournalDataStore()
    dataStore.failSaves(with: .keychainWriteFailed(errSecInteractionNotAllowed))
    let unavailableStore = keychainRecoveryStore(dataStore: dataStore)
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let engine = FakeProxyEngine()
    let lease = FakeLease()
    let lifecycle = ProxySessionLifecycle(
      dependencies: ProxySessionDependencies(
        prepareOwnership: { _ in
          PreparedProxyOwnership(lease: lease)
        },
        recoverCleanupLease: { _ in lease },
        engineFactory: FakeProxyEngineFactory(engine: engine, creationFails: false),
        preferences: preferences,
        journalStore: unavailableStore,
        readinessTimeout: 60,
        endProcess: { _ in Issue.record("every engine in this test closes") }
      )
    )
    let start = OperationRecorder()
    lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(engine.waitUntilStarted())

    engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    guard case .failure(.ownershipJournal) = start.values[0] else {
      Issue.record("Expected Keychain failure to abort authenticated journal persistence")
      return
    }
    #expect(preferences.prepareCount == 1)
    #expect(preferences.applyCount == 0)
    #expect(preferences.restoreCount == 0)
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(engine.stopCount == 1)
    #expect(lease.releaseCount == 1)
  }
}

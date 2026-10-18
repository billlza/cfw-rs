import CFWSharedProtocol
import Foundation
import Synchronization
import Testing

@testable import CFWCredentialTransport
@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

/// Test harness shorthand. The production coordinator requires one explicit
/// one-use runtime buffer and has no descriptor-only start path.
extension ProxySystemProxyOwnerCoordinator {
  func start(
    configuration descriptor: ConfigurationDescriptor,
    authorization: ProxyOwnerAuthorization,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    start(
      configuration: SensitiveDataBuffer(copying: Data("{}".utf8)),
      descriptor: descriptor,
      authorization: authorization,
      completionHandler: completionHandler)
  }
}

private enum CoordinatorFixtureError: Error { case forced }

// MARK: - Ordering / recorders

private final class OrderLog: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []
  func record(_ event: String) { lock.withLock { events.append(event) } }
  var values: [String] { lock.withLock { events } }
}

private enum CoordinatorOutcome: Equatable {
  case success
  case failure(ProxySessionLifecycleError)
}

private final class CoordinatorRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let done = DispatchSemaphore(value: 0)
  private var outcomes: [CoordinatorOutcome] = []

  func record(_ result: Result<Void, ProxySessionLifecycleError>) {
    lock.withLock {
      switch result {
      case .success: outcomes.append(.success)
      case .failure(let error): outcomes.append(.failure(error))
      }
    }
    done.signal()
  }

  func wait() -> Bool { done.wait(timeout: .now() + 2) == .success }
  var values: [CoordinatorOutcome] { lock.withLock { outcomes } }
}

/// Wakes the tasks awaiting it once signalled. An async wait blocks no
/// thread, so a test that waits for work a lower-priority queue does causes
/// no priority inversion; the waiting task's cancellation, as a test's time
/// limit, ends the wait.
private final class AsyncTestLatch: @unchecked Sendable {
  private let lock = NSLock()
  private var signaled = false
  private var waiters: [UUID: CheckedContinuation<Void, Never>] = [:]

  func signal() {
    let values = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
      guard !signaled else { return [] }
      signaled = true
      let values = Array(waiters.values)
      waiters.removeAll()
      return values
    }
    for value in values { value.resume() }
  }

  func wait() async throws {
    let id = UUID()
    await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        let ready = lock.withLock {
          guard !signaled, !Task.isCancelled else { return true }
          waiters[id] = continuation
          return false
        }
        if ready { continuation.resume() }
      }
    } onCancel: {
      lock.withLock { waiters.removeValue(forKey: id) }?.resume()
    }
    try Task.checkCancellation()
  }
}

private final class ProcessEndRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let done = DispatchSemaphore(value: 0)
  private let ended = AsyncTestLatch()
  private var failures: [ProxyAgentEndReason] = []

  func record(_ failure: ProxyAgentEndReason) {
    lock.withLock { failures.append(failure) }
    done.signal()
    ended.signal()
  }

  func wait() -> Bool { done.wait(timeout: .now() + 2) == .success }
  /// Waits for the first end without blocking a thread.
  func firstEnd() async throws { try await ended.wait() }
  var values: [ProxyAgentEndReason] { lock.withLock { failures } }
}

private final class SnapshotRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let done = DispatchSemaphore(value: 0)
  private var snapshots: [EngineSnapshot] = []

  func record(_ snapshot: EngineSnapshot) {
    lock.withLock { snapshots.append(snapshot) }
    done.signal()
  }

  func wait() -> Bool { done.wait(timeout: .now() + 2) == .success }
  var values: [EngineSnapshot] { lock.withLock { snapshots } }
}

private final class BlockingCallGate: @unchecked Sendable {
  private let entered = DispatchSemaphore(value: 0)
  private let released = DispatchSemaphore(value: 0)

  func block() {
    entered.signal()
    _ = released.wait(timeout: .now() + 2)
  }

  func waitUntilEntered() -> Bool {
    entered.wait(timeout: .now() + 2) == .success
  }

  func release() { released.signal() }
}

// MARK: - Authority fake

private final class FakeProxyOwnerAuthorityClient: ProxyOwnerAuthorityClient, @unchecked Sendable {
  private let lock = NSLock()
  private var leaseStatusesRemaining: [Result<OwnerLeaseStatus, AuthorityDomainError>]
  private var leaseStatusQueriesValue: [AuthorityIdentifier] = []
  private let orderLog: OrderLog
  private let makeLease: @Sendable () throws -> LeaseView
  private let bindThrows: AuthorityDomainError?
  private let readyThrows: Bool
  private let onBind: @Sendable () -> Void
  private let bindGate: BlockingCallGate?
  private let stoppedGate: BlockingCallGate?
  private var stoppedFailuresRemaining: Int
  private var bindCountValue = 0
  private var bindContextsValue: [ProxyOwnerContext] = []
  private var readyValue: [ReadyAttestation] = []
  private var stoppedValue: [StoppedAttestation] = []
  private var stoppedAttemptCountValue = 0
  private let stoppedSignal = DispatchSemaphore(value: 0)

  init(
    orderLog: OrderLog,
    bindThrows: AuthorityDomainError? = nil,
    readyThrows: Bool = false,
    stoppedAttestationFailures: Int = 0,
    onBind: @escaping @Sendable () -> Void = {},
    bindGate: BlockingCallGate? = nil,
    stoppedGate: BlockingCallGate? = nil,
    leaseStatuses: [Result<OwnerLeaseStatus, AuthorityDomainError>] = [],
    makeLease: @escaping @Sendable () throws -> LeaseView
  ) {
    self.leaseStatusesRemaining = leaseStatuses
    self.orderLog = orderLog
    self.bindThrows = bindThrows
    self.readyThrows = readyThrows
    self.onBind = onBind
    self.bindGate = bindGate
    self.stoppedGate = stoppedGate
    self.stoppedFailuresRemaining = stoppedAttestationFailures
    self.makeLease = makeLease
  }

  var bindCount: Int { lock.withLock { bindCountValue } }
  var bindContexts: [ProxyOwnerContext] { lock.withLock { bindContextsValue } }
  var readyAttestations: [ReadyAttestation] { lock.withLock { readyValue } }
  var stoppedAttestations: [StoppedAttestation] { lock.withLock { stoppedValue } }
  var stoppedAttemptCount: Int { lock.withLock { stoppedAttemptCountValue } }
  var leaseStatusQueries: [AuthorityIdentifier] { lock.withLock { leaseStatusQueriesValue } }

  /// Answers with the next scripted status; without one the Authority gives
  /// no answer, as an unreachable one would. Tests read the queries made.
  func ownerLeaseStatus(_ leaseID: AuthorityIdentifier) async throws -> OwnerLeaseStatus {
    let next = lock.withLock { () -> Result<OwnerLeaseStatus, AuthorityDomainError>? in
      leaseStatusQueriesValue.append(leaseID)
      return leaseStatusesRemaining.isEmpty ? nil : leaseStatusesRemaining.removeFirst()
    }
    orderLog.record("leaseStatus")
    guard let next else { throw AuthorityDomainError(code: .globalAuthorityUnavailable) }
    return try next.get()
  }
  func waitForStoppedAttempt() -> Bool {
    stoppedSignal.wait(timeout: .now() + 2) == .success
  }

  func bind(
    _ capability: OwnerCapability,
    context: ProxyOwnerContext
  ) async throws -> LeaseView {
    capability.erase()
    orderLog.record("bind")
    lock.withLock {
      bindCountValue += 1
      bindContextsValue.append(context)
    }
    // A held bind answers, with its lease or its failure, once released.
    bindGate?.block()
    if let bindThrows { throw bindThrows }
    onBind()
    return try makeLease()
  }

  func redeem(_ ticket: StartTicket) async throws -> RedeemedTunnelStart {
    ticket.erase()
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
  }

  func attestReady(_ attestation: ReadyAttestation) async throws {
    lock.withLock { readyValue.append(attestation) }
    if readyThrows { throw AuthorityDomainError(code: .globalAuthorityUnavailable) }
  }

  func attestStopped(_ attestation: StoppedAttestation) async throws {
    let shouldFail = lock.withLock {
      stoppedAttemptCountValue += 1
      guard stoppedFailuresRemaining > 0 else {
        stoppedValue.append(attestation)
        return false
      }
      stoppedFailuresRemaining -= 1
      return true
    }
    stoppedSignal.signal()
    stoppedGate?.block()
    if shouldFail {
      throw AuthorityDomainError(code: .globalAuthorityUnavailable)
    }
  }
}

private struct FakeEffectiveSystemProxyObserver: EffectiveSystemProxyObserving {
  let applied: Bool
  func observe(
    _ descriptor: ConfigurationDescriptor
  ) async throws -> EffectiveSystemProxyObservation {
    EffectiveSystemProxyObservation(
      httpApplied: applied, httpsApplied: applied, socksApplied: applied)
  }
}

private final class FakeClock: ProxyOwnerMonotonicClock, @unchecked Sendable {
  let value: UInt64
  init(value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { value }
}

// MARK: - Data-plane fakes

private final class FakeProxyEngine: ProxyEngine, @unchecked Sendable {
  private let lock = NSLock()
  private let started = DispatchSemaphore(value: 0)
  private let orderLog: OrderLog
  private var eventHandler: (@Sendable (ProxyEngineEvent) -> Void)?
  private var startCountValue = 0
  private var stopCountValue = 0
  private var startDeadlines: [EngineStartDeadline] = []
  private let startFailure: ProxyEngineError?
  private let closeFailure: LibboxInstanceUnclosable?
  private let stopped = DispatchSemaphore(value: 0)

  /// With `startFailure`, every start throws it. With `closeFailure`, every
  /// stop throws it, as an engine whose libbox instance could not be closed
  /// does.
  init(
    orderLog: OrderLog, startFailure: ProxyEngineError? = nil,
    closeFailure: LibboxInstanceUnclosable? = nil
  ) {
    self.orderLog = orderLog
    self.startFailure = startFailure
    self.closeFailure = closeFailure
  }

  var startCount: Int { lock.withLock { startCountValue } }
  var stopCount: Int { lock.withLock { stopCountValue } }
  var deadlines: [EngineStartDeadline] { lock.withLock { startDeadlines } }

  func start(
    configuration: Data,
    deadline: EngineStartDeadline,
    eventHandler: @escaping @Sendable (ProxyEngineEvent) -> Void
  ) throws {
    lock.withLock {
      startCountValue += 1
      startDeadlines.append(deadline)
      self.eventHandler = eventHandler
    }
    orderLog.record("engine.start")
    started.signal()
    if let startFailure { throw startFailure }
  }

  func stop() throws(LibboxInstanceUnclosable) {
    lock.withLock { stopCountValue += 1 }
    stopped.signal()
    if let closeFailure { throw closeFailure }
  }
  func healthCheck() throws {}

  func waitUntilStarted() -> Bool { started.wait(timeout: .now() + 2) == .success }
  func waitForStopAttempt() -> Bool { stopped.wait(timeout: .now() + 2) == .success }

  func emit(_ event: ProxyEngineEvent) {
    let handler = lock.withLock { eventHandler }
    handler?(event)
  }
}

private struct FakeProxyEngineFactory: ProxyEngineFactory {
  let engine: FakeProxyEngine
  func makeEngine(configuration: Data) throws -> any ProxyEngine { engine }
}

private final class FakeJournalStore: ProxyOwnershipJournalStoring, @unchecked Sendable {
  private let lock = NSLock()
  private var journalValue: ProxyOwnershipJournal?
  func load() throws -> ProxyOwnershipJournal? { lock.withLock { journalValue } }
  func save(_ journal: ProxyOwnershipJournal) throws { lock.withLock { journalValue = journal } }
  func remove() throws { lock.withLock { journalValue = nil } }
}

private final class FakeSystemProxyPreferences: SystemProxyPreferences, @unchecked Sendable {
  func requireAuthorization() throws {}
  private let lock = NSLock()
  private let orderLog: OrderLog
  private var values: [SystemProxyField: ProxyPreferenceValue] = [:]
  private var applyCountValue = 0
  private var restoreCountValue = 0
  private var restoreFailuresRemaining: Int

  init(orderLog: OrderLog, restoreFailures: Int = 0) {
    self.orderLog = orderLog
    self.restoreFailuresRemaining = restoreFailures
  }

  var applyCount: Int { lock.withLock { applyCountValue } }
  var restoreCount: Int { lock.withLock { restoreCountValue } }

  func prepareOwnership(
    configuration: ConfigurationDescriptor,
    endpoint: MixedListenerEndpoint
  ) throws -> ProxyOwnershipJournal {
    try lock.withLock {
      try Self.journal(configuration: configuration, endpoint: endpoint, originalValues: values)
    }
  }

  func apply(_ journal: ProxyOwnershipJournal) throws {
    lock.withLock {
      applyCountValue += 1
      for service in journal.services {
        for field in service.fields { values[field.field] = field.appliedValue }
      }
    }
    orderLog.record("apply")
  }

  func restore(_ journal: ProxyOwnershipJournal) throws -> ProxyRestoreResult {
    try lock.withLock {
      restoreCountValue += 1
      guard restoreFailuresRemaining == 0 else {
        restoreFailuresRemaining -= 1
        throw CoordinatorFixtureError.forced
      }
      for service in journal.services {
        for field in service.fields {
          if values[field.field] == field.appliedValue {
            if let original = field.originalValue {
              values[field.field] = original
            } else {
              values.removeValue(forKey: field.field)
            }
          }
        }
      }
      return ProxyRestoreResult(conflicts: [])
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
      guard let appliedValue = applied[field] else { throw CoordinatorFixtureError.forced }
      return OwnedSystemProxyField(
        field: field, originalValue: originalValues[field], appliedValue: appliedValue)
    }
    return try ProxyOwnershipJournal(
      phase: .prepared,
      configuration: configuration,
      services: [try SystemProxyServiceOwnership(serviceID: "service-1", fields: fields)])
  }
}

// MARK: - Builders

private func proxyDescriptor(slot: ConfigurationSlot = .systemProxy) throws
  -> ConfigurationDescriptor
{
  try ConfigurationDescriptor(
    slot: slot,
    tunnelOptions: nil,
    credentialAudience: CredentialAudience(
      profileID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
      profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
    installationID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32)),
    identitySHA256: SHA256Digest(hex: String(repeating: "11", count: 32)))
}

private func matchingLease(_ descriptor: ConfigurationDescriptor) throws -> LeaseView {
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(descriptor.installationID),
      epoch: descriptor.epoch, generation: descriptor.generation),
    mode: descriptor.slot.authorityMode,
    configSHA256: descriptor.sha256,
    identitySHA256: descriptor.identitySHA256,
    ownerUID: 501,
    authorityRevision: 1)
  return try LeaseView(
    leaseID: AuthorityIdentifier(UUID()), operation: operation,
    state: .starting, expiryMonotonic: 10_000)
}

private func mismatchedLease(_ descriptor: ConfigurationDescriptor) throws -> LeaseView {
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(descriptor.installationID),
      epoch: descriptor.epoch, generation: descriptor.generation),
    mode: descriptor.slot.authorityMode,
    configSHA256: SHA256Digest(hex: String(repeating: "22", count: 32)),
    identitySHA256: descriptor.identitySHA256,
    ownerUID: 501,
    authorityRevision: 1)
  return try LeaseView(
    leaseID: AuthorityIdentifier(UUID()), operation: operation,
    state: .starting, expiryMonotonic: 10_000)
}

private func readyEndpoint() throws -> MixedListenerEndpoint {
  try MixedListenerEndpoint(host: "127.0.0.1", port: 7_890)
}

private struct CoordinatorFixture {
  let coordinator: ProxySystemProxyOwnerCoordinator
  let authority: FakeProxyOwnerAuthorityClient
  let engine: FakeProxyEngine
  let preferences: FakeSystemProxyPreferences
  let revocation: ProxyRevocationChannel
  let descriptor: ConfigurationDescriptor
  let lease: LeaseView
  let boundLease: LeaseView
  let orderLog: OrderLog
  let processEnds: ProcessEndRecorder

  func authorization() throws -> ProxyOwnerAuthorization {
    ProxyOwnerAuthorization(
      context: try ProxyOwnerContext(
        operation: lease.operation,
        leaseID: lease.leaseID),
      capability: try OwnerCapability(
        copying: Data(repeating: 0x5, count: AuthorityV1Limits.capabilityBytes)))
  }
}

private func makeFixture(
  slot: ConfigurationSlot = .systemProxy,
  bindThrows: AuthorityDomainError? = nil,
  readyThrows: Bool = false,
  effectiveApplied: Bool = true,
  engineStartFailure: ProxyEngineError? = nil,
  engineCloseFailure: LibboxInstanceUnclosable? = nil,
  preferencesRestoreFailures: Int = 0,
  stoppedAttestationFailures: Int = 0,
  leaseStatuses: [Result<OwnerLeaseStatus, AuthorityDomainError>] = [],
  returnMismatchedLease: Bool = false,
  onBind: @escaping @Sendable () -> Void = {},
  bindGate: BlockingCallGate? = nil,
  stoppedGate: BlockingCallGate? = nil,
  revocation: ProxyRevocationChannel = ProxyRevocationChannel(),
  clockValue: UInt64 = 777,
  leftoverSettings: Bool = false
) throws -> CoordinatorFixture {
  let orderLog = OrderLog()
  let descriptor = try proxyDescriptor(slot: slot)
  let journalStore = FakeJournalStore()
  if leftoverSettings {
    // An earlier agent applied these settings and ended before restoring them.
    try journalStore.save(
      FakeSystemProxyPreferences.journal(
        configuration: descriptor, endpoint: readyEndpoint(), originalValues: [:]))
  }
  let engine = FakeProxyEngine(
    orderLog: orderLog, startFailure: engineStartFailure, closeFailure: engineCloseFailure)
  let processEnds = ProcessEndRecorder()
  let preferences = FakeSystemProxyPreferences(
    orderLog: orderLog,
    restoreFailures: preferencesRestoreFailures)
  let lease = try matchingLease(descriptor)
  let boundLease = returnMismatchedLease ? try mismatchedLease(descriptor) : lease
  let authority = FakeProxyOwnerAuthorityClient(
    orderLog: orderLog,
    bindThrows: bindThrows,
    readyThrows: readyThrows,
    stoppedAttestationFailures: stoppedAttestationFailures,
    onBind: onBind,
    bindGate: bindGate,
    stoppedGate: stoppedGate,
    leaseStatuses: leaseStatuses
  ) { boundLease }
  let lifecycle = ProxySessionLifecycle(
    dependencies: ProxySessionDependencies(
      prepareOwnership: { _ in
        PreparedProxyOwnership(lease: UnleasedProxyOwnership())
      },
      recoverCleanupLease: { _ in UnleasedProxyOwnership() },
      engineFactory: FakeProxyEngineFactory(engine: engine),
      preferences: preferences,
      journalStore: journalStore,
      readinessTimeout: 60,
      endProcess: { failure in
        orderLog.record("endProcess")
        processEnds.record(failure)
      }))
  let coordinator = ProxySystemProxyOwnerCoordinator(
    authority: authority,
    observer: FakeEffectiveSystemProxyObserver(applied: effectiveApplied),
    lifecycle: lifecycle,
    revocation: revocation,
    clock: FakeClock(value: clockValue))
  return CoordinatorFixture(
    coordinator: coordinator, authority: authority, engine: engine,
    preferences: preferences, revocation: revocation,
    descriptor: descriptor, lease: lease, boundLease: boundLease, orderLog: orderLog,
    processEnds: processEnds)
}

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

// MARK: - Tests

@Suite(.serialized)
struct ProxySystemProxyOwnerCoordinatorTests {
  @Test(arguments: [ConfigurationSlot.localProxy, .systemProxy])
  func engineCrashKeepsAuthorityOwnershipUntilExplicitStop(slot: ConfigurationSlot) throws {
    let fixture = try makeFixture(slot: slot)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    fixture.engine.emit(.failed(ProxyEngineFailure(code: "crash", message: "Runtime exited.")))
    let stopped = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stopped.record($0) }
    #expect(stopped.wait())
    #expect(stopped.values == [.success])
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.lease.operation)
    #expect(fixture.preferences.restoreCount == (slot == .systemProxy ? 1 : 0))
  }

  @Test func localProxyAttestsOnlyListenerReadinessAndStopsThroughTheAuthority() throws {
    let fixture = try makeFixture(slot: .localProxy, effectiveApplied: false)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    #expect(fixture.authority.readyAttestations.isEmpty)
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    #expect(fixture.orderLog.values == ["bind", "engine.start"])
    let ready = try #require(fixture.authority.readyAttestations.first)
    #expect(ready.operation.mode == .localProxy)
    #expect(ready.readyFlags == [.libboxStarted, .transportReady])
    #expect(!ready.readyFlags.contains(.operatingSystemStateReady))
    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.lease.operation)
    #expect(fixture.preferences.restoreCount == 0)
  }

  @Test func localProxyCannotStartWithoutAnExactOwnerCapability() throws {
    let fixture = try makeFixture(
      slot: .localProxy, bindThrows: AuthorityDomainError(code: .ticketInvalid))
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())
    #expect(fixture.orderLog.values == ["bind"])
    #expect(fixture.authority.readyAttestations.isEmpty)
    #expect(fixture.authority.stoppedAttestations.isEmpty)
  }

  @Test func localProxyRevocationStillClosesTheListenerAndAttestsStopped() throws {
    let fixture = try makeFixture(slot: .localProxy)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    fixture.revocation.revoke()
    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(fixture.preferences.restoreCount == 0)
  }

  @Test func consumedAuthorizationFailsClosedBeforeAnyMutation() throws {
    let fixture = try makeFixture()
    let authorization = try fixture.authorization()
    let consumed = try authorization.consumeCapability()
    consumed.erase()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: authorization
    ) { start.record($0) }
    try #require(start.wait())

    let outcome = try #require(start.values.first)
    guard case .failure(.authority(.ticketAlreadyRedeemed)) = outcome else {
      Issue.record("Expected fail-closed engine-lease (Authority) failure")
      return
    }
    #expect(fixture.authority.bindCount == 0)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.orderLog.values.isEmpty)
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func rejectedCapabilityFailsClosedBeforeLibboxOrPreferences() throws {
    let fixture = try makeFixture(
      bindThrows: AuthorityDomainError(code: .globalAuthorityIdentityRejected))
    let start = CoordinatorRecorder()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.authority(.globalAuthorityIdentityRejected)) = start.values[0] else {
      Issue.record("Expected fail-closed Authority rejection")
      return
    }
    #expect(fixture.authority.bindCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.orderLog.values == ["bind"])
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func boundLeaseMismatchProvesStoppedAndAttestsExactAuthorityContext() throws {
    let fixture = try makeFixture(returnMismatchedLease: true)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected the mismatched bound lease to fail closed")
      return
    }
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.boundLease.operation)
    #expect(fixture.authority.stoppedAttestations.first?.leaseID == fixture.boundLease.leaseID)
  }

  @Test func boundMismatchAttestationFailureBlocksStartAndRetriesExactProof() throws {
    let fixture = try makeFixture(
      stoppedAttestationFailures: 1,
      returnMismatchedLease: true)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())
    guard case .failure(.cleanupFailed) = start.values[0] else {
      Issue.record("Expected the mismatch and stopped-attestation failures to be preserved")
      return
    }

    let blocked = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { blocked.record($0) }
    #expect(blocked.wait())
    #expect(blocked.values == [.failure(.lifecycleConflict)])
    #expect(fixture.authority.bindCount == 1)

    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 2)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.boundLease.operation)
  }

  @Test func revocationLatchedAfterBindPreventsLocalStartAndAttestsStopped() throws {
    let revocation = ProxyRevocationChannel()
    let fixture = try makeFixture(
      onBind: { revocation.revoke() },
      revocation: revocation)
    let start = CoordinatorRecorder()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected the claim-after-revoke start to fail closed")
      return
    }
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func libboxDeadlineIsFixedWhenTheStartArrivesNotAfterTheBind() throws {
    let bindGate = BlockingCallGate()
    let fixture = try makeFixture(bindGate: bindGate)
    let start = CoordinatorRecorder()
    let receivedBefore = ContinuousClock.now
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    let receivedAfter = ContinuousClock.now
    #expect(bindGate.waitUntilEntered())
    // A slow Authority bind must spend the libbox start's time, not extend it.
    Thread.sleep(forTimeInterval: 0.3)
    bindGate.release()
    #expect(fixture.engine.waitUntilStarted())
    let deadline = try #require(fixture.engine.deadlines.first)
    #expect(fixture.engine.deadlines.count == 1)
    #expect(deadline.instant >= receivedBefore.advanced(by: EngineStartBudget.ownerLibboxStart))
    #expect(deadline.instant <= receivedAfter.advanced(by: EngineStartBudget.ownerLibboxStart))
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
  }

  @Test func explicitStopDuringBindCancelsStartAndWaitsForExactStoppedProof() throws {
    let bindGate = BlockingCallGate()
    let fixture = try makeFixture(bindGate: bindGate)
    let start = CoordinatorRecorder()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(bindGate.waitUntilEntered())

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.values.isEmpty)
    bindGate.release()

    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(start.wait())
    #expect(start.values == [.failure(.startupCancelled)])
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.boundLease.operation)
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func ownerBindingPrecedesLibboxAndPreferencesAndAttestsReadyExactly() throws {
    let fixture = try makeFixture(clockValue: 4_242)
    let authorization = try fixture.authorization()
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: authorization
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    // Binding to the Authority precedes libbox start, which precedes SCPreferences.
    #expect(fixture.orderLog.values == ["bind", "engine.start", "apply"])
    #expect(fixture.authority.bindCount == 1)
    #expect(
      fixture.authority.bindContexts == [
        try ProxyOwnerContext(
          operation: fixture.lease.operation,
          leaseID: fixture.lease.leaseID)
      ])
    #expect(throws: (any Error).self) {
      _ = try authorization.consumeCapability()
    }

    let ready = fixture.authority.readyAttestations
    #expect(ready.count == 1)
    #expect(ready.first?.ownerRole == .proxyAgent)
    #expect(ready.first?.readyFlags == .all)
    #expect(ready.first?.packetPumpLimits == nil)
    #expect(ready.first?.monotonicTimestamp == 4_242)
    #expect(ready.first?.operation.mode == .systemProxy)
    #expect(ready.first?.operation.configSHA256 == fixture.descriptor.sha256)
    #expect(ready.first?.operation.identitySHA256 == fixture.descriptor.identitySHA256)
  }

  @Test func readinessRefusedWhenEffectiveProxyStateIsNotApplied() throws {
    let fixture = try makeFixture(effectiveApplied: false)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    guard case .failure(.authority(.globalAuthorityUnavailable)) = start.values[0] else {
      Issue.record("Expected fail-closed readiness refusal")
      return
    }
    #expect(fixture.authority.readyAttestations.isEmpty)
    // The owned libbox runtime and System Proxy state are torn down on refusal.
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func readyAttestationFailureTearsDownAndFailsClosed() throws {
    let fixture = try makeFixture(readyThrows: true)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    guard case .failure(.authority(.globalAuthorityUnavailable)) = start.values[0] else {
      Issue.record("Expected fail-closed attestation failure")
      return
    }
    #expect(fixture.authority.readyAttestations.count == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func stopAttestsStoppedExactlyWithBoundContext() throws {
    let fixture = try makeFixture(clockValue: 909)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])

    let stopped = fixture.authority.stoppedAttestations
    #expect(stopped.count == 1)
    #expect(stopped.first?.libboxStopped == true)
    #expect(stopped.first?.transportClosed == true)
    #expect(stopped.first?.osRestored == true)
    #expect(stopped.first?.monotonicTimestamp == 909)
    #expect(stopped.first?.operation.mode == .systemProxy)
    #expect(fixture.engine.stopCount == 1)
  }

  /// Starts System Proxy and waits until it is active.
  private func activeFixture(
    stoppedAttestationFailures: Int = 0,
    leaseStatuses: [Result<OwnerLeaseStatus, AuthorityDomainError>] = []
  ) throws -> CoordinatorFixture {
    let fixture = try makeFixture(
      stoppedAttestationFailures: stoppedAttestationFailures, leaseStatuses: leaseStatuses)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    return fixture
  }

  private func stop(_ fixture: CoordinatorFixture) -> [CoordinatorOutcome] {
    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { result in
      fixture.orderLog.record("stopReply")
      stop.record(result)
    }
    #expect(stop.wait())
    return stop.values
  }

  private func snapshotState(_ fixture: CoordinatorFixture) -> EngineStateKind? {
    let snapshot = SnapshotRecorder()
    fixture.coordinator.snapshot { snapshot.record($0) }
    #expect(snapshot.wait())
    return snapshot.values.first?.state.kind
  }

  /// After an Authority restart, or once it recovered, the Authority no longer
  /// holds the lease, so the stopped attestation has nothing to complete. An
  /// owner whose stop finished locally learns that and settles Off; the Host
  /// then proves Off itself.
  @Test func aStopWhoseLeaseTheAuthorityNoLongerHoldsSettlesOff() throws {
    let fixture = try activeFixture(
      stoppedAttestationFailures: 1, leaseStatuses: [.success(.absent)])
    #expect(stop(fixture) == [.success])
    #expect(fixture.authority.leaseStatusQueries == [fixture.lease.leaseID])
    #expect(snapshotState(fixture) == .off)
    // Nothing is left to attest or stop again.
    #expect(stop(fixture) == [.success])
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.processEnds.values.isEmpty)
  }

  /// A lease the Authority still holds, an Authority that cannot tell yet, and
  /// no answer at all prove nothing: the stop keeps its failure and its owner
  /// context, so the next stop attests again.
  @Test(arguments: [
    Result<OwnerLeaseStatus, AuthorityDomainError>.success(.held), .success(.notReady),
    .failure(AuthorityDomainError(code: .globalAuthorityInterrupted)),
  ])
  func aStopWhoseLeaseIsHeldOrUnknownKeepsItsFailure(
    status: Result<OwnerLeaseStatus, AuthorityDomainError>
  ) throws {
    let fixture = try activeFixture(stoppedAttestationFailures: 1, leaseStatuses: [status])
    guard case .failure(.engineLease)? = stop(fixture).first else {
      Issue.record("an unproven stop did not keep its attestation failure")
      return
    }
    #expect(snapshotState(fixture) == .failed)
    #expect(stop(fixture) == [.success])
    #expect(fixture.authority.stoppedAttemptCount == 2)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.processEnds.values.isEmpty)
  }

  /// The Authority refuses the attestation of a stop it quarantined, and
  /// releases the lease once the owner's process ended. The agent, its stop
  /// finished locally, replies and then ends.
  @Test func aStopTheAuthorityQuarantinedEndsTheAgentAfterItsReply() throws {
    let fixture = try activeFixture(
      stoppedAttestationFailures: 1, leaseStatuses: [.success(.quarantined)])
    guard case .failure(.engineLease)? = stop(fixture).first else {
      Issue.record("a quarantined stop did not report its attestation failure")
      return
    }
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.quarantinedStop])
    #expect(Array(fixture.orderLog.values.suffix(3)) == ["leaseStatus", "stopReply", "endProcess"])
  }

  /// Only a stop that finished locally and whose attestation failed asks after
  /// its lease.
  @Test func anAttestedOrLocallyFailedStopAsksNothing() throws {
    let attested = try activeFixture()
    #expect(stop(attested) == [.success])
    #expect(attested.authority.leaseStatusQueries.isEmpty)

    let restoreFailing = try makeFixture(preferencesRestoreFailures: 1)
    let start = CoordinatorRecorder()
    restoreFailing.coordinator.start(
      configuration: restoreFailing.descriptor,
      authorization: try restoreFailing.authorization()
    ) { start.record($0) }
    #expect(restoreFailing.engine.waitUntilStarted())
    restoreFailing.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    guard case .failure(.preferences)? = stop(restoreFailing).first else {
      Issue.record("the restore failure was not reported")
      return
    }
    #expect(restoreFailing.authority.leaseStatusQueries.isEmpty)
  }

  /// A stop that failed because its settings could not be restored ends once
  /// the rights the user granted restored them, as a retried stop would: after
  /// the reply, the agent attests Stopped and its owner context ends, so the
  /// Host's retry asks nothing more of the Authority.
  @Test func aStopWhoseRestoreFailedEndsOnceGrantedRightsRestoredIt() throws {
    let fixture = try restoreFailingFixture()
    #expect(restoreAfterAuthorization(fixture))
    #expect(fixture.authority.waitForStoppedAttempt())
    let settled = ContinuousClock.now.advanced(by: .seconds(2))
    while snapshotState(fixture) != .off {
      guard ContinuousClock.now < settled else {
        Issue.record("the restored stop did not settle Off")
        return
      }
      Thread.sleep(forTimeInterval: 0.01)
    }
    #expect(stop(fixture) == [.success])
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.processEnds.values.isEmpty)
  }

  /// The Authority quarantined the failed stop meanwhile, so it refuses the
  /// attestation, and the agent, its settings restored, ends, which lifts the
  /// quarantine.
  @Test func aFailedStopTheAuthorityQuarantinedEndsTheAgentOnceItsSettingsAreRestored()
    throws
  {
    let fixture = try restoreFailingFixture(
      stoppedAttestationFailures: 1, leaseStatuses: [.success(.quarantined)])
    #expect(restoreAfterAuthorization(fixture))
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.quarantinedStop])
    #expect(fixture.authority.stoppedAttemptCount == 1)
  }

  /// Settings still not restored after the rights were granted leave the
  /// failed stop as it was: nothing is attested, and the agent reports the
  /// same failure.
  @Test func aStopWhoseSettingsStayUnrestoredKeepsItsFailure() throws {
    let fixture = try restoreFailingFixture(preferencesRestoreFailures: 2)
    #expect(restoreAfterAuthorization(fixture))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.preferences.restoreCount == 2)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(snapshotState(fixture) == .failed)
  }

  /// A session whose engine failed while its settings could not be restored
  /// still holds its lease, and the Host, finding the owner Off once granted
  /// rights restored the settings, would never stop it. The agent attests the
  /// session's stop before it answers the rights request, so the Off that
  /// follows finds the lease stopping; the Host's own stop then finds nothing
  /// left to attest.
  @Test func aCrashedSessionsRestoreAttestsItsStopBeforeTheAnswer() throws {
    let stoppedGate = BlockingCallGate()
    let fixture = try makeFixture(preferencesRestoreFailures: 1, stoppedGate: stoppedGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    fixture.engine.emit(.failed(ProxyEngineFailure(code: "crash", message: "Runtime exited.")))
    #expect(snapshotState(fixture) == .failed)

    let replied = DispatchSemaphore(value: 0)
    fixture.coordinator.restoreSettingsAfterAuthorization { replied.signal() }
    #expect(stoppedGate.waitUntilEntered())
    #expect(
      replied.wait(timeout: .now() + .milliseconds(100)) == .timedOut,
      "the rights request was answered before the stop was attested")
    stoppedGate.release()
    #expect(replied.wait(timeout: .now() + 2) == .success)
    #expect(fixture.preferences.restoreCount == 2)
    #expect(fixture.authority.stoppedAttestations.map(\.operation) == [fixture.lease.operation])
    #expect(snapshotState(fixture) == .off)
    #expect(stop(fixture) == [.success])
    #expect(fixture.authority.stoppedAttemptCount == 1)
  }

  /// Granted rights stop no running session: its settings stay applied until
  /// its own stop.
  @Test func grantedRightsLeaveARunningSessionAndItsOwnerAlone() throws {
    let fixture = try activeFixture()
    #expect(restoreAfterAuthorization(fixture))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(snapshotState(fixture) == .proxyActive)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.engine.stopCount == 0)
  }

  /// A System Proxy session whose stop failed because its settings could not
  /// be restored, its engine already stopped.
  private func restoreFailingFixture(
    preferencesRestoreFailures: Int = 1,
    stoppedAttestationFailures: Int = 0,
    leaseStatuses: [Result<OwnerLeaseStatus, AuthorityDomainError>] = []
  ) throws -> CoordinatorFixture {
    let fixture = try makeFixture(
      preferencesRestoreFailures: preferencesRestoreFailures,
      stoppedAttestationFailures: stoppedAttestationFailures, leaseStatuses: leaseStatuses)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    guard case .failure(.preferences)? = stop(fixture).first else {
      Issue.record("the restore failure was not reported")
      return fixture
    }
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    return fixture
  }

  private func restoreAfterAuthorization(_ fixture: CoordinatorFixture) -> Bool {
    let replied = DispatchSemaphore(value: 0)
    fixture.coordinator.restoreSettingsAfterAuthorization { replied.signal() }
    return replied.wait(timeout: .now() + 2) == .success
  }

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

  /// A retiring agent keeps a running System Proxy, its engine and settings,
  /// until its stop restores them, and ends after the stop's reply.
  @Test func aRetiringAgentKeepsItsSystemProxyUntilTheStopThenEnds() throws {
    let fixture = try activeFixture()
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)
    #expect(snapshotState(fixture) == .proxyActive)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.preferences.restoreCount == 0)

    #expect(stop(fixture) == [.success])
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.retired(LibboxInstanceUnclosable(.callDidNotReturn))])
    #expect(fixture.preferences.restoreCount == 1)
    #expect(Array(fixture.orderLog.values.suffix(2)) == ["stopReply", "endProcess"])
  }

  /// The end waits for the stop's attestation and reply.
  @Test func aRetiringAgentEndsOnlyAfterItsStopIsAttestedAndAnswered() throws {
    let stoppedGate = BlockingCallGate()
    let fixture = try makeFixture(stoppedGate: stoppedGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))

    let stopped = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { result in
      fixture.orderLog.record("stopReply")
      stopped.record(result)
    }
    #expect(stoppedGate.waitUntilEntered())
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)
    stoppedGate.release()
    #expect(stopped.wait())
    #expect(fixture.processEnds.wait())
    #expect(Array(fixture.orderLog.values.suffix(2)) == ["stopReply", "endProcess"])
  }

  /// A retiring agent whose stop the Authority did not attest still owns its
  /// lease, so it keeps running; a retried stop that attests ends it.
  @Test func aRetiringAgentWhoseStopWasNotAttestedEndsOnceARetryIs() throws {
    let fixture = try activeFixture(
      stoppedAttestationFailures: 1, leaseStatuses: [.success(.held)])
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    guard case .failure(.engineLease)? = stop(fixture).first else {
      Issue.record("the unattested stop did not keep its failure")
      return
    }
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)
    #expect(stop(fixture) == [.success])
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.retired(LibboxInstanceUnclosable(.callDidNotReturn))])
  }

  /// A start still binding its lease when the agent retires may own that
  /// lease once bound, so the agent ends only after the start finished: a
  /// bound start fails and its stop proves the owner Off, and a start the
  /// Authority refused to bind just fails.
  @Test(arguments: [false, true])
  func aRetiringAgentEndsOnlyOnceItsPendingStartFinished(bindFails: Bool) throws {
    let bindGate = BlockingCallGate()
    let fixture = try makeFixture(
      bindThrows: bindFails ? AuthorityDomainError(code: .ticketInvalid) : nil,
      bindGate: bindGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(bindGate.waitUntilEntered())
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)

    bindGate.release()
    #expect(start.wait())
    #expect(
      start.values == [.failure(bindFails ? .authority(.ticketInvalid) : .agentEnding)])
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.processEnds.wait())
    #expect(fixture.authority.stoppedAttemptCount == (bindFails ? 0 : 1))
  }

  /// A retiring agent that holds only settings an earlier agent left ends
  /// once the rights the user grants restored them.
  @Test func aRetiringAgentWithLeftoverSettingsEndsOnceTheRightsRestoredThem() throws {
    let fixture = try makeFixture(preferencesRestoreFailures: 1, leftoverSettings: true)
    #expect(snapshotState(fixture) == .failed)
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)
    #expect(restoreAfterAuthorization(fixture))
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.retired(LibboxInstanceUnclosable(.callDidNotReturn))])
    #expect(fixture.authority.stoppedAttemptCount == 0)
  }

  /// A retiring agent whose stop could not restore its settings keeps running
  /// until the rights the user grants restore them; it then completes the
  /// stop and ends.
  @Test func aRetiringAgentWhoseRestoreFailedEndsOnceTheRightsRestoredIt() throws {
    let fixture = try restoreFailingFixture()
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)
    #expect(restoreAfterAuthorization(fixture))
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.retired(LibboxInstanceUnclosable(.callDidNotReturn))])
    #expect(fixture.authority.stoppedAttemptCount == 1)
  }

  /// A revocation's stop settles the same way, and once settled a later
  /// revocation finds nothing to stop or attest.
  @Test func aRevokedOwnerWhoseLeaseIsGoneSettlesOnce() throws {
    let fixture = try activeFixture(
      stoppedAttestationFailures: 1, leaseStatuses: [.success(.absent)])
    fixture.revocation.revoke()
    #expect(fixture.authority.waitForStoppedAttempt())
    let settled = ContinuousClock.now.advanced(by: .seconds(2))
    while fixture.authority.leaseStatusQueries.isEmpty || snapshotState(fixture) != .off {
      guard ContinuousClock.now < settled else {
        Issue.record("the revoked owner did not settle Off")
        return
      }
      Thread.sleep(forTimeInterval: 0.01)
    }
    fixture.revocation.revoke()
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.engine.stopCount == 1)
  }

  @Test func unclosableEngineNeverAttestsAndEndsTheProcessAfterTheStopReply() throws {
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    let fixture = try makeFixture(engineCloseFailure: closeFailure)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    let failedStop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { result in
      fixture.orderLog.record("stopReply")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(fixture.processEnds.wait())
    #expect(failedStop.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(Array(fixture.orderLog.values.suffix(2)) == ["stopReply", "endProcess"])
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.authority.stoppedAttestations.isEmpty)

    // The owner context stays bound; a retry reaches neither libbox nor the
    // Authority and ends nothing again.
    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.failure(.engineUnclosable(closeFailure))])
    let snapshot = SnapshotRecorder()
    fixture.coordinator.snapshot { snapshot.record($0) }
    #expect(snapshot.wait())
    #expect(snapshot.values.first?.state.failure?.code == "proxy-engine-unclosable")
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.processEnds.values == [.engineUnclosable(closeFailure)])
  }

  @Test func preferencesCleanupFailureDoesNotAttestOrClearOwnerContext() throws {
    let fixture = try makeFixture(preferencesRestoreFailures: 1)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    let failedStop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) {
      failedStop.record($0)
    }
    #expect(failedStop.wait())
    guard case .failure(.preferences) = failedStop.values[0] else {
      Issue.record("Expected the SCPreferences restore failure to be reported explicitly")
      return
    }
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.authority.stoppedAttestations.isEmpty)

    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(fixture.preferences.restoreCount == 2)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  /// The coordinator keeps the owner context of a stop whose restore failed.
  /// Once the rights the user grants restored the settings, the Host's Off
  /// attests Stopped to the Authority and leaves the agent Off, without
  /// restoring again.
  @Test func settingsRestoredAfterAuthorizationLetTheNextStopAttestStopped() throws {
    let fixture = try makeFixture(preferencesRestoreFailures: 1)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    let failedStop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) {
      failedStop.record($0)
    }
    #expect(failedStop.wait())
    #expect(fixture.authority.stoppedAttemptCount == 0)

    let restored = DispatchSemaphore(value: 0)
    fixture.coordinator.restoreSettingsAfterAuthorization { restored.signal() }
    #expect(restored.wait(timeout: .now() + 1) == .success)
    #expect(fixture.preferences.restoreCount == 2)

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.preferences.restoreCount == 2)
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.lease.operation)
    let snapshot = DispatchSemaphore(value: 0)
    let observed = Mutex<EngineSnapshot?>(nil)
    fixture.coordinator.snapshot { value in
      observed.withLock { $0 = value }
      snapshot.signal()
    }
    #expect(snapshot.wait(timeout: .now() + 1) == .success)
    #expect(observed.withLock { $0 }?.state.kind == .off)
  }

  @Test func stoppedAttestationFailureIsReportedAndRemainsRetryable() throws {
    let fixture = try makeFixture(stoppedAttestationFailures: 1)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    let failedStop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) {
      failedStop.record($0)
    }
    #expect(failedStop.wait())
    guard case .failure(.engineLease) = failedStop.values[0] else {
      Issue.record("Expected the Authority stopped-attestation failure")
      return
    }
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.isEmpty)

    let failedSnapshot = SnapshotRecorder()
    fixture.coordinator.snapshot { failedSnapshot.record($0) }
    #expect(failedSnapshot.wait())
    #expect(failedSnapshot.values.first?.state.kind == .failed)
    #expect(failedSnapshot.values.first?.configuration == fixture.descriptor)

    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 2)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func readinessFailureWithAnUnclosableEngineReportsUnprovenCleanupThenEnds() throws {
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    let fixture = try makeFixture(effectiveApplied: false, engineCloseFailure: closeFailure)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { result in
      fixture.orderLog.record("startReply")
      start.record(result)
    }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(fixture.processEnds.wait())
    guard case .failure(let failure) = start.values[0],
      failure.engineFailure.code == "proxy-cleanup-failed"
    else {
      Issue.record("Expected readiness failure to include the unproven cleanup")
      return
    }
    #expect(Array(fixture.orderLog.values.suffix(2)) == ["startReply", "endProcess"])
    #expect(fixture.authority.readyAttestations.isEmpty)
    #expect(fixture.authority.stoppedAttemptCount == 0)

    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttestations.isEmpty)
    #expect(fixture.processEnds.values == [.engineUnclosable(closeFailure)])
  }

  /// A start whose engine fails and then cannot be closed is answered by the
  /// stop the coordinator queues for that failure, not by the failure itself,
  /// so the process ends only after that later stop handed over the reply.
  @Test func engineStartFailureWithAnUnclosableEngineRepliesBeforeTheProcessEnds() throws {
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    let fixture = try makeFixture(
      engineStartFailure: .runtime("libbox could not close its service instance"),
      engineCloseFailure: closeFailure)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { result in
      fixture.orderLog.record("startReply")
      start.record(result)
    }
    #expect(start.wait())
    #expect(fixture.processEnds.wait())
    guard case .failure(let failure) = start.values.first,
      failure.engineFailure.code == "proxy-cleanup-failed"
    else {
      Issue.record("Expected the failed start to include the unproven cleanup")
      return
    }
    #expect(Array(fixture.orderLog.values.suffix(2)) == ["startReply", "endProcess"])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.readyAttestations.isEmpty)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.processEnds.values == [.engineUnclosable(closeFailure)])
  }

  @Test func revocationOfAnUnclosableOwnerEndsTheProcessOnceWithoutAttesting() throws {
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    let fixture = try makeFixture(engineCloseFailure: closeFailure)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    fixture.revocation.revoke()
    fixture.revocation.revoke()
    #expect(fixture.processEnds.wait())
    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.processEnds.values == [.engineUnclosable(closeFailure)])
  }

  @Test func revocationForcesStopAndAttestsStopped() throws {
    let fixture = try makeFixture()
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    fixture.revocation.revoke()
    #expect(fixture.authority.waitForStoppedAttempt())
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func revocationRetainsContextUntilStoppedAttestationSucceeds() throws {
    let stoppedGate = BlockingCallGate()
    let fixture = try makeFixture(
      stoppedAttestationFailures: 1,
      stoppedGate: stoppedGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    fixture.revocation.revoke()
    #expect(stoppedGate.waitUntilEntered())
    #expect(fixture.authority.waitForStoppedAttempt())
    let joinedStop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) {
      joinedStop.record($0)
    }
    stoppedGate.release()
    #expect(joinedStop.wait())
    guard case .failure(.engineLease) = joinedStop.values[0] else {
      Issue.record("Expected the joined stop to observe the failed attestation")
      return
    }
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.isEmpty)

    // Revocation is idempotently retryable after local Off because the exact owner
    // context was retained when the first Authority attestation failed.
    fixture.revocation.revoke()
    #expect(fixture.authority.waitForStoppedAttempt())
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 2)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func concurrentExplicitStopAndRevocationShareOneStopTransaction() throws {
    let stoppedGate = BlockingCallGate()
    let fixture = try makeFixture(stoppedGate: stoppedGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stoppedGate.waitUntilEntered())
    fixture.revocation.revoke()
    stoppedGate.release()

    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }
}

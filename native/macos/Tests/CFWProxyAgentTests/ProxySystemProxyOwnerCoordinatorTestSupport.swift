import CFWSharedProtocol
import Foundation
import Synchronization
import Testing

@testable import CFWCredentialTransport
@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// The coordinator fixture: a test harness start, recorders and latches, and
// the builders of descriptors, leases and fixtures. The owner binding
// integration tests share its fixture error, order log and recorder.
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

enum CoordinatorFixtureError: Error { case forced }

// MARK: - Ordering / recorders

final class OrderLog: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []
  func record(_ event: String) { lock.withLock { events.append(event) } }
  var values: [String] { lock.withLock { events } }
}

enum CoordinatorOutcome: Equatable {
  case success
  case failure(ProxySessionLifecycleError)
}

final class CoordinatorRecorder: @unchecked Sendable {
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
final class AsyncTestLatch: @unchecked Sendable {
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

final class ProcessEndRecorder: @unchecked Sendable {
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

final class SnapshotRecorder: @unchecked Sendable {
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

final class BlockingCallGate: @unchecked Sendable {
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

struct CoordinatorFixture {
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

func makeFixture(
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

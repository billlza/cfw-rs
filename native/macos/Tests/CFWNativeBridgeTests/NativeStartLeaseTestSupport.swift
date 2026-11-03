import CFWCredentialTransport
import CFWCredentialVault
import CryptoKit
import Foundation
@preconcurrency import NetworkExtension
@preconcurrency import SystemExtensions
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Engine lease and build fakes for the start command tests: fixed, conflicting
// and recording leases, a replay cursor, an earlier ProxyAgent build, and a
// preparer that advances the cursor.
/// Reports an exact Authority ownership observation. Concrete production inspectors
/// override the default coarse derivation; this stub returns the exact observation
/// so start-path activation agreement can be exercised deterministically.
struct FixedEngineLease: NativeEngineLeaseInspecting {
  let observation: AuthorityOwnershipObservation
  func isAvailable() async throws -> Bool { observation.state == .off }
  func authorityOwnership() async throws -> AuthorityOwnershipObservation { observation }
  func beginStop(
    for descriptor: ConfigurationDescriptor
  ) async throws -> NativeAuthorityStopContext {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop boundary")
  }
  func completeStop(_ context: NativeAuthorityStopContext) async throws {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop boundary")
  }
}

/// Reports the running ProxyAgent as an earlier build than this app's, as in
/// the window before an update replaces it, or an inspection that fails.
struct EarlierProxyBuildObserver: CurrentAppServiceBuildObserving {
  let fails: Bool

  func inspect() throws -> CurrentAppServiceBuildInspection {
    if fails { throw CurrentAppServiceBuildError.identityUnavailable }
    let current = try CurrentAppServiceCodeIdentity(
      build: 50010, cdHash: Data(repeating: 0x42, count: 20))
    let earlier = try CurrentAppServiceCodeIdentity(
      build: 50009, cdHash: Data(repeating: 0x41, count: 20))
    return .init(
      proxy: CurrentAppServiceBuildObservation(
        registration: .enabled, runningCode: earlier, expectedCode: current),
      authority: CurrentAppServiceBuildObservation(
        registration: .enabled, runningCode: current, expectedCode: current))
  }
}

/// An Authority whose lease another user holds: this Host cannot observe it.
struct ConflictingEngineLease: NativeEngineLeaseInspecting {
  func isAvailable() async throws -> Bool { false }
  func authorityOwnership() async throws -> AuthorityOwnershipObservation {
    throw AuthorityDomainError(code: .globalLeaseConflict)
  }
  func beginStop(
    for descriptor: ConfigurationDescriptor
  ) async throws -> NativeAuthorityStopContext {
    throw AuthorityDomainError(code: .globalLeaseConflict)
  }
  func completeStop(_ context: NativeAuthorityStopContext) async throws {
    throw AuthorityDomainError(code: .globalLeaseConflict)
  }
}

/// The installation, epoch and generation a replay cursor names.
private struct FakeReplayCursor: Equatable {
  let installationID: UUID
  let epoch: UInt64
  let generation: UInt64

  init(_ context: EngineCommandContext) {
    installationID = context.installationID
    epoch = context.configEpoch
    generation = context.generation
  }

  init(_ lease: AuthorityLeaseAgreement) {
    installationID = lease.installationID
    epoch = lease.epoch
    generation = lease.generation
  }

  init(_ root: RootContext) {
    installationID = root.installationID.rawValue
    epoch = root.epoch
    generation = root.generation
  }

  init(_ descriptor: ConfigurationDescriptor) {
    installationID = descriptor.installationID
    epoch = descriptor.epoch
    generation = descriptor.generation
  }
}

/// Moves a recording Authority's replay cursor as each System Proxy
/// preparation the preparer grants does, so the fake's cursor names the
/// generation the Authority's would.
struct CursorAdvancingSystemProxyStartPreparer: SystemProxyStartPreparing {
  let preparer: any SystemProxyStartPreparing
  let lease: RecordingEngineLease

  func prepareSystemProxyStart(
    configuration: Data,
    descriptor: ConfigurationDescriptor
  ) async throws -> HostPreparedSystemProxyStart {
    let prepared = try await preparer.prepareSystemProxyStart(
      configuration: configuration, descriptor: descriptor)
    await lease.prepared(descriptor)
    return prepared
  }

  func cancelSystemProxyStart(_ prepared: HostPreparedSystemProxyStart) async throws {
    try await preparer.cancelSystemProxyStart(prepared)
  }
}

actor RecordingEngineLease: NativeEngineLeaseInspecting {
  private var observation: AuthorityOwnershipObservation
  private var remainingBeginFailures: Int
  private var remainingCompleteFailures: Int
  private var remainingOwnershipFailures: Int
  private let recoveredStop: NativeRecoveredStop?
  private let completeError: AuthorityDomainError?
  private let completeFailureCommits: Bool
  private let cancelPreparedResult: Bool
  private let cleanupEvents: NativeCleanupEventLog?
  private var stopContext: NativeAuthorityStopContext?
  /// The generation the replay cursor names. Preparing a start moves it to
  /// that start's generation, so an Authority that holds a lease names the
  /// lease's generation from the start.
  private var cursor: FakeReplayCursor?
  /// The lease this fake started with reached Off through its own completion
  /// or reconciliation, or a later start passed it, so no stop can order it
  /// any more.
  private var leaseEnded = false
  private var stopResolutionFailure: AuthorityDomainError?
  private(set) var beginCalls = 0
  private(set) var completeCalls = 0
  private(set) var reconcileCalls = 0
  private(set) var recoverCalls = 0
  private(set) var cancelPreparedCalls = 0

  init(
    observation: AuthorityOwnershipObservation,
    beginFailures: Int = 0,
    completeFailures: Int = 0,
    ownershipFailures: Int = 0,
    recoveredStop: NativeRecoveredStop? = nil,
    completeError: AuthorityDomainError? = nil,
    completeFailureCommits: Bool = false,
    cancelPreparedResult: Bool = false,
    cleanupEvents: NativeCleanupEventLog? = nil,
    replayContext: EngineCommandContext? = nil
  ) {
    self.observation = observation
    remainingBeginFailures = beginFailures
    remainingCompleteFailures = completeFailures
    remainingOwnershipFailures = ownershipFailures
    self.recoveredStop = recoveredStop
    self.completeError = completeError
    self.completeFailureCommits = completeFailureCommits
    self.cancelPreparedResult = cancelPreparedResult
    self.cleanupEvents = cleanupEvents
    cursor =
      replayContext.map(FakeReplayCursor.init(_:)) ?? observation.lease.map(FakeReplayCursor.init)
  }

  func isAvailable() -> Bool { observation.state == .off }

  func authorityOwnership() throws -> AuthorityOwnershipObservation {
    if remainingOwnershipFailures > 0 {
      remainingOwnershipFailures -= 1
      throw NativeBridgeExecutionError.failure(
        .unavailable,
        "Injected Authority ownership observation failure.")
    }
    return observation
  }

  func reconcileOff(
    managedTunnel: RecoveryManagedTunnelStatus
  ) throws -> AuthorityOwnershipObservation {
    reconcileCalls += 1
    guard observation.state == .recovering,
      managedTunnel == .disconnected || managedTunnel == .invalid
    else {
      throw AuthorityDomainError(code: .cleanupUnproven)
    }
    observation = AuthorityOwnershipObservation(state: .off, lease: nil)
    leaseEnded = true
    return observation
  }

  /// The stop deadline passed before the owner attested Stopped.
  func quarantine() {
    observation = AuthorityOwnershipObservation(state: .quarantined, lease: nil)
  }

  /// The Authority recovers in memory once the quarantined owner ended: it holds
  /// no lease, and its replay cursor names `context`, which reconciling Off
  /// keeps.
  /// The Authority prepared a start of `descriptor`'s generation, which moves
  /// the replay cursor there and holds a lease that has not ended. Tests set
  /// the lease the Authority reports themselves. The Authority refuses to
  /// prepare a generation behind its cursor, so a test that does has a setup
  /// production cannot reach.
  func prepared(_ descriptor: ConfigurationDescriptor) {
    let prepared = FakeReplayCursor(descriptor)
    if let cursor, cursor.installationID == prepared.installationID,
      (prepared.epoch, prepared.generation) < (cursor.epoch, cursor.generation)
    {
      Issue.record("a prepare moved the replay cursor backwards, which the Authority refuses")
    }
    cursor = prepared
    leaseEnded = false
  }

  func recoverFromEndedOwner(of context: EngineCommandContext) {
    observation = AuthorityOwnershipObservation(state: .recovering, lease: nil)
    cursor = FakeReplayCursor(context)
  }

  /// The Authority lost its durable store, as a removed and reinstalled one
  /// does: it is Off and holds no record of any generation.
  func loseStore() {
    observation = AuthorityOwnershipObservation(state: .off, lease: nil)
    cursor = nil
    leaseEnded = true
  }

  /// A later start, prepared from a proven Off, moved the replay cursor to
  /// `cursor`; the Authority now holds `lease` in `state`.
  func passGeneration(
    to cursor: EngineCommandContext, state: AuthorityState,
    lease: AuthorityLeaseAgreement? = nil
  ) {
    self.cursor = FakeReplayCursor(cursor)
    observation = AuthorityOwnershipObservation(state: state, lease: lease)
    leaseEnded = true
  }

  private func cursorPasses(
    installationID: UUID, epoch: UInt64, generation: UInt64
  ) -> Bool {
    guard let cursor, cursor.installationID == installationID else { return false }
    return (cursor.epoch, cursor.generation) > (epoch, generation)
  }

  func recoverStoppingLease() -> NativeRecoveredStop? {
    recoverCalls += 1
    return observation.state == .stopping ? recoveredStop : nil
  }

  func cancelPreparedStart(for descriptor: ConfigurationDescriptor) -> Bool {
    cancelPreparedCalls += 1
    cleanupEvents?.append("cancel-prepared")
    // A cursor past the start shows its preparation ended; Recovering holds no
    // preparation; Off still needs the Host's proof.
    if cursorPasses(
      installationID: descriptor.installationID, epoch: descriptor.epoch,
      generation: descriptor.generation)
    {
      return true
    }
    if observation.state == .recovering { return true }
    if cancelPreparedResult {
      observation = AuthorityOwnershipObservation(state: .off, lease: nil)
    }
    return cancelPreparedResult
  }

  func beginStop(
    for descriptor: ConfigurationDescriptor
  ) throws -> NativeAuthorityStopContext {
    beginCalls += 1
    cleanupEvents?.append("begin-stop")
    if observation.state == .recovering {
      throw AuthorityDomainError(code: .globalAuthorityRecovering)
    }
    // As the production inspector: a quarantined Authority, or one whose lease
    // ended, holds no lease to order.
    if observation.state == .quarantined || leaseEnded {
      throw AuthorityDomainError(code: .staleOperation)
    }
    if remainingBeginFailures > 0 {
      remainingBeginFailures -= 1
      throw NativeBridgeExecutionError.failure(
        .unavailable,
        "Injected Authority begin-stop failure.")
    }
    if let stopContext { return stopContext }
    let mode = descriptor.slot.authorityMode
    let operation = try OperationContext(
      operationID: AuthorityIdentifier(UUID()),
      root: RootContext(
        installationID: AuthorityIdentifier(descriptor.installationID),
        epoch: descriptor.epoch,
        generation: descriptor.generation),
      mode: mode,
      configSHA256: descriptor.sha256,
      identitySHA256: descriptor.identitySHA256,
      ownerUID: 501,
      authorityRevision: 1)
    let context = NativeAuthorityStopContext(
      operation: operation,
      leaseID: AuthorityIdentifier(UUID()))
    stopContext = context
    return context
  }

  func completeStop(_ context: NativeAuthorityStopContext) throws {
    completeCalls += 1
    cleanupEvents?.append("complete-stop")
    if observation.state == .recovering {
      throw AuthorityDomainError(code: .globalAuthorityRecovering)
    }
    // A quarantined Authority, or one a later start passed, holds no stop to
    // complete.
    let root = context.operation.root
    if observation.state == .quarantined
      || cursorPasses(
        installationID: root.installationID.rawValue, epoch: root.epoch,
        generation: root.generation)
    {
      throw AuthorityDomainError(code: .cleanupUnproven)
    }
    if let completeError { throw completeError }
    if remainingCompleteFailures > 0 {
      remainingCompleteFailures -= 1
      if completeFailureCommits {
        observation = AuthorityOwnershipObservation(state: .off, lease: nil)
        leaseEnded = true
        cursor = FakeReplayCursor(context.operation.root)
      }
      throw NativeBridgeExecutionError.failure(
        .unavailable,
        "Injected Authority complete-stop failure.")
    }
    observation = AuthorityOwnershipObservation(state: .off, lease: nil)
    leaseEnded = true
    cursor = FakeReplayCursor(context.operation.root)
  }

  /// As the production inspector reads one snapshot.
  func stopResolution(_ context: EngineCommandContext) throws -> NativeStopResolution {
    if let stopResolutionFailure {
      self.stopResolutionFailure = nil
      throw stopResolutionFailure
    }
    let leaseOfStop = observation.lease.map {
      $0.installationID == context.installationID && $0.epoch == context.configEpoch
        && $0.generation == context.generation
    }
    if cursorPasses(
      installationID: context.installationID, epoch: context.configEpoch,
      generation: context.generation), leaseOfStop != true
    {
      return .superseded
    }
    return observation.state == .off && observation.lease == nil
      && cursor == FakeReplayCursor(context) ? .completed : .unresolved
  }

  /// The next stop-resolution check fails, as an unreachable Authority does.
  func failNextStopResolution(with error: AuthorityDomainError) {
    stopResolutionFailure = error
  }

  func counters() -> (begin: Int, complete: Int) {
    (beginCalls, completeCalls)
  }

  func reconcileCount() -> Int { reconcileCalls }
  func recoverCount() -> Int { recoverCalls }
  func cancelPreparedCount() -> Int { cancelPreparedCalls }
  func currentState() -> AuthorityState { observation.state }
}

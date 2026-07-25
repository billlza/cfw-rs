import CFWSharedProtocol
import Darwin
import Foundation

extension GlobalAuthorityReducer {
  /// Reconstructs the reducer from a validated journal recovery to the exact durable
  /// high-water state. A committed record restores the immutable installation ID,
  /// epoch, generation, and revision cursor; the machine enters Recovering (starts
  /// rejected until owner and OS Off are reconciled) or Quarantined. Tickets and
  /// secrets are intentionally never reconstructed.
  public static func reconciled(
    from recovery: AuthorityJournalRecovery
  ) throws -> GlobalAuthorityReducer {
    guard let state = recovery.committedState, let head = recovery.head else {
      switch recovery.posture {
      case .recovering:
        return try .unEnrolledOff()
      case .quarantined:
        return try GlobalAuthorityReducer(state: .quarantined, revision: 1)
      }
    }
    let cursor = try ReplayCursor(
      installationID: state.installationID,
      acceptedEpoch: state.epoch,
      acceptedGeneration: state.generation,
      revision: state.revision,
      previousRecordSHA256: head.recordSHA256)
    switch recovery.posture {
    case .recovering:
      return try .recovering(revision: state.revision, replayCursor: cursor)
    case .quarantined:
      return try GlobalAuthorityReducer(
        state: .quarantined, revision: state.revision, replayCursor: cursor)
    }
  }
}

/// Owner-side fail-closed policy. When an owner (ProxyAgent or Provider) loses the
/// Authority channel, it must stop libbox and restore/close owned network state within
/// a bounded grace period; the Authority being unreachable is never permission to keep
/// running indefinitely. Pure and clock-injected so owners can decide deterministically.
public struct AuthorityGracePeriod: Equatable, Sendable {
  public let graceMilliseconds: UInt64

  public init(
    graceMilliseconds: UInt64 = AuthorityV1Limits.commandTimeoutMilliseconds
  ) {
    self.graceMilliseconds = graceMilliseconds
  }

  /// True once the grace period since the last successful Authority contact has
  /// elapsed, at which point the owner must fail closed.
  public func mustFailClosed(
    lastAuthorityContactMonotonic: UInt64, now: UInt64
  ) -> Bool {
    guard now >= lastAuthorityContactMonotonic else { return false }
    return now - lastAuthorityContactMonotonic >= graceMilliseconds
  }
}

/// The action the liveness supervisor took on a single evaluation tick.
public enum AuthorityLivenessAction: Equatable, Sendable {
  case none
  case forcedStop(AuthorityLivenessTrigger)
  case quarantinedForUnprovenCleanup
}

/// Wires bounded owner heartbeat tracking, the public live-console-user observation,
/// and the five-second owner stop/reattest timeout to the Authority core. All external
/// inputs are behind injectable seams (clock, console resolver) so behavior is fully
/// deterministic in tests; the supervisor never touches launchd, Network Extension, or
/// SystemConfiguration directly.
public final class AuthorityLivenessSupervisor: @unchecked Sendable {
  /// Owners renew liveness at least this often; a missed renewal past this bound is
  /// treated as owner loss and forces a stop.
  public static let heartbeatTimeoutMilliseconds: UInt64 =
    AuthorityV1Limits.commandTimeoutMilliseconds

  private let core: GlobalAuthorityServiceCore
  private let clock: any AuthorityMonotonicClock
  private let consoleResolver: any LiveConsoleUserResolving
  private let events: AuthorityEventHub
  private let heartbeatTimeoutMilliseconds: UInt64

  private let lock = NSLock()
  private var lastHeartbeatMonotonic: UInt64?
  private var stopOrderedMonotonic: UInt64?

  public init(
    core: GlobalAuthorityServiceCore,
    clock: any AuthorityMonotonicClock = SystemAuthorityMonotonicClock(),
    consoleResolver: any LiveConsoleUserResolving =
      SystemConfigurationLiveConsoleUserResolver(),
    events: AuthorityEventHub = AuthorityEventHub(),
    heartbeatTimeoutMilliseconds: UInt64 = heartbeatTimeoutMilliseconds
  ) {
    self.core = core
    self.clock = clock
    self.consoleResolver = consoleResolver
    self.events = events
    self.heartbeatTimeoutMilliseconds = heartbeatTimeoutMilliseconds
  }

  /// Records a fresh owner heartbeat. Bounded to a single monotonic timestamp per
  /// owner; the channel carries no owner-supplied identity or secret material.
  public func recordHeartbeat() {
    lock.withLock { lastHeartbeatMonotonic = clock.nowMilliseconds() }
  }

  /// Re-resolves the public live console user and forces a stop when the owner's user
  /// is no longer the live console user. Emits the revocation to the owner peer.
  @discardableResult
  public func observeConsoleUser() throws -> AuthorityLivenessAction {
    let liveConsoleUID = consoleResolver.liveConsoleUID()
    guard let outcome = try core.observeLiveConsoleUser(liveConsoleUID) else {
      return .none
    }
    deliver(outcome)
    return .forcedStop(.consoleUserChange)
  }

  /// Forces a stop for connection loss, owner identity drift, or logout.
  @discardableResult
  public func forceStop(
    _ trigger: AuthorityLivenessTrigger
  ) throws -> AuthorityLivenessAction {
    guard let outcome = try core.forceStop(trigger: trigger) else { return .none }
    deliver(outcome)
    return .forcedStop(trigger)
  }

  /// One deterministic liveness tick. Forces a stop when the owner heartbeat is stale,
  /// and escalates an owner that has not attested stopped within the timeout to
  /// Quarantined (cleanup cannot be proven, so the machine never returns to Off).
  @discardableResult
  public func evaluate() throws -> AuthorityLivenessAction {
    let now = clock.nowMilliseconds()
    switch core.authorityState {
    case .preparing, .starting, .active:
      let stale = lock.withLock { () -> Bool in
        guard let last = lastHeartbeatMonotonic else { return false }
        return now >= last && now - last >= heartbeatTimeoutMilliseconds
      }
      guard stale else { return .none }
      guard let outcome = try core.forceStop(trigger: .missedHeartbeat) else {
        return .none
      }
      lock.withLock { stopOrderedMonotonic = now }
      deliver(outcome)
      return .forcedStop(.missedHeartbeat)
    case .stopping:
      let elapsed = lock.withLock { () -> Bool in
        guard let ordered = stopOrderedMonotonic else { return false }
        return now >= ordered
          && now - ordered >= AuthorityV1Limits.stopAttestationTimeoutMilliseconds
      }
      guard elapsed, !core.ownerHasAttestedStopped else { return .none }
      _ = try core.resolveOff(Self.unprovenCleanupProof)
      lock.withLock { stopOrderedMonotonic = nil }
      return .quarantinedForUnprovenCleanup
    case .off, .recovering, .quarantined:
      return .none
    }
  }

  /// Marks that a stop was ordered at the current time so a subsequent `evaluate`
  /// can enforce the five-second owner stop/reattest timeout.
  public func noteStopOrdered() {
    lock.withLock { stopOrderedMonotonic = clock.nowMilliseconds() }
  }

  private func deliver(_ outcome: AuthorityForcedStopOutcome) {
    lock.withLock { stopOrderedMonotonic = clock.nowMilliseconds() }
    guard let directive = outcome.directive, let peerID = outcome.ownerPeerID else {
      return
    }
    events.send(.revoke(directive), to: peerID)
  }

  /// An unproven cleanup proof: unknown owner/OS observation. `applyOffProof` retains
  /// Quarantined for any such ambiguity rather than committing Off.
  private static let unprovenCleanupProof = GlobalOffProof(
    leaseReleased: false, capabilityOrTicketCleared: false,
    secretBufferCleared: false, ownerEndpointCleared: false,
    cleanup: .unknown, managedTunnel: .unknown)
}

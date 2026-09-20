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
      case .recovering(.restoreAnchorAccess):
        return try GlobalAuthorityReducer(state: .recovering, revision: 1)
      case .recovering:
        return try .unEnrolledOff()
      case .quarantined:
        return try GlobalAuthorityReducer(state: .quarantined, revision: 1)
      }
    }
    if state.transition == .enrollOff {
      switch recovery.posture {
      case .recovering:
        return try .enrolledOff(
          installationID: state.installationID,
          revision: state.revision)
      case .quarantined:
        return try GlobalAuthorityReducer(
          state: .quarantined,
          revision: state.revision,
          enrolledInstallationID: state.installationID)
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
  case expiredPreparation
  case forcedStop(AuthorityLivenessTrigger)
  case quarantinedForUnprovenCleanup
}

/// Wires bounded owner heartbeat tracking, the public live-console-user observation,
/// and the five-second owner stop/reattest timeout to the Authority core. All external
/// inputs are behind injectable seams (the core clock and console resolver) so behavior is fully
/// deterministic in tests; the supervisor never touches launchd, Network Extension, or
/// SystemConfiguration directly.
public final class AuthorityLivenessSupervisor: @unchecked Sendable {
  /// Owners renew liveness at least this often; a missed renewal past this bound is
  /// treated as owner loss and forces a stop.
  public static let heartbeatTimeoutMilliseconds: UInt64 =
    AuthorityV1Limits.commandTimeoutMilliseconds

  private let core: GlobalAuthorityServiceCore
  private let consoleResolver: any LiveConsoleUserResolving
  private let events: AuthorityEventHub
  private let heartbeatTimeoutMilliseconds: UInt64

  public init(
    core: GlobalAuthorityServiceCore,
    consoleResolver: any LiveConsoleUserResolving =
      SystemConfigurationLiveConsoleUserResolver(),
    events: AuthorityEventHub = AuthorityEventHub(),
    heartbeatTimeoutMilliseconds: UInt64 = heartbeatTimeoutMilliseconds
  ) {
    self.core = core
    self.consoleResolver = consoleResolver
    self.events = events
    self.heartbeatTimeoutMilliseconds = heartbeatTimeoutMilliseconds
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

  /// Called from the public SystemConfiguration ConsoleUser notification. A
  /// GUI session transition revokes the old lease even when logout/login reuses
  /// the same numeric UID; screen locking does not change this key.
  @discardableResult
  public func observeConsoleSessionChange() throws -> AuthorityLivenessAction {
    try forceStop(.consoleUserChange)
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
    switch core.authorityState {
    case .preparing:
      return try core.expireUnboundPreparationIfNeeded()
        ? .expiredPreparation : .none
    case .starting, .active:
      guard
        let outcome = try core.revokeExpiredHeartbeatIfNeeded(
          timeoutMilliseconds: heartbeatTimeoutMilliseconds)
      else {
        return .none
      }
      deliver(outcome)
      return .forcedStop(.missedHeartbeat)
    case .stopping:
      return try core.quarantineExpiredStopIfNeeded()
        ? .quarantinedForUnprovenCleanup : .none
    case .off, .recovering, .quarantined:
      return .none
    }
  }

  private func deliver(_ outcome: AuthorityForcedStopOutcome) {
    guard let directive = outcome.directive else { return }
    guard let peerID = outcome.ownerPeerID else { return }
    events.send(.revoke(directive), to: peerID)
  }
}

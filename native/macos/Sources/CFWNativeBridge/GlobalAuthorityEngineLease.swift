import CFWSharedProtocol
import Foundation

/// Machine-wide Proxy/Tunnel/multi-user engine exclusion is enforced solely through
/// the Global Authority lease. This inspector reports availability from the
/// Authority's durable machine-wide state rather than any provider-local rendezvous:
/// a fresh owner may be admitted only when the Authority proves the global Off state.
///
/// It fails closed. Any Authority unavailability, recovery, protocol incompatibility,
/// or transport error surfaces as a typed Authority error to the coordinator instead
/// of being treated as "available", so an unproven boundary can never admit a second
/// engine owner.
struct GlobalAuthorityEngineLeaseInspector: NativeEngineLeaseInspecting {
  private let authority: any AuthorityClient

  init(authority: any AuthorityClient) {
    self.authority = authority
  }

  func isAvailable() async throws -> Bool {
    let snapshot = try await authority.snapshot()
    return snapshot.state == .off
  }

  /// Projects the durable Authority snapshot into the non-secret ownership
  /// observation used for exact activation agreement. The bound lease's
  /// `Operation_Context` and configuration digests are surfaced so the coordinator
  /// can require exact lease/context/digest/owner-ready agreement before declaring
  /// an owner Active. No secrets, tickets, or credentials are exposed.
  func authorityOwnership() async throws -> AuthorityOwnershipObservation {
    let snapshot = try await authority.snapshot()
    return Self.observation(snapshot)
  }

  func reconcileOff(
    managedTunnel: RecoveryManagedTunnelStatus
  ) async throws -> AuthorityOwnershipObservation {
    guard managedTunnel == .disconnected || managedTunnel == .invalid else {
      throw AuthorityDomainError(code: .cleanupUnproven)
    }
    let snapshot = try await authority.snapshot()
    guard snapshot.state == .recovering,
      snapshot.leaseView == nil,
      let cursor = snapshot.replayCursor,
      cursor.revision == snapshot.revision
    else {
      throw AuthorityDomainError(code: .globalAuthorityRecovering)
    }
    let request = try ReconcileOffRequest(
      expectedRevision: snapshot.revision,
      replayCursor: cursor,
      proxy: RecoveryProxyOffEvidence(
        ownershipCleared: true,
        listenerClosed: true,
        effectiveSystemConfigurationRestored: true),
      provider: RecoveryProviderOffEvidence(
        ownershipCleared: true,
        libboxStopped: true,
        packetPumpClosed: true),
      managedTunnel: managedTunnel)
    let receipt = try await authority.reconcileOff(request)
    guard receipt.replayCursor == cursor,
      receipt.revision == snapshot.revision + 1
    else {
      throw AuthorityDomainError(code: .staleOperation)
    }
    let reconciled = try await authority.snapshot()
    guard reconciled.state == .off,
      reconciled.revision == receipt.revision,
      reconciled.leaseView == nil
    else {
      throw AuthorityDomainError(code: .cleanupUnproven)
    }
    return Self.observation(reconciled)
  }

  func recoverStoppingLease() async throws -> NativeRecoveredStop? {
    let snapshot = try await authority.snapshot()
    switch snapshot.state {
    case .stopping:
      guard let lease = snapshot.leaseView,
        lease.state == .stopping || lease.state == .revoked
      else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }
      return try NativeRecoveredStop(
        operation: lease.operation,
        leaseID: lease.leaseID)
    case .quarantined:
      throw AuthorityDomainError(code: .quarantined)
    case .recovering:
      throw AuthorityDomainError(code: .globalAuthorityRecovering)
    case .off, .preparing, .starting, .active:
      return nil
    }
  }

  func cancelPreparedStart(
    for descriptor: ConfigurationDescriptor
  ) async throws -> Bool {
    let snapshot = try await authority.snapshot()
    switch try Self.preparedCancellationDisposition(snapshot, descriptor: descriptor) {
    case .alreadyOff:
      return true
    case .ownerControlled:
      return false
    case .cancel(let lease):
      do {
        try await authority.cancelPrepared(
          lease.operation,
          revision: snapshot.revision)
      } catch {
        let observed = try await authority.snapshot()
        switch try Self.preparedCancellationDisposition(
          observed,
          descriptor: descriptor)
        {
        case .alreadyOff:
          return true
        case .ownerControlled:
          return false
        case .cancel:
          throw error
        }
      }
      let observed = try await authority.snapshot()
      guard
        try Self.preparedCancellationDisposition(
          observed,
          descriptor: descriptor) == .alreadyOff
      else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }
      return true
    }
  }

  func beginStop(
    for descriptor: ConfigurationDescriptor
  ) async throws -> NativeAuthorityStopContext {
    let snapshot = try await authority.snapshot()
    guard [.starting, .active, .stopping].contains(snapshot.state),
      let lease = snapshot.leaseView,
      Self.matches(lease.operation, descriptor: descriptor)
    else {
      throw AuthorityDomainError(code: .staleOperation)
    }
    let request = try BeginStopRequest(
      operation: lease.operation,
      leaseID: lease.leaseID,
      expectedRevision: snapshot.revision)
    let directive = try await authority.beginStop(request)
    let (nextRevision, overflow) = snapshot.revision.addingReportingOverflow(1)
    let revisionIsValid =
      snapshot.state == .stopping
      ? directive.revision == snapshot.revision
      : !overflow && directive.revision == nextRevision
    guard directive.operation == lease.operation,
      directive.leaseID == lease.leaseID,
      revisionIsValid
    else {
      throw AuthorityDomainError(code: .staleOperation)
    }
    return NativeAuthorityStopContext(
      operation: lease.operation,
      leaseID: lease.leaseID)
  }

  func completeStop(_ context: NativeAuthorityStopContext) async throws {
    let snapshot = try await authority.snapshot()
    if Self.isCompleted(snapshot, context: context) {
      return
    }
    guard snapshot.state == .stopping,
      let lease = snapshot.leaseView,
      lease.operation == context.operation,
      lease.leaseID == context.leaseID
    else {
      throw AuthorityDomainError(code: .cleanupUnproven)
    }
    try await authority.completeStop(
      CompleteStopRequest(
        operation: context.operation,
        leaseID: context.leaseID,
        expectedRevision: snapshot.revision))
  }

  /// A completion reply can be lost after the Authority durably commits Off. The
  /// replay cursor's exact installation/epoch/generation tuple is monotonic and
  /// unique, so this is the only safe idempotent success projection after the lease
  /// itself has been cleared.
  private static func isCompleted(
    _ snapshot: AuthoritySnapshot,
    context: NativeAuthorityStopContext
  ) -> Bool {
    guard snapshot.state == .off,
      snapshot.leaseView == nil,
      let cursor = snapshot.replayCursor
    else { return false }
    return cursor.installationID == context.operation.root.installationID
      && cursor.acceptedEpoch == context.operation.root.epoch
      && cursor.acceptedGeneration == context.operation.root.generation
  }

  private static func matches(
    _ operation: OperationContext,
    descriptor: ConfigurationDescriptor
  ) -> Bool {
    let expectedMode: AuthorityMode =
      descriptor.slot == .systemProxy ? .systemProxy : .tunnel
    return operation.mode == expectedMode
      && operation.root.installationID.rawValue == descriptor.installationID
      && operation.root.epoch == descriptor.epoch
      && operation.root.generation == descriptor.generation
      && operation.configSHA256 == descriptor.sha256
      && operation.identitySHA256 == descriptor.identitySHA256
  }

  private enum PreparedCancellationDisposition: Equatable {
    case alreadyOff
    case cancel(LeaseView)
    case ownerControlled
  }

  private static func preparedCancellationDisposition(
    _ snapshot: AuthoritySnapshot,
    descriptor: ConfigurationDescriptor
  ) throws -> PreparedCancellationDisposition {
    switch snapshot.state {
    case .off:
      guard snapshot.leaseView == nil else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }
      if let cursor = snapshot.replayCursor {
        guard cursor.installationID.rawValue == descriptor.installationID else {
          throw AuthorityDomainError(code: .replayRejected)
        }
        guard
          (cursor.acceptedEpoch, cursor.acceptedGeneration)
            <= (descriptor.epoch, descriptor.generation)
        else {
          throw AuthorityDomainError(code: .replayRejected)
        }
      }
      return .alreadyOff
    case .preparing:
      guard let lease = snapshot.leaseView,
        lease.state == .prepared,
        matches(lease.operation, descriptor: descriptor)
      else {
        throw AuthorityDomainError(code: .staleOperation)
      }
      return .cancel(lease)
    case .starting, .active, .stopping:
      guard let lease = snapshot.leaseView,
        matches(lease.operation, descriptor: descriptor)
      else {
        throw AuthorityDomainError(code: .staleOperation)
      }
      return .ownerControlled
    case .recovering:
      throw AuthorityDomainError(code: .globalAuthorityRecovering)
    case .quarantined:
      throw AuthorityDomainError(code: .quarantined)
    }
  }

  private static func observation(
    _ snapshot: AuthoritySnapshot
  ) -> AuthorityOwnershipObservation {
    let lease = snapshot.leaseView.map { view in
      AuthorityLeaseAgreement(
        installationID: view.operation.root.installationID.rawValue,
        epoch: view.operation.root.epoch,
        generation: view.operation.root.generation,
        ownerUID: view.operation.ownerUID,
        mode: view.operation.mode,
        configSHA256: view.operation.configSHA256,
        identitySHA256: view.operation.identitySHA256,
        leaseState: view.state
      )
    }
    return AuthorityOwnershipObservation(state: snapshot.state, lease: lease)
  }
}

import CFWSharedProtocol

protocol NativeEngineLeaseInspecting: Sendable {
  func installationRecoveryIdentity() async throws -> InstallationRecoveryState
  func isAvailable() async throws -> Bool
  /// Reports the Global Authority's machine-wide ownership observation used to
  /// require exact agreement before declaring an owner Active. A default
  /// implementation derives a coarse observation from `isAvailable()`.
  func authorityOwnership() async throws -> AuthorityOwnershipObservation
  /// Commits a restarted Authority to Off only after the Host has independently
  /// proven both native owners Off and supplied the exact public managed-tunnel
  /// status. Implementations without a production recovery channel fail closed.
  func reconcileOff(
    managedTunnel: RecoveryManagedTunnelStatus
  ) async throws -> AuthorityOwnershipObservation
  /// Recovers the exact persisted stopping lease after a Host restart. A nil
  /// result means the Authority is not currently in the recoverable Stopping
  /// state; it never means that global Off has been proven.
  func recoverStoppingLease() async throws -> NativeRecoveredStop?
  /// Cancels an exact unredeemed preparation. Returns true only when no
  /// preparation is left that the Authority could still authorize: a fresh
  /// snapshot proves global Off, or the Authority is Recovering, which holds no
  /// lease and admits no start until the Host proves Off. Returns false when the
  /// same lease has already advanced to an owner-controlled state and must use
  /// stop.
  func cancelPreparedStart(for descriptor: ConfigurationDescriptor) async throws -> Bool
  /// Durably orders the exact active Global Authority lease to stop before the
  /// Host asks either native owner to tear down its data plane. A Recovering
  /// Authority, which holds no lease, fails with `globalAuthorityRecovering`.
  func beginStop(for descriptor: ConfigurationDescriptor) async throws
    -> NativeAuthorityStopContext
  /// Commits global Off only after the owner has attested its teardown and the
  /// Host has observed the matching OS-facing endpoint at its Off barrier. A
  /// Recovering Authority fails with `globalAuthorityRecovering`.
  func completeStop(_ context: NativeAuthorityStopContext) async throws
  /// What one fresh snapshot says of a stop's generation; this does not
  /// replace the proof that the owner and the OS are Off.
  func stopResolution(_ context: EngineCommandContext) async throws -> NativeStopResolution
}

extension NativeEngineLeaseInspecting {
  func installationRecoveryIdentity() async throws -> InstallationRecoveryState {
    throw AuthorityDomainError(code: .globalAuthorityProtocolMismatch)
  }

  func reconcileOff(
    managedTunnel: RecoveryManagedTunnelStatus
  ) async throws -> AuthorityOwnershipObservation {
    throw AuthorityDomainError(code: .globalAuthorityRecovering)
  }

  func recoverStoppingLease() async throws -> NativeRecoveredStop? { nil }
  func stopResolution(_ context: EngineCommandContext) async throws -> NativeStopResolution {
    .unresolved
  }
  func cancelPreparedStart(for descriptor: ConfigurationDescriptor) async throws -> Bool {
    false
  }
}

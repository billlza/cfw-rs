import CFWSharedProtocol
import Foundation

/// The Global Authority's machine-wide ownership observation used to require exact
/// agreement before an owner is classified Active (Requirements 2.5, 3.1, 3.3).
///
/// It carries the durable Authority `state` and, when a lease is bound, the exact
/// `Operation_Context`, owner UID, mode, and configuration digest of the current
/// `Global_Lease`. The coordinator compares these against the owner-ready
/// attestation (the owner's effective active snapshot) and the effective
/// SystemConfiguration / Network Extension descriptor before declaring Active.
/// It never carries secrets, tickets, or credential bytes.
struct AuthorityOwnershipObservation: Sendable, Equatable {
  let state: AuthorityState
  let lease: AuthorityLeaseAgreement?
}

/// The non-secret projection of the current `Global_Lease` and its `Operation_Context`
/// used for exact activation agreement. Every field must match the effective OS-facing
/// owner descriptor for an owner to be classified Active.
struct AuthorityLeaseAgreement: Sendable, Equatable {
  let installationID: UUID
  let epoch: UInt64
  let generation: UInt64
  let ownerUID: UInt32
  let mode: AuthorityMode
  let configSHA256: SHA256Digest
  let identitySHA256: SHA256Digest
  let leaseState: AuthorityLeaseState
}

extension NativeEngineLeaseInspecting {
  /// Backwards-compatible default that derives a coarse ownership observation from
  /// the boolean availability seam. Availability means the Authority proves global
  /// Off; unavailability is treated as an active-but-unbound observation, which the
  /// agreement gate never promotes to Active. Concrete Authority-backed inspectors
  /// override this to report the exact lease/context/digest.
  func authorityOwnership() async throws -> AuthorityOwnershipObservation {
    let available = try await isAvailable()
    return AuthorityOwnershipObservation(
      state: available ? .off : .active,
      lease: nil
    )
  }
}

extension NativeBridgeCoordinator {
  /// Requires exact agreement between the Global Authority's machine-wide ownership
  /// observation and the effective OS-facing owner descriptor before an owner is
  /// classified Active. Active is returned only when `Global_Lease`,
  /// `Operation_Context`, owner-ready attestation (an active lease state), the
  /// configuration digest, and the effective OS descriptor all agree exactly. Any
  /// single disagreement fails closed as Failed, Recovering, or Quarantined — never
  /// Active, never Off from ambiguity (Requirements 2.5, 3.1, 3.3).
  static func requireActiveAgreement(
    descriptor: ConfigurationDescriptor,
    mode: EngineMode,
    ownership: AuthorityOwnershipObservation
  ) throws {
    switch ownership.state {
    case .active:
      break
    case .recovering:
      throw NativeBridgeExecutionError.failure(
        .globalAuthorityRecovering,
        "Global Authority is recovering; owner activation is not proven."
      )
    case .quarantined:
      throw NativeBridgeExecutionError.failure(
        .quarantined,
        "Global Authority is quarantined; owner activation is not proven."
      )
    case .off:
      // The effective OS state shows an active owner while the Authority proves
      // global Off. This is an unresolved ownership ambiguity, not activation.
      throw NativeBridgeExecutionError.failure(
        .quarantined,
        "An owner reported active while the Authority proves global Off."
      )
    case .preparing, .starting, .stopping:
      throw NativeBridgeExecutionError.failure(
        .busy,
        "Global Authority is in transitional state \(ownership.state.rawValue)."
      )
    }
    guard let lease = ownership.lease else {
      // Authority reports Active without a bound lease projection: ambiguous.
      throw NativeBridgeExecutionError.failure(
        .quarantined,
        "Global Authority reported Active without a bound lease."
      )
    }
    let expectedMode: AuthorityMode = mode == .systemProxy ? .systemProxy : .tunnel
    guard lease.leaseState == .active,
      lease.mode == expectedMode,
      lease.installationID == descriptor.installationID,
      lease.epoch == descriptor.epoch,
      lease.generation == descriptor.generation,
      lease.configSHA256 == descriptor.sha256,
      lease.identitySHA256 == descriptor.identitySHA256
    else {
      // Lease/context/digest/owner-ready disagreement: fail closed as Failed.
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "Global Authority lease does not exactly match the active owner context."
      )
    }
  }

  /// Requires the Global Authority to prove global Off when every owner endpoint is
  /// at the stable Off barrier. Recovering and Quarantined are reported exactly;
  /// any retained or in-flight lease keeps the machine busy rather than Off.
  static func requireGlobalOff(_ ownership: AuthorityOwnershipObservation) throws {
    switch ownership.state {
    case .off:
      return
    case .recovering:
      throw NativeBridgeExecutionError.failure(
        .globalAuthorityRecovering,
        "Global Authority is recovering; the Off barrier is not proven."
      )
    case .quarantined:
      throw NativeBridgeExecutionError.failure(
        .quarantined,
        "Global Authority is quarantined; the Off barrier is not proven."
      )
    case .preparing, .starting, .active, .stopping:
      throw NativeBridgeExecutionError.failure(
        .busy,
        "Another user or native engine process holds the machine-wide engine lease."
      )
    }
  }
}

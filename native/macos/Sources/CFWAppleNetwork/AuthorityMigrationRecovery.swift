import CFWSharedProtocol
import Foundation

// MARK: - Crash-recovery signal

/// The migration's view of the Authority journal recovery reducer's posture.
///
/// It mirrors `AuthorityJournalRecovery.posture` without importing the root
/// Authority module: `ambiguous` corresponds to a `.quarantined(...)` posture
/// (invalid, truncated, rolled-back, reordered, unknown-field, or
/// hash-chain-inconsistent journal), while the `pending*` cases correspond to a
/// `.recovering(action)` posture. In every posture the reducer's `permitsStart`
/// is false, and this migration recovery never authorizes a start either.
public enum MigrationCrashRecoverySignal: Equatable, Sendable {
  /// Journal state is ambiguous/tampered; durable state cannot be trusted.
  case ambiguous
  /// Recovering: the committed head is Off and only an Off verification remains.
  case pendingVerifyOff
  /// Recovering: a prepared/starting/stopping owner must be driven to a stop.
  case pendingStopOwner
  /// Recovering: an active owner would need to reattest. In a migration context
  /// no live owner channel exists, so reattestation is unavailable and the only
  /// safe path is an orderly fail-closed stop to Off.
  case pendingReattestOwner
}

// MARK: - Recovery conditions

/// Every upgrade/recovery condition that must terminate in cleanup plus proven
/// Off or in Quarantined — never in a running data plane, a retired path, a
/// direct-payload Tunnel, a previous mode, an alternate core, or a private API.
public enum AuthorityMigrationRecoveryCondition: Equatable, Sendable {
  /// The pure enrollment agreement disagreed (identity, ownership, or lineage).
  case migrationDisagreement(MigrationQuarantineReason)
  /// The Authority journal recovery reducer reported the given posture.
  case crashRecovery(MigrationCrashRecoverySignal)
  /// Authority daemon registration/approval was denied or the service is absent.
  case registrationDenied
  /// The Authority protocol version negotiated as incompatible.
  case protocolIncompatible
  /// The installed product was downgraded below the enrolled Authority lineage.
  case downgrade
  /// The product/app was replaced by a different signed tree.
  case replacement
  /// The Authority daemon was uninstalled from the machine.
  case authorityUninstall
}

// MARK: - Recovery outcome

/// The terminal outcome of a recovery run. Every path ends either in a proven
/// Off state after cleanup or in Quarantined — never in a running data plane.
public enum AuthorityMigrationRecoveryOutcome: Equatable, Sendable {
  case cleanedOff
  case quarantined(MigrationQuarantineReason)

  /// True when the run terminated in a proven Off state.
  public var isProvenOff: Bool {
    switch self {
    case .cleanedOff: true
    case .quarantined: false
    }
  }
}

/// The full record of a recovery run: its terminal outcome plus the ordered,
/// audited list of actions it emitted. The action vocabulary is deliberately the
/// same inspect/stop/prove-Off/reconcile/cleanup/quarantine set used by
/// enrollment — recovery can never emit a start or an `enrolledLineage` action.
public struct AuthorityMigrationRecoveryRun: Equatable, Sendable {
  public let outcome: AuthorityMigrationRecoveryOutcome
  public let actions: [AuthorityMigrationAction]

  public init(
    outcome: AuthorityMigrationRecoveryOutcome, actions: [AuthorityMigrationAction]
  ) {
    self.outcome = outcome
    self.actions = actions
  }
}

// MARK: - Pure policy

/// The pure mapping from a recovery condition to a recovery policy. Conditions
/// that reflect untrusted durable state or an unresolved disagreement forbid
/// mutation and fail closed after read-only inspection; conditions that merely
/// mean "no arbitrated engine may run here" clean product-owned state up and
/// prove Off.
public enum AuthorityMigrationRecoveryPlan {
  public enum Policy: Equatable, Sendable {
    /// Read-only inspection only, then quarantine with the given reason.
    case inspectThenQuarantine(MigrationQuarantineReason)
    /// Stop product-owned activity, prove Off, reconcile, and clean up; a proven
    /// Off ends the run, and any unproven step quarantines fail-closed.
    case cleanupToProvenOff
  }

  public static func policy(
    for condition: AuthorityMigrationRecoveryCondition
  ) -> Policy {
    switch condition {
    case .migrationDisagreement(let reason):
      // A disagreement over identity, ownership, or lineage is never resolved by
      // mutation; fail closed preserving the disagreement's reason.
      .inspectThenQuarantine(reason)
    case .crashRecovery(.ambiguous):
      // Untrusted durable state forbids any mutation.
      .inspectThenQuarantine(.crashRecoveryAmbiguous)
    case .crashRecovery(.pendingVerifyOff),
      .crashRecovery(.pendingStopOwner),
      .crashRecovery(.pendingReattestOwner):
      // A recovering (non-ambiguous) posture drives an orderly stop to Off.
      .cleanupToProvenOff
    case .registrationDenied, .protocolIncompatible,
      .downgrade, .replacement, .authorityUninstall:
      // The Authority boundary is unavailable, superseded, or refused: clean up
      // product-owned state and prove Off. No start is ever attempted.
      .cleanupToProvenOff
    }
  }
}

// MARK: - Lineage consumption guard

/// A binary's claim to consume the enrolled installation/high-water lineage. A
/// non-secret value: it carries only whether the binary understands the
/// Authority, its protocol major, and the bounded lineage tuple it claims.
public struct MigrationBinaryLineageClaim: Equatable, Sendable {
  public let isAuthorityAware: Bool
  public let protocolMajor: UInt16
  public let claimedLineage: MigrationLineage

  public init(
    isAuthorityAware: Bool, protocolMajor: UInt16, claimedLineage: MigrationLineage
  ) {
    self.isAuthorityAware = isAuthorityAware
    self.protocolMajor = protocolMajor
    self.claimedLineage = claimedLineage
  }
}

/// The decision on whether a binary may consume the enrolled lineage.
public enum AuthorityLineageConsumptionDecision: Equatable, Sendable {
  case permitted
  case rejected(MigrationQuarantineReason)
}

/// Blocks older, downgraded, or non-Authority binaries from consuming the new
/// immutable installation/high-water lineage. Consumption is permitted only for
/// an Authority-aware binary speaking the compatible protocol major, claiming
/// the same immutable installation, with a lineage that strictly exceeds the
/// enrolled high-water. Any other claim is rejected (and the caller quarantines)
/// so a consumed tuple can never be reused.
public enum AuthorityMigrationLineageGuard {
  public static func evaluate(
    enrolled: MigrationLineage,
    claim: MigrationBinaryLineageClaim
  ) -> AuthorityLineageConsumptionDecision {
    guard claim.isAuthorityAware else {
      return .rejected(.downgradeBlocked)
    }
    guard claim.protocolMajor == AuthorityV1Limits.major else {
      return .rejected(.protocolIncompatible)
    }
    guard claim.claimedLineage.installationID == enrolled.installationID else {
      return .rejected(.lineageConflict)
    }
    // The enrolled high-water is immutable and monotonic. A claim that does not
    // strictly exceed it would consume an already-consumed tuple — a downgrade or
    // replay — and is blocked.
    guard !claim.claimedLineage.precedesOrEquals(enrolled) else {
      return .rejected(.downgradeBlocked)
    }
    return .permitted
  }
}

// MARK: - Recovery orchestrator

/// The one-way, fail-closed recovery and downgrade/uninstall handler. It maps
/// each recovery condition to cleanup plus proven Off or to Quarantined, reusing
/// the same read-only inventory and stop/prove-Off/reconcile/cleanup seams as
/// enrollment. It has no seam that can start a data plane, revive a retired
/// helper or runtime, emit a direct-payload Tunnel, resume a previous mode, load
/// an alternate core, or reach a private Network Extension API.
public struct AuthorityMigrationRecovery: Sendable {
  private let inventoryReader: AuthorityMigrationInventoryReader
  private let stopper: any MigrationTemporaryActivityStopping
  private let offProver: any MigrationGlobalOffProving
  private let reconciler: any MigrationManagedManagerReconciling
  private let cleaner: any MigrationLegacyRemnantCleaning

  public init(
    inventoryReader: AuthorityMigrationInventoryReader,
    stopper: any MigrationTemporaryActivityStopping,
    offProver: any MigrationGlobalOffProving,
    reconciler: any MigrationManagedManagerReconciling,
    cleaner: any MigrationLegacyRemnantCleaning
  ) {
    self.inventoryReader = inventoryReader
    self.stopper = stopper
    self.offProver = offProver
    self.reconciler = reconciler
    self.cleaner = cleaner
  }

  /// Runs recovery for a condition and returns only the terminal outcome.
  public func recover(
    from condition: AuthorityMigrationRecoveryCondition
  ) async -> AuthorityMigrationRecoveryOutcome {
    await run(from: condition).outcome
  }

  /// Runs recovery for a condition and returns the terminal outcome plus the
  /// ordered, audited action list.
  public func run(
    from condition: AuthorityMigrationRecoveryCondition
  ) async -> AuthorityMigrationRecoveryRun {
    var actions: [AuthorityMigrationAction] = []

    // (1) Read-only inventory. A read failure fails closed.
    let inventory: AuthorityMigrationInventory
    do {
      inventory = try await inventoryReader.readInventory()
    } catch {
      return finish(.quarantined(.inventoryUnavailable), actions)
    }
    actions.append(.inspected)

    switch AuthorityMigrationRecoveryPlan.policy(for: condition) {
    case .inspectThenQuarantine(let reason):
      // Untrusted durable state or an unresolved disagreement: never mutate.
      return finish(.quarantined(reason), actions)

    case .cleanupToProvenOff:
      // (2) Stop any product-owned temporary-path activity before the barrier.
      if inventory.temporaryRuntime.requiresStop {
        do {
          try await stopper.stopProductOwnedTemporaryActivity()
        } catch {
          return finish(.quarantined(.globalOffNotProven), actions)
        }
        actions.append(.stoppedTemporaryActivity)
      }

      // (3) Prove the global Off barrier. Any missing predicate fails closed.
      let offObservation: MigrationGlobalOffObservation
      do {
        offObservation = try await offProver.proveGlobalOff()
      } catch {
        return finish(.quarantined(.globalOffNotProven), actions)
      }
      guard offObservation.isProvenGlobalOff else {
        return finish(.quarantined(.globalOffNotProven), actions)
      }
      actions.append(.provedGlobalOff)

      // (4) Reconcile the saved managed manager (descriptor-only; no start).
      do {
        try await reconciler.reconcileManagedManager()
      } catch {
        return finish(.quarantined(.reconcileFailed), actions)
      }
      actions.append(.reconciledManagedManager)

      // (5) Clean up tombstoned legacy remnants (cleanup only).
      if inventory.legacyRemnants.requiresCleanup {
        do {
          try await cleaner.cleanupLegacyRemnants()
        } catch {
          return finish(.quarantined(.cleanupFailed), actions)
        }
        actions.append(.cleanedLegacyRemnants)
      }

      return finish(.cleanedOff, actions)
    }
  }

  private func finish(
    _ outcome: AuthorityMigrationRecoveryOutcome, _ actions: [AuthorityMigrationAction]
  ) -> AuthorityMigrationRecoveryRun {
    var recorded = actions
    if case .quarantined(let reason) = outcome {
      recorded.append(.quarantined(reason))
    }
    return AuthorityMigrationRecoveryRun(outcome: outcome, actions: recorded)
  }
}

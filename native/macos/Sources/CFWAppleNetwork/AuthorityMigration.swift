import CFWSharedProtocol
import Foundation

// MARK: - Errors

public enum AuthorityMigrationError: Error, Equatable, Sendable {
  /// A lineage was constructed with a non-positive epoch or generation.
  case invalidLineage
}

// MARK: - Non-secret lineage

/// The bounded, non-secret installation lineage the migration reasons about.
///
/// A lineage carries only an immutable installation identifier and a
/// lexicographic `(epoch, generation)` high-water tuple. It never carries
/// configuration or credential bytes, so it is safe to enroll into the root
/// store and to keep in an in-memory inventory.
public struct MigrationLineage: Equatable, Sendable {
  public let installationID: UUID
  public let epoch: UInt64
  public let generation: UInt64

  public init(installationID: UUID, epoch: UInt64, generation: UInt64) throws {
    guard epoch > 0, generation > 0 else {
      throw AuthorityMigrationError.invalidLineage
    }
    self.installationID = installationID
    self.epoch = epoch
    self.generation = generation
  }

  /// Builds a lineage from an already-validated source (for example a
  /// `ConfigurationDescriptor`, whose epoch and generation are guaranteed
  /// positive by its own initializer). Kept internal so external callers use the
  /// validating initializer.
  init(uncheckedInstallationID installationID: UUID, epoch: UInt64, generation: UInt64) {
    self.installationID = installationID
    self.epoch = epoch
    self.generation = generation
  }

  /// True when this lineage's `(epoch, generation)` does not exceed `other`'s.
  /// Only meaningful when both lineages share an installation identifier.
  public func precedesOrEquals(_ other: MigrationLineage) -> Bool {
    (epoch, generation) <= (other.epoch, other.generation)
  }
}

// MARK: - Signed Host identity

/// The non-secret, signed Host identity the migration requires before it will
/// enroll a lineage. Resolution of the real Security.framework identity lives
/// behind `MigrationHostIdentityResolving`, so tests supply this value directly.
public struct MigrationHostIdentity: Equatable, Sendable {
  public static let expectedSigningID = "com.bill.clashformac"
  public static let expectedTeamID = "YKUPL7Z869"

  public let signingID: String
  public let teamID: String
  public let isLiveConsoleUser: Bool

  public init(signingID: String, teamID: String, isLiveConsoleUser: Bool) {
    self.signingID = signingID
    self.teamID = teamID
    self.isLiveConsoleUser = isLiveConsoleUser
  }

  /// The exact conjunction that lets the Host authorize a one-time enrollment:
  /// the expected signing identifier, the expected Team ID, and the live console
  /// user. Any mismatch fails closed.
  public var isTrustedConsoleHost: Bool {
    signingID == Self.expectedSigningID
      && teamID == Self.expectedTeamID
      && isLiveConsoleUser
  }
}

// MARK: - Inventory value types

/// Product-owned temporary-path runtime activity observed before migration.
public enum MigrationTemporaryRuntime: Equatable, Sendable {
  case off
  case systemProxyActive
  case tunnelActive
  case ambiguous

  /// Any non-`off` runtime must be stopped before the global Off barrier.
  public var requiresStop: Bool {
    self != .off
  }

  /// Ambiguous runtime means ownership cannot be attributed and fails closed.
  public var isAmbiguousOwnership: Bool {
    self == .ambiguous
  }
}

/// Presence-only inventory of tombstoned legacy remnants. Records only whether a
/// remnant exists; it never reads, starts, or authorizes a retired path.
public struct MigrationLegacyRemnants: Equatable, Sendable {
  public let tombstonedHelperPresent: Bool
  public let retiredCoreRemnantPresent: Bool

  public init(tombstonedHelperPresent: Bool, retiredCoreRemnantPresent: Bool) {
    self.tombstonedHelperPresent = tombstonedHelperPresent
    self.retiredCoreRemnantPresent = retiredCoreRemnantPresent
  }

  public static let none = MigrationLegacyRemnants(
    tombstonedHelperPresent: false, retiredCoreRemnantPresent: false)

  public var requiresCleanup: Bool {
    tombstonedHelperPresent || retiredCoreRemnantPresent
  }
}

/// The durable root replay-cursor state, from the migration's perspective.
public enum MigrationRootStoreState: Equatable, Sendable {
  case empty
  case enrolled(MigrationLineage)
}

/// A read-only, in-memory snapshot of everything the migration inspects. It
/// holds only non-secret metadata: bounded descriptors, lineage tuples, presence
/// flags, and an ownership-ambiguity flag. No configuration or credential bytes
/// are ever captured here, and nothing in this value is written to the root
/// store — enrollment persists only a `MigrationLineage`.
public struct AuthorityMigrationInventory: Equatable, Sendable {
  public let temporaryRuntime: MigrationTemporaryRuntime
  public let savedManagerDescriptor: ConfigurationDescriptor?
  public let hostLineage: MigrationLineage?
  /// Provider-local cursor is retained for diagnostics only. It can never lower
  /// or establish the root cursor.
  public let providerLocalCursor: MigrationLineage?
  public let legacyRemnants: MigrationLegacyRemnants
  public let ownerAmbiguity: Bool
  public let rootStore: MigrationRootStoreState

  public init(
    temporaryRuntime: MigrationTemporaryRuntime,
    savedManagerDescriptor: ConfigurationDescriptor?,
    hostLineage: MigrationLineage?,
    providerLocalCursor: MigrationLineage?,
    legacyRemnants: MigrationLegacyRemnants,
    ownerAmbiguity: Bool,
    rootStore: MigrationRootStoreState
  ) {
    self.temporaryRuntime = temporaryRuntime
    self.savedManagerDescriptor = savedManagerDescriptor
    self.hostLineage = hostLineage
    self.providerLocalCursor = providerLocalCursor
    self.legacyRemnants = legacyRemnants
    self.ownerAmbiguity = ownerAmbiguity
    self.rootStore = rootStore
  }

  /// The bounded, non-secret lineage implied by the saved managed manager
  /// descriptor, if one is present.
  public var descriptorLineage: MigrationLineage? {
    savedManagerDescriptor.map {
      MigrationLineage(
        uncheckedInstallationID: $0.installationID,
        epoch: $0.epoch, generation: $0.generation)
    }
  }
}

// MARK: - Global Off observation

/// The exact predicates the migration must observe to prove the global Off
/// barrier before enrollment. Every predicate must hold; any gap fails closed.
public struct MigrationGlobalOffObservation: Equatable, Sendable {
  public let leaseReleased: Bool
  public let ticketsAndSecretsCleared: Bool
  public let ownerEndpointCleared: Bool
  public let temporaryRuntimeStopped: Bool
  public let managedTunnelDisconnected: Bool
  public let systemProxyRestored: Bool

  public init(
    leaseReleased: Bool,
    ticketsAndSecretsCleared: Bool,
    ownerEndpointCleared: Bool,
    temporaryRuntimeStopped: Bool,
    managedTunnelDisconnected: Bool,
    systemProxyRestored: Bool
  ) {
    self.leaseReleased = leaseReleased
    self.ticketsAndSecretsCleared = ticketsAndSecretsCleared
    self.ownerEndpointCleared = ownerEndpointCleared
    self.temporaryRuntimeStopped = temporaryRuntimeStopped
    self.managedTunnelDisconnected = managedTunnelDisconnected
    self.systemProxyRestored = systemProxyRestored
  }

  public var isProvenGlobalOff: Bool {
    leaseReleased && ticketsAndSecretsCleared && ownerEndpointCleared
      && temporaryRuntimeStopped && managedTunnelDisconnected && systemProxyRestored
  }
}

// MARK: - Outcomes and audited actions

/// The reasons a migration fails closed to Quarantined instead of proven Off.
public enum MigrationQuarantineReason: Equatable, Sendable {
  case hostIdentityRejected
  case ownerAmbiguous
  case lineageConflict
  case inventoryUnavailable
  case globalOffNotProven
  case reconcileFailed
  case cleanupFailed
  case enrollmentFailed
  /// The Authority journal recovery reducer reported an ambiguous, tampered,
  /// truncated, rolled-back, reordered, or hash-chain-inconsistent journal, so
  /// durable state cannot be trusted and mutation is forbidden.
  case crashRecoveryAmbiguous
  /// Authority registration/approval was denied or the service is absent, so no
  /// arbitrated engine may run.
  case registrationDenied
  /// The Authority protocol version is incompatible with this binary.
  case protocolIncompatible
  /// An older, downgraded, or non-Authority binary attempted to consume the
  /// enrolled immutable installation/high-water lineage.
  case downgradeBlocked
}

/// The pure decision on whether and what to enroll, computed after Off and
/// reconciliation are proven.
public enum MigrationEnrollmentDecision: Equatable, Sendable {
  case enroll(MigrationLineage)
  case alreadyEnrolled(MigrationLineage)
  case noMigrationNeeded
  case quarantine(MigrationQuarantineReason)
}

/// The terminal outcome of a migration run. Every path ends either in a proven
/// Off variant or in Quarantined — never in a running data plane.
public enum AuthorityMigrationOutcome: Equatable, Sendable {
  case enrolledOff(lineage: MigrationLineage, revision: UInt64)
  case alreadyEnrolledOff(lineage: MigrationLineage)
  case noMigrationNeededOff
  case quarantined(MigrationQuarantineReason)

  /// True when the run terminated in a proven Off state.
  public var isProvenOff: Bool {
    switch self {
    case .enrolledOff, .alreadyEnrolledOff, .noMigrationNeededOff:
      true
    case .quarantined:
      false
    }
  }
}

/// Every side effect the migration is permitted to emit. There is deliberately
/// no start action: the migration can only inspect, stop, prove Off, reconcile,
/// clean up, enroll, or quarantine.
public enum AuthorityMigrationAction: Equatable, Sendable {
  case inspected
  case stoppedTemporaryActivity
  case provedGlobalOff
  case reconciledManagedManager
  case cleanedLegacyRemnants
  case enrolledLineage(MigrationLineage)
  case quarantined(MigrationQuarantineReason)
}

/// The full record of a migration run: its terminal outcome plus the ordered,
/// audited list of actions it emitted.
public struct AuthorityMigrationRun: Equatable, Sendable {
  public let outcome: AuthorityMigrationOutcome
  public let actions: [AuthorityMigrationAction]

  public init(outcome: AuthorityMigrationOutcome, actions: [AuthorityMigrationAction]) {
    self.outcome = outcome
    self.actions = actions
  }
}

// MARK: - Pure enrollment agreement

/// The pure, deterministic core that decides whether a lineage may be enrolled.
/// Enrollment is permitted only when the signed Host identity and the agreeing
/// non-secret inputs all agree; every disagreement fails closed to Quarantined.
public enum AuthorityMigrationAgreement {
  public static func decide(
    inventory: AuthorityMigrationInventory,
    hostIdentity: MigrationHostIdentity
  ) -> MigrationEnrollmentDecision {
    // A one-time enrollment requires the exact signed, live-console Host.
    guard hostIdentity.isTrustedConsoleHost else {
      return .quarantine(.hostIdentityRejected)
    }
    // Ambiguous ownership can never be resolved into a trusted lineage.
    if inventory.ownerAmbiguity {
      return .quarantine(.ownerAmbiguous)
    }

    let descriptorLineage = inventory.descriptorLineage

    switch inventory.rootStore {
    case .enrolled(let existing):
      // Enrollment already occurred and is immutable. Re-running is idempotent
      // for the same installation; a different installation is a conflict and
      // the provider-local cursor is never authoritative.
      if let hostLineage = inventory.hostLineage,
        hostLineage.installationID != existing.installationID
      {
        return .quarantine(.lineageConflict)
      }
      if let descriptorLineage,
        descriptorLineage.installationID != existing.installationID
      {
        return .quarantine(.lineageConflict)
      }
      return .alreadyEnrolled(existing)

    case .empty:
      // The empty root store is established only from the host Keychain lineage,
      // which the managed non-secret descriptor must agree with when present.
      // The provider-local cursor is diagnostic only and never establishes the
      // root cursor.
      guard let hostLineage = inventory.hostLineage else {
        // Without a trusted host lineage there is nothing to establish. A saved
        // descriptor alone cannot authorize a root cursor, so it fails closed;
        // an otherwise-empty inventory simply needs no migration.
        if descriptorLineage != nil {
          return .quarantine(.lineageConflict)
        }
        return .noMigrationNeeded
      }
      if let descriptorLineage {
        guard descriptorLineage.installationID == hostLineage.installationID else {
          return .quarantine(.lineageConflict)
        }
        // The saved descriptor must not claim a lineage newer than the host
        // high-water lineage being enrolled.
        guard descriptorLineage.precedesOrEquals(hostLineage) else {
          return .quarantine(.lineageConflict)
        }
      }
      return .enroll(hostLineage)
    }
  }
}

// MARK: - Read-only inventory seams

/// Read-only inspection of product-owned temporary-path runtime activity.
public protocol MigrationTemporaryRuntimeInspecting: Sendable {
  func inspectTemporaryRuntime() async throws -> MigrationTemporaryRuntime
}

/// Read-only inspection of the saved managed manager's bounded, non-secret
/// descriptor. Returns `nil` when no product-owned manager is present.
public protocol MigrationManagerDescriptorInspecting: Sendable {
  func inspectSavedManagerDescriptor() async throws -> ConfigurationDescriptor?
}

/// Read-only inspection of the host Keychain installation lineage.
public protocol MigrationHostLineageInspecting: Sendable {
  func inspectHostLineage() async throws -> MigrationLineage?
}

/// Read-only inspection of the provider-local cursor (diagnostics only).
public protocol MigrationProviderCursorInspecting: Sendable {
  func inspectProviderLocalCursor() async throws -> MigrationLineage?
}

/// Read-only inspection of tombstoned legacy remnants (presence only).
public protocol MigrationLegacyRemnantInspecting: Sendable {
  func inspectLegacyRemnants() async throws -> MigrationLegacyRemnants
}

/// Read-only inspection of the durable root replay-cursor state.
public protocol MigrationRootStoreInspecting: Sendable {
  func inspectRootStore() async throws -> MigrationRootStoreState
}

/// Composes the six read-only inspection seams into one non-secret inventory.
/// It performs no mutation and imports no configuration or secret bytes.
public struct AuthorityMigrationInventoryReader: Sendable {
  private let runtime: any MigrationTemporaryRuntimeInspecting
  private let manager: any MigrationManagerDescriptorInspecting
  private let hostLineage: any MigrationHostLineageInspecting
  private let providerCursor: any MigrationProviderCursorInspecting
  private let legacy: any MigrationLegacyRemnantInspecting
  private let rootStore: any MigrationRootStoreInspecting

  public init(
    runtime: any MigrationTemporaryRuntimeInspecting,
    manager: any MigrationManagerDescriptorInspecting,
    hostLineage: any MigrationHostLineageInspecting,
    providerCursor: any MigrationProviderCursorInspecting,
    legacy: any MigrationLegacyRemnantInspecting,
    rootStore: any MigrationRootStoreInspecting
  ) {
    self.runtime = runtime
    self.manager = manager
    self.hostLineage = hostLineage
    self.providerCursor = providerCursor
    self.legacy = legacy
    self.rootStore = rootStore
  }

  public func readInventory() async throws -> AuthorityMigrationInventory {
    let temporaryRuntime = try await runtime.inspectTemporaryRuntime()
    let descriptor = try await manager.inspectSavedManagerDescriptor()
    let host = try await hostLineage.inspectHostLineage()
    let cursor = try await providerCursor.inspectProviderLocalCursor()
    let remnants = try await legacy.inspectLegacyRemnants()
    let root = try await rootStore.inspectRootStore()
    return AuthorityMigrationInventory(
      temporaryRuntime: temporaryRuntime,
      savedManagerDescriptor: descriptor,
      hostLineage: host,
      providerLocalCursor: cursor,
      legacyRemnants: remnants,
      ownerAmbiguity: temporaryRuntime.isAmbiguousOwnership,
      rootStore: root)
  }
}

// MARK: - Action seams

/// Resolves the signed, live-console Host identity. The real Security.framework
/// and SystemConfiguration lookups live here so tests can inject a value.
public protocol MigrationHostIdentityResolving: Sendable {
  func resolveHostIdentity() async throws -> MigrationHostIdentity
}

/// Stops product-owned temporary-path activity. Stop only — never starts.
public protocol MigrationTemporaryActivityStopping: Sendable {
  func stopProductOwnedTemporaryActivity() async throws
}

/// Observes the global Off barrier predicates. Observation only — never starts.
public protocol MigrationGlobalOffProving: Sendable {
  func proveGlobalOff() async throws -> MigrationGlobalOffObservation
}

/// Reconciles the saved managed manager (disable/remove/verify). Never starts a
/// data plane and never writes configuration or credential bytes.
public protocol MigrationManagedManagerReconciling: Sendable {
  func reconcileManagedManager() async throws
}

/// Cleans up tombstoned legacy remnants. Cleanup only — never starts or
/// authorizes a retired path.
public protocol MigrationLegacyRemnantCleaning: Sendable {
  func cleanupLegacyRemnants() async throws
}

/// Enrolls exactly one immutable lineage into the empty root store. It persists
/// only the non-secret lineage, is immutable and idempotent for the same
/// installation, and returns the durable revision it committed.
public protocol MigrationLineageEnrolling: Sendable {
  func enroll(_ lineage: MigrationLineage) async throws -> UInt64
}

// MARK: - Migration orchestrator

/// The one-time, one-way Authority enrollment migration. It inspects a
/// read-only inventory, stops product-owned temporary activity, proves the
/// global Off barrier, reconciles the managed manager, cleans up tombstoned
/// remnants, and enrolls exactly one immutable installation lineage into the
/// empty root store — but only when the signed Host identity and the agreeing
/// non-secret inputs allow it. Every failure or disagreement fails closed and
/// terminates in proven Off or Quarantined. There is no seam that can start a
/// data plane, import configuration, or import secret bytes.
public struct AuthorityEnrollmentMigration: Sendable {
  private let inventoryReader: AuthorityMigrationInventoryReader
  private let identityResolver: any MigrationHostIdentityResolving
  private let stopper: any MigrationTemporaryActivityStopping
  private let offProver: any MigrationGlobalOffProving
  private let reconciler: any MigrationManagedManagerReconciling
  private let cleaner: any MigrationLegacyRemnantCleaning
  private let enroller: any MigrationLineageEnrolling

  public init(
    inventoryReader: AuthorityMigrationInventoryReader,
    identityResolver: any MigrationHostIdentityResolving,
    stopper: any MigrationTemporaryActivityStopping,
    offProver: any MigrationGlobalOffProving,
    reconciler: any MigrationManagedManagerReconciling,
    cleaner: any MigrationLegacyRemnantCleaning,
    enroller: any MigrationLineageEnrolling
  ) {
    self.inventoryReader = inventoryReader
    self.identityResolver = identityResolver
    self.stopper = stopper
    self.offProver = offProver
    self.reconciler = reconciler
    self.cleaner = cleaner
    self.enroller = enroller
  }

  /// Runs the migration and returns only the terminal outcome.
  public func migrate() async -> AuthorityMigrationOutcome {
    await run().outcome
  }

  /// Runs the migration and returns the terminal outcome plus the ordered,
  /// audited action list. Useful for proving the migration never emits a start.
  public func run() async -> AuthorityMigrationRun {
    var actions: [AuthorityMigrationAction] = []

    // (1) Read-only inventory. A read failure fails closed.
    let inventory: AuthorityMigrationInventory
    do {
      inventory = try await inventoryReader.readInventory()
    } catch {
      return finish(.quarantined(.inventoryUnavailable), actions)
    }
    actions.append(.inspected)

    // (2) Stop any product-owned temporary-path activity before the Off barrier.
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

    // (6) Resolve the signed Host identity used to authorize enrollment.
    let hostIdentity: MigrationHostIdentity
    do {
      hostIdentity = try await identityResolver.resolveHostIdentity()
    } catch {
      return finish(.quarantined(.hostIdentityRejected), actions)
    }

    // (7) Decide and, when agreement holds, enroll exactly one immutable lineage.
    switch AuthorityMigrationAgreement.decide(
      inventory: inventory, hostIdentity: hostIdentity)
    {
    case .quarantine(let reason):
      return finish(.quarantined(reason), actions)
    case .noMigrationNeeded:
      return finish(.noMigrationNeededOff, actions)
    case .alreadyEnrolled(let lineage):
      return finish(.alreadyEnrolledOff(lineage: lineage), actions)
    case .enroll(let lineage):
      let revision: UInt64
      do {
        revision = try await enroller.enroll(lineage)
      } catch {
        return finish(.quarantined(.enrollmentFailed), actions)
      }
      actions.append(.enrolledLineage(lineage))
      return finish(.enrolledOff(lineage: lineage, revision: revision), actions)
    }
  }

  private func finish(
    _ outcome: AuthorityMigrationOutcome, _ actions: [AuthorityMigrationAction]
  ) -> AuthorityMigrationRun {
    var recorded = actions
    if case .quarantined(let reason) = outcome {
      recorded.append(.quarantined(reason))
    }
    return AuthorityMigrationRun(outcome: outcome, actions: recorded)
  }
}

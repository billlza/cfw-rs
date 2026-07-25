import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAppleNetwork

// MARK: - Builders

private func lineage(
  _ installationID: UUID = UUID(), epoch: UInt64 = 1, generation: UInt64 = 1
) throws -> MigrationLineage {
  try MigrationLineage(installationID: installationID, epoch: epoch, generation: generation)
}

private func provenOff() -> MigrationGlobalOffObservation {
  MigrationGlobalOffObservation(
    leaseReleased: true, ticketsAndSecretsCleared: true, ownerEndpointCleared: true,
    temporaryRuntimeStopped: true, managedTunnelDisconnected: true, systemProxyRestored: true)
}

private func notProvenOff() -> MigrationGlobalOffObservation {
  MigrationGlobalOffObservation(
    leaseReleased: true, ticketsAndSecretsCleared: true, ownerEndpointCleared: true,
    temporaryRuntimeStopped: true, managedTunnelDisconnected: false, systemProxyRestored: true)
}

// MARK: - Fakes

private final class FakeRuntimeInspector: MigrationTemporaryRuntimeInspecting, @unchecked Sendable {
  let value: MigrationTemporaryRuntime
  let shouldThrow: Bool
  init(_ value: MigrationTemporaryRuntime, shouldThrow: Bool = false) {
    self.value = value
    self.shouldThrow = shouldThrow
  }
  func inspectTemporaryRuntime() async throws -> MigrationTemporaryRuntime {
    if shouldThrow { throw CancellationError() }
    return value
  }
}

private final class FakeDescriptorInspector: MigrationManagerDescriptorInspecting,
  @unchecked Sendable
{
  func inspectSavedManagerDescriptor() async throws -> ConfigurationDescriptor? { nil }
}

private final class FakeHostLineageInspector: MigrationHostLineageInspecting, @unchecked Sendable {
  let value: MigrationLineage?
  init(_ value: MigrationLineage?) { self.value = value }
  func inspectHostLineage() async throws -> MigrationLineage? { value }
}

private final class FakeProviderCursorInspector: MigrationProviderCursorInspecting,
  @unchecked Sendable
{
  func inspectProviderLocalCursor() async throws -> MigrationLineage? { nil }
}

private final class FakeLegacyInspector: MigrationLegacyRemnantInspecting, @unchecked Sendable {
  let value: MigrationLegacyRemnants
  init(_ value: MigrationLegacyRemnants) { self.value = value }
  func inspectLegacyRemnants() async throws -> MigrationLegacyRemnants { value }
}

private final class FakeRootStoreInspector: MigrationRootStoreInspecting, @unchecked Sendable {
  let value: MigrationRootStoreState
  init(_ value: MigrationRootStoreState) { self.value = value }
  func inspectRootStore() async throws -> MigrationRootStoreState { value }
}

private final class RecordingStopper: MigrationTemporaryActivityStopping, @unchecked Sendable {
  private let lock = NSLock()
  private var countValue = 0
  let shouldThrow: Bool
  init(shouldThrow: Bool = false) { self.shouldThrow = shouldThrow }
  var count: Int { lock.withLock { countValue } }
  func stopProductOwnedTemporaryActivity() async throws {
    lock.withLock { countValue += 1 }
    if shouldThrow { throw CancellationError() }
  }
}

private struct StubOffProver: MigrationGlobalOffProving {
  let observation: MigrationGlobalOffObservation
  let failure: Bool
  init(_ observation: MigrationGlobalOffObservation, failure: Bool = false) {
    self.observation = observation
    self.failure = failure
  }
  func proveGlobalOff() async throws -> MigrationGlobalOffObservation {
    if failure { throw CancellationError() }
    return observation
  }
}

private final class RecordingReconciler: MigrationManagedManagerReconciling, @unchecked Sendable {
  private let lock = NSLock()
  private var countValue = 0
  let shouldThrow: Bool
  init(shouldThrow: Bool = false) { self.shouldThrow = shouldThrow }
  var count: Int { lock.withLock { countValue } }
  func reconcileManagedManager() async throws {
    lock.withLock { countValue += 1 }
    if shouldThrow { throw CancellationError() }
  }
}

private final class RecordingCleaner: MigrationLegacyRemnantCleaning, @unchecked Sendable {
  private let lock = NSLock()
  private var countValue = 0
  let shouldThrow: Bool
  init(shouldThrow: Bool = false) { self.shouldThrow = shouldThrow }
  var count: Int { lock.withLock { countValue } }
  func cleanupLegacyRemnants() async throws {
    lock.withLock { countValue += 1 }
    if shouldThrow { throw CancellationError() }
  }
}

private func reader(
  runtime: MigrationTemporaryRuntime = .off,
  runtimeThrows: Bool = false,
  legacy: MigrationLegacyRemnants = .none,
  rootStore: MigrationRootStoreState = .empty
) -> AuthorityMigrationInventoryReader {
  AuthorityMigrationInventoryReader(
    runtime: FakeRuntimeInspector(runtime, shouldThrow: runtimeThrows),
    manager: FakeDescriptorInspector(),
    hostLineage: FakeHostLineageInspector(nil),
    providerCursor: FakeProviderCursorInspector(),
    legacy: FakeLegacyInspector(legacy),
    rootStore: FakeRootStoreInspector(rootStore))
}

private func recovery(
  inventory readerValue: AuthorityMigrationInventoryReader,
  stopper: RecordingStopper = RecordingStopper(),
  offProver: StubOffProver = StubOffProver(provenOff()),
  reconciler: RecordingReconciler = RecordingReconciler(),
  cleaner: RecordingCleaner = RecordingCleaner()
) -> AuthorityMigrationRecovery {
  AuthorityMigrationRecovery(
    inventoryReader: readerValue,
    stopper: stopper,
    offProver: offProver,
    reconciler: reconciler,
    cleaner: cleaner)
}

// MARK: - Policy classification tests

@Suite(.serialized)
struct AuthorityMigrationRecoveryPolicyTests {
  @Test func migrationDisagreementInspectsThenQuarantinesPreservingReason() {
    #expect(
      AuthorityMigrationRecoveryPlan.policy(for: .migrationDisagreement(.lineageConflict))
        == .inspectThenQuarantine(.lineageConflict))
    #expect(
      AuthorityMigrationRecoveryPlan.policy(for: .migrationDisagreement(.ownerAmbiguous))
        == .inspectThenQuarantine(.ownerAmbiguous))
  }

  @Test func ambiguousCrashRecoveryForbidsMutation() {
    #expect(
      AuthorityMigrationRecoveryPlan.policy(for: .crashRecovery(.ambiguous))
        == .inspectThenQuarantine(.crashRecoveryAmbiguous))
  }

  @Test func recoveringCrashPosturesCleanupToOff() {
    for signal in [
      MigrationCrashRecoverySignal.pendingVerifyOff,
      .pendingStopOwner, .pendingReattestOwner,
    ] {
      #expect(
        AuthorityMigrationRecoveryPlan.policy(for: .crashRecovery(signal)) == .cleanupToProvenOff)
    }
  }

  @Test func boundaryUnavailableConditionsCleanupToOff() {
    for condition: AuthorityMigrationRecoveryCondition in [
      .registrationDenied, .protocolIncompatible, .downgrade, .replacement, .authorityUninstall,
    ] {
      #expect(AuthorityMigrationRecoveryPlan.policy(for: condition) == .cleanupToProvenOff)
    }
  }
}

// MARK: - Orchestrator tests

@Suite(.serialized)
struct AuthorityMigrationRecoveryTests {
  @Test func uninstallStopsProvesReconcilesCleansAndEndsOff() async throws {
    let stopper = RecordingStopper()
    let reconciler = RecordingReconciler()
    let cleaner = RecordingCleaner()
    let run = await recovery(
      inventory: reader(
        runtime: .tunnelActive,
        legacy: MigrationLegacyRemnants(
          tombstonedHelperPresent: true, retiredCoreRemnantPresent: false)),
      stopper: stopper, reconciler: reconciler, cleaner: cleaner
    ).run(from: .authorityUninstall)

    #expect(run.outcome == .cleanedOff)
    #expect(run.outcome.isProvenOff)
    #expect(stopper.count == 1)
    #expect(reconciler.count == 1)
    #expect(cleaner.count == 1)
    #expect(
      run.actions == [
        .inspected, .stoppedTemporaryActivity, .provedGlobalOff,
        .reconciledManagedManager, .cleanedLegacyRemnants,
      ])
  }

  @Test func downgradeWithNothingRunningCleansToOffWithoutStopping() async throws {
    let stopper = RecordingStopper()
    let run = await recovery(
      inventory: reader(runtime: .off), stopper: stopper
    ).run(from: .downgrade)
    #expect(run.outcome == .cleanedOff)
    #expect(stopper.count == 0)
    #expect(!run.actions.contains(.stoppedTemporaryActivity))
    #expect(run.actions == [.inspected, .provedGlobalOff, .reconciledManagedManager])
  }

  @Test func registrationDeniedFailsClosedToOff() async throws {
    let run = await recovery(inventory: reader()).run(from: .registrationDenied)
    #expect(run.outcome == .cleanedOff)
  }

  @Test func protocolIncompatibleFailsClosedToOff() async throws {
    let run = await recovery(inventory: reader()).run(from: .protocolIncompatible)
    #expect(run.outcome == .cleanedOff)
  }

  @Test func replacementFailsClosedToOff() async throws {
    let run = await recovery(inventory: reader()).run(from: .replacement)
    #expect(run.outcome == .cleanedOff)
  }

  @Test func ambiguousCrashRecoveryInspectsOnlyAndQuarantines() async throws {
    // Even with a running temporary runtime, ambiguity forbids any mutation.
    let stopper = RecordingStopper()
    let reconciler = RecordingReconciler()
    let run = await recovery(
      inventory: reader(runtime: .tunnelActive), stopper: stopper, reconciler: reconciler
    ).run(from: .crashRecovery(.ambiguous))

    #expect(run.outcome == .quarantined(.crashRecoveryAmbiguous))
    #expect(!run.outcome.isProvenOff)
    #expect(stopper.count == 0)
    #expect(reconciler.count == 0)
    #expect(run.actions == [.inspected, .quarantined(.crashRecoveryAmbiguous)])
  }

  @Test func migrationDisagreementInspectsOnlyAndQuarantines() async throws {
    let run = await recovery(inventory: reader(runtime: .systemProxyActive))
      .run(from: .migrationDisagreement(.lineageConflict))
    #expect(run.outcome == .quarantined(.lineageConflict))
    #expect(run.actions == [.inspected, .quarantined(.lineageConflict)])
  }

  @Test func recoveringPostureDrivesStopToOff() async throws {
    let stopper = RecordingStopper()
    let run = await recovery(
      inventory: reader(runtime: .tunnelActive), stopper: stopper
    ).run(from: .crashRecovery(.pendingStopOwner))
    #expect(run.outcome == .cleanedOff)
    #expect(stopper.count == 1)
  }

  @Test func unprovableOffQuarantines() async throws {
    let run = await recovery(
      inventory: reader(runtime: .tunnelActive),
      offProver: StubOffProver(notProvenOff())
    ).run(from: .authorityUninstall)
    #expect(run.outcome == .quarantined(.globalOffNotProven))
    #expect(!run.actions.contains(.provedGlobalOff))
  }

  @Test func offProofErrorQuarantines() async throws {
    let run = await recovery(
      inventory: reader(),
      offProver: StubOffProver(provenOff(), failure: true)
    ).run(from: .downgrade)
    #expect(run.outcome == .quarantined(.globalOffNotProven))
  }

  @Test func stopFailureQuarantines() async throws {
    let run = await recovery(
      inventory: reader(runtime: .tunnelActive),
      stopper: RecordingStopper(shouldThrow: true)
    ).run(from: .replacement)
    #expect(run.outcome == .quarantined(.globalOffNotProven))
  }

  @Test func reconcileFailureQuarantines() async throws {
    let run = await recovery(
      inventory: reader(),
      reconciler: RecordingReconciler(shouldThrow: true)
    ).run(from: .downgrade)
    #expect(run.outcome == .quarantined(.reconcileFailed))
  }

  @Test func cleanupFailureQuarantines() async throws {
    let run = await recovery(
      inventory: reader(
        legacy: MigrationLegacyRemnants(
          tombstonedHelperPresent: true, retiredCoreRemnantPresent: false)),
      cleaner: RecordingCleaner(shouldThrow: true)
    ).run(from: .authorityUninstall)
    #expect(run.outcome == .quarantined(.cleanupFailed))
  }

  @Test func inventoryUnavailableQuarantines() async throws {
    let run = await recovery(inventory: reader(runtimeThrows: true)).run(from: .downgrade)
    #expect(run.outcome == .quarantined(.inventoryUnavailable))
    #expect(run.actions == [.quarantined(.inventoryUnavailable)])
  }

  @Test func recoveryNeverEmitsAStartOrEnrollActionOnAnyPath() async throws {
    let conditions: [AuthorityMigrationRecoveryCondition] = [
      .migrationDisagreement(.ownerAmbiguous),
      .crashRecovery(.ambiguous),
      .crashRecovery(.pendingVerifyOff),
      .crashRecovery(.pendingStopOwner),
      .crashRecovery(.pendingReattestOwner),
      .registrationDenied, .protocolIncompatible, .downgrade, .replacement, .authorityUninstall,
    ]
    for condition in conditions {
      let run = await recovery(
        inventory: reader(
          runtime: .tunnelActive,
          legacy: MigrationLegacyRemnants(
            tombstonedHelperPresent: true, retiredCoreRemnantPresent: true))
      ).run(from: condition)

      // The recovery action vocabulary excludes enrollment and any start.
      for action in run.actions {
        #expect(action != .enrolledLineage(try lineage()))
        switch action {
        case .inspected, .stoppedTemporaryActivity, .provedGlobalOff,
          .reconciledManagedManager, .cleanedLegacyRemnants, .quarantined:
          break
        case .enrolledLineage:
          Issue.record("recovery must never enroll a lineage")
        }
      }
      // Every terminal outcome is proven Off or Quarantined — never Active.
      switch run.outcome {
      case .cleanedOff, .quarantined:
        break
      }
    }
  }
}

// MARK: - Lineage consumption guard tests

@Suite(.serialized)
struct AuthorityMigrationLineageGuardTests {
  @Test func authorityAwareStrictlyNewerSameInstallationIsPermitted() throws {
    let installationID = UUID()
    let enrolled = try lineage(installationID, epoch: 2, generation: 3)
    let claim = MigrationBinaryLineageClaim(
      isAuthorityAware: true, protocolMajor: AuthorityV1Limits.major,
      claimedLineage: try lineage(installationID, epoch: 2, generation: 4))
    #expect(AuthorityMigrationLineageGuard.evaluate(enrolled: enrolled, claim: claim) == .permitted)
  }

  @Test func nonAuthorityBinaryIsBlocked() throws {
    let installationID = UUID()
    let enrolled = try lineage(installationID, epoch: 1, generation: 1)
    let claim = MigrationBinaryLineageClaim(
      isAuthorityAware: false, protocolMajor: AuthorityV1Limits.major,
      claimedLineage: try lineage(installationID, epoch: 9, generation: 9))
    #expect(
      AuthorityMigrationLineageGuard.evaluate(enrolled: enrolled, claim: claim)
        == .rejected(.downgradeBlocked))
  }

  @Test func incompatibleProtocolMajorIsRejected() throws {
    let installationID = UUID()
    let enrolled = try lineage(installationID, epoch: 1, generation: 1)
    let claim = MigrationBinaryLineageClaim(
      isAuthorityAware: true, protocolMajor: AuthorityV1Limits.major &+ 1,
      claimedLineage: try lineage(installationID, epoch: 2, generation: 2))
    #expect(
      AuthorityMigrationLineageGuard.evaluate(enrolled: enrolled, claim: claim)
        == .rejected(.protocolIncompatible))
  }

  @Test func differentInstallationIsLineageConflict() throws {
    let enrolled = try lineage(UUID(), epoch: 1, generation: 1)
    let claim = MigrationBinaryLineageClaim(
      isAuthorityAware: true, protocolMajor: AuthorityV1Limits.major,
      claimedLineage: try lineage(UUID(), epoch: 2, generation: 2))
    #expect(
      AuthorityMigrationLineageGuard.evaluate(enrolled: enrolled, claim: claim)
        == .rejected(.lineageConflict))
  }

  @Test func downgradeOrEqualLineageIsBlocked() throws {
    let installationID = UUID()
    let enrolled = try lineage(installationID, epoch: 3, generation: 3)
    // Strictly older.
    let older = MigrationBinaryLineageClaim(
      isAuthorityAware: true, protocolMajor: AuthorityV1Limits.major,
      claimedLineage: try lineage(installationID, epoch: 2, generation: 9))
    // Exactly equal (a consumed tuple).
    let equal = MigrationBinaryLineageClaim(
      isAuthorityAware: true, protocolMajor: AuthorityV1Limits.major,
      claimedLineage: try lineage(installationID, epoch: 3, generation: 3))
    #expect(
      AuthorityMigrationLineageGuard.evaluate(enrolled: enrolled, claim: older)
        == .rejected(.downgradeBlocked))
    #expect(
      AuthorityMigrationLineageGuard.evaluate(enrolled: enrolled, claim: equal)
        == .rejected(.downgradeBlocked))
  }
}

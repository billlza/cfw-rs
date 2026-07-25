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

private func trustedHost(consoleUser: Bool = true) -> MigrationHostIdentity {
  MigrationHostIdentity(
    signingID: MigrationHostIdentity.expectedSigningID,
    teamID: MigrationHostIdentity.expectedTeamID,
    isLiveConsoleUser: consoleUser)
}

private func tunnelDescriptor(
  installationID: UUID, epoch: UInt64 = 1, generation: UInt64 = 1
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
    installationID: installationID,
    epoch: epoch,
    generation: generation,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "ab", count: 32)),
    identitySHA256: SHA256Digest(hex: String(repeating: "cd", count: 32)))
}

private func provenOff() -> MigrationGlobalOffObservation {
  MigrationGlobalOffObservation(
    leaseReleased: true, ticketsAndSecretsCleared: true, ownerEndpointCleared: true,
    temporaryRuntimeStopped: true, managedTunnelDisconnected: true, systemProxyRestored: true)
}

private func inventory(
  temporaryRuntime: MigrationTemporaryRuntime = .off,
  descriptor: ConfigurationDescriptor? = nil,
  hostLineage: MigrationLineage? = nil,
  providerLocalCursor: MigrationLineage? = nil,
  legacyRemnants: MigrationLegacyRemnants = .none,
  ownerAmbiguity: Bool = false,
  rootStore: MigrationRootStoreState = .empty
) -> AuthorityMigrationInventory {
  AuthorityMigrationInventory(
    temporaryRuntime: temporaryRuntime,
    savedManagerDescriptor: descriptor,
    hostLineage: hostLineage,
    providerLocalCursor: providerLocalCursor,
    legacyRemnants: legacyRemnants,
    ownerAmbiguity: ownerAmbiguity,
    rootStore: rootStore)
}

// MARK: - Fakes

private final class FakeRuntimeInspector: MigrationTemporaryRuntimeInspecting, @unchecked Sendable {
  let value: MigrationTemporaryRuntime
  init(_ value: MigrationTemporaryRuntime) { self.value = value }
  func inspectTemporaryRuntime() async throws -> MigrationTemporaryRuntime { value }
}

private final class FakeDescriptorInspector: MigrationManagerDescriptorInspecting,
  @unchecked Sendable
{
  let value: ConfigurationDescriptor?
  init(_ value: ConfigurationDescriptor?) { self.value = value }
  func inspectSavedManagerDescriptor() async throws -> ConfigurationDescriptor? { value }
}

private final class FakeHostLineageInspector: MigrationHostLineageInspecting, @unchecked Sendable {
  let value: MigrationLineage?
  init(_ value: MigrationLineage?) { self.value = value }
  func inspectHostLineage() async throws -> MigrationLineage? { value }
}

private final class FakeProviderCursorInspector: MigrationProviderCursorInspecting,
  @unchecked Sendable
{
  let value: MigrationLineage?
  init(_ value: MigrationLineage?) { self.value = value }
  func inspectProviderLocalCursor() async throws -> MigrationLineage? { value }
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

private struct StubIdentityResolver: MigrationHostIdentityResolving {
  let identity: MigrationHostIdentity
  let failure: Bool
  init(_ identity: MigrationHostIdentity, failure: Bool = false) {
    self.identity = identity
    self.failure = failure
  }
  func resolveHostIdentity() async throws -> MigrationHostIdentity {
    if failure { throw CancellationError() }
    return identity
  }
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

private final class RecordingEnroller: MigrationLineageEnrolling, @unchecked Sendable {
  private let lock = NSLock()
  private var enrolledValue: MigrationLineage?
  private var countValue = 0
  let revision: UInt64
  let shouldThrow: Bool
  init(revision: UInt64 = 2, shouldThrow: Bool = false) {
    self.revision = revision
    self.shouldThrow = shouldThrow
  }
  var enrolled: MigrationLineage? { lock.withLock { enrolledValue } }
  var count: Int { lock.withLock { countValue } }
  func enroll(_ lineage: MigrationLineage) async throws -> UInt64 {
    lock.withLock {
      countValue += 1
      enrolledValue = lineage
    }
    if shouldThrow { throw CancellationError() }
    return revision
  }
}

private func migration(
  inventory reader: AuthorityMigrationInventoryReader,
  identity: MigrationHostIdentity = trustedHost(),
  identityFailure: Bool = false,
  stopper: RecordingStopper = RecordingStopper(),
  offProver: StubOffProver = StubOffProver(provenOff()),
  reconciler: RecordingReconciler = RecordingReconciler(),
  cleaner: RecordingCleaner = RecordingCleaner(),
  enroller: RecordingEnroller = RecordingEnroller()
) -> AuthorityEnrollmentMigration {
  AuthorityEnrollmentMigration(
    inventoryReader: reader,
    identityResolver: StubIdentityResolver(identity, failure: identityFailure),
    stopper: stopper,
    offProver: offProver,
    reconciler: reconciler,
    cleaner: cleaner,
    enroller: enroller)
}

private func reader(
  runtime: MigrationTemporaryRuntime = .off,
  descriptor: ConfigurationDescriptor? = nil,
  hostLineage: MigrationLineage? = nil,
  providerCursor: MigrationLineage? = nil,
  legacy: MigrationLegacyRemnants = .none,
  rootStore: MigrationRootStoreState = .empty
) -> AuthorityMigrationInventoryReader {
  AuthorityMigrationInventoryReader(
    runtime: FakeRuntimeInspector(runtime),
    manager: FakeDescriptorInspector(descriptor),
    hostLineage: FakeHostLineageInspector(hostLineage),
    providerCursor: FakeProviderCursorInspector(providerCursor),
    legacy: FakeLegacyInspector(legacy),
    rootStore: FakeRootStoreInspector(rootStore))
}

// MARK: - Read-only inventory tests

@Suite(.serialized)
struct AuthorityMigrationInventoryTests {
  @Test func readerComposesEverySeamIntoNonSecretInventory() async throws {
    let installationID = UUID()
    let descriptor = try tunnelDescriptor(installationID: installationID)
    let host = try lineage(installationID, epoch: 2, generation: 3)
    let cursor = try lineage(installationID, epoch: 1, generation: 1)
    let inventory = try await reader(
      runtime: .tunnelActive,
      descriptor: descriptor,
      hostLineage: host,
      providerCursor: cursor,
      legacy: MigrationLegacyRemnants(
        tombstonedHelperPresent: true, retiredCoreRemnantPresent: false),
      rootStore: .empty
    ).readInventory()

    #expect(inventory.temporaryRuntime == .tunnelActive)
    #expect(inventory.savedManagerDescriptor == descriptor)
    #expect(inventory.hostLineage == host)
    #expect(inventory.providerLocalCursor == cursor)
    #expect(inventory.legacyRemnants.tombstonedHelperPresent)
    #expect(inventory.rootStore == .empty)
    #expect(!inventory.ownerAmbiguity)
    // The descriptor implies a bounded lineage carrying no configuration bytes.
    #expect(inventory.descriptorLineage?.installationID == installationID)
    #expect(inventory.descriptorLineage?.epoch == 1)
  }

  @Test func ambiguousRuntimeMarksOwnerAmbiguity() async throws {
    let inventory = try await reader(runtime: .ambiguous).readInventory()
    #expect(inventory.ownerAmbiguity)
  }

  @Test func migrationImportsNoConfigurationOrSecretBytesIntoEnrollment() async throws {
    // The enroller receives ONLY a bounded lineage — never a descriptor,
    // configuration, or secret bytes.
    let installationID = UUID()
    let host = try lineage(installationID, epoch: 4, generation: 5)
    let enroller = RecordingEnroller(revision: 7)
    let run = await migration(
      inventory: reader(
        runtime: .tunnelActive,
        descriptor: try tunnelDescriptor(installationID: installationID),
        hostLineage: host,
        rootStore: .empty),
      enroller: enroller
    ).run()

    #expect(run.outcome == .enrolledOff(lineage: host, revision: 7))
    #expect(enroller.enrolled == host)
    // A MigrationLineage has exactly three non-secret fields.
    #expect(enroller.enrolled?.installationID == installationID)
    #expect(enroller.enrolled?.epoch == 4)
    #expect(enroller.enrolled?.generation == 5)
  }
}

// MARK: - Pure agreement tests

@Suite(.serialized)
struct AuthorityMigrationAgreementTests {
  @Test func enrollsHostLineageIntoEmptyStoreWhenInputsAgree() throws {
    let installationID = UUID()
    let host = try lineage(installationID, epoch: 2, generation: 2)
    let decision = AuthorityMigrationAgreement.decide(
      inventory: inventory(
        descriptor: try tunnelDescriptor(installationID: installationID),
        hostLineage: host,
        rootStore: .empty),
      hostIdentity: trustedHost())
    #expect(decision == .enroll(host))
  }

  @Test func untrustedIdentityFailsClosed() throws {
    let host = try lineage()
    let wrongTeam = MigrationHostIdentity(
      signingID: MigrationHostIdentity.expectedSigningID,
      teamID: "WRONGTEAMID", isLiveConsoleUser: true)
    let notConsole = trustedHost(consoleUser: false)
    let base = inventory(hostLineage: host, rootStore: .empty)

    #expect(
      AuthorityMigrationAgreement.decide(inventory: base, hostIdentity: wrongTeam)
        == .quarantine(.hostIdentityRejected))
    #expect(
      AuthorityMigrationAgreement.decide(inventory: base, hostIdentity: notConsole)
        == .quarantine(.hostIdentityRejected))
  }

  @Test func ambiguousOwnershipFailsClosed() throws {
    let decision = AuthorityMigrationAgreement.decide(
      inventory: inventory(hostLineage: try lineage(), ownerAmbiguity: true, rootStore: .empty),
      hostIdentity: trustedHost())
    #expect(decision == .quarantine(.ownerAmbiguous))
  }

  @Test func descriptorInstallationMismatchIsLineageConflict() throws {
    let host = try lineage(UUID(), epoch: 1, generation: 1)
    let descriptor = try tunnelDescriptor(installationID: UUID())
    let decision = AuthorityMigrationAgreement.decide(
      inventory: inventory(descriptor: descriptor, hostLineage: host, rootStore: .empty),
      hostIdentity: trustedHost())
    #expect(decision == .quarantine(.lineageConflict))
  }

  @Test func descriptorNewerThanHostHighWaterIsLineageConflict() throws {
    let installationID = UUID()
    let host = try lineage(installationID, epoch: 1, generation: 1)
    let descriptor = try tunnelDescriptor(installationID: installationID, epoch: 2, generation: 1)
    let decision = AuthorityMigrationAgreement.decide(
      inventory: inventory(descriptor: descriptor, hostLineage: host, rootStore: .empty),
      hostIdentity: trustedHost())
    #expect(decision == .quarantine(.lineageConflict))
  }

  @Test func providerCursorNeverEstablishesOrBlocksEnrollment() throws {
    // A disagreeing provider-local cursor is diagnostic only: it does not block
    // enrollment of the agreeing host lineage.
    let installationID = UUID()
    let host = try lineage(installationID, epoch: 3, generation: 3)
    let cursor = try lineage(UUID(), epoch: 9, generation: 9)
    let decision = AuthorityMigrationAgreement.decide(
      inventory: inventory(
        hostLineage: host, providerLocalCursor: cursor, rootStore: .empty),
      hostIdentity: trustedHost())
    #expect(decision == .enroll(host))
  }

  @Test func descriptorOnlyWithoutHostLineageFailsClosed() throws {
    let descriptor = try tunnelDescriptor(installationID: UUID())
    let decision = AuthorityMigrationAgreement.decide(
      inventory: inventory(descriptor: descriptor, hostLineage: nil, rootStore: .empty),
      hostIdentity: trustedHost())
    #expect(decision == .quarantine(.lineageConflict))
  }

  @Test func emptyInventoryNeedsNoMigration() {
    let decision = AuthorityMigrationAgreement.decide(
      inventory: inventory(rootStore: .empty), hostIdentity: trustedHost())
    #expect(decision == .noMigrationNeeded)
  }

  @Test func reenrollingSameInstallationIsIdempotent() throws {
    let installationID = UUID()
    let existing = try lineage(installationID, epoch: 5, generation: 5)
    let host = try lineage(installationID, epoch: 5, generation: 6)
    let decision = AuthorityMigrationAgreement.decide(
      inventory: inventory(hostLineage: host, rootStore: .enrolled(existing)),
      hostIdentity: trustedHost())
    #expect(decision == .alreadyEnrolled(existing))
  }

  @Test func differentInstallationAgainstEnrolledStoreIsImmutableConflict() throws {
    let existing = try lineage(UUID(), epoch: 5, generation: 5)
    let host = try lineage(UUID(), epoch: 6, generation: 6)
    let decision = AuthorityMigrationAgreement.decide(
      inventory: inventory(hostLineage: host, rootStore: .enrolled(existing)),
      hostIdentity: trustedHost())
    #expect(decision == .quarantine(.lineageConflict))
  }
}

// MARK: - Orchestrator tests

@Suite(.serialized)
struct AuthorityEnrollmentMigrationTests {
  @Test func happyPathStopsProvesReconcilesAndEnrollsEndingOff() async throws {
    let installationID = UUID()
    let host = try lineage(installationID, epoch: 1, generation: 1)
    let stopper = RecordingStopper()
    let reconciler = RecordingReconciler()
    let cleaner = RecordingCleaner()
    let enroller = RecordingEnroller(revision: 2)

    let run = await migration(
      inventory: reader(
        runtime: .tunnelActive,
        descriptor: try tunnelDescriptor(installationID: installationID),
        hostLineage: host,
        legacy: MigrationLegacyRemnants(
          tombstonedHelperPresent: true, retiredCoreRemnantPresent: false),
        rootStore: .empty),
      stopper: stopper,
      reconciler: reconciler,
      cleaner: cleaner,
      enroller: enroller
    ).run()

    #expect(run.outcome == .enrolledOff(lineage: host, revision: 2))
    #expect(run.outcome.isProvenOff)
    #expect(stopper.count == 1)
    #expect(reconciler.count == 1)
    #expect(cleaner.count == 1)
    #expect(enroller.count == 1)
    #expect(
      run.actions == [
        .inspected, .stoppedTemporaryActivity, .provedGlobalOff,
        .reconciledManagedManager, .cleanedLegacyRemnants, .enrolledLineage(host),
      ])
  }

  @Test func offAlreadyOffSkipsStopButStillEnrolls() async throws {
    let installationID = UUID()
    let host = try lineage(installationID, epoch: 1, generation: 1)
    let stopper = RecordingStopper()
    let run = await migration(
      inventory: reader(runtime: .off, hostLineage: host, rootStore: .empty),
      stopper: stopper
    ).run()

    #expect(run.outcome == .enrolledOff(lineage: host, revision: 2))
    #expect(stopper.count == 0)
    #expect(run.actions.first == .inspected)
    #expect(!run.actions.contains(.stoppedTemporaryActivity))
  }

  @Test func offBarrierNotProvenQuarantinesWithoutEnrolling() async throws {
    let host = try lineage()
    let enroller = RecordingEnroller()
    let notOff = MigrationGlobalOffObservation(
      leaseReleased: true, ticketsAndSecretsCleared: true, ownerEndpointCleared: true,
      temporaryRuntimeStopped: true, managedTunnelDisconnected: false, systemProxyRestored: true)
    let run = await migration(
      inventory: reader(runtime: .tunnelActive, hostLineage: host, rootStore: .empty),
      offProver: StubOffProver(notOff),
      enroller: enroller
    ).run()

    #expect(run.outcome == .quarantined(.globalOffNotProven))
    #expect(!run.outcome.isProvenOff)
    #expect(enroller.count == 0)
    #expect(!run.actions.contains(.provedGlobalOff))
    #expect(run.actions.last == .quarantined(.globalOffNotProven))
  }

  @Test func reconcileFailureQuarantines() async throws {
    let host = try lineage()
    let enroller = RecordingEnroller()
    let run = await migration(
      inventory: reader(hostLineage: host, rootStore: .empty),
      reconciler: RecordingReconciler(shouldThrow: true),
      enroller: enroller
    ).run()
    #expect(run.outcome == .quarantined(.reconcileFailed))
    #expect(enroller.count == 0)
  }

  @Test func identityRejectionAfterCleanupQuarantines() async throws {
    let host = try lineage()
    let enroller = RecordingEnroller()
    let run = await migration(
      inventory: reader(hostLineage: host, rootStore: .empty),
      identityFailure: true,
      enroller: enroller
    ).run()
    #expect(run.outcome == .quarantined(.hostIdentityRejected))
    #expect(enroller.count == 0)
  }

  @Test func enrollmentFailureQuarantines() async throws {
    let host = try lineage()
    let run = await migration(
      inventory: reader(hostLineage: host, rootStore: .empty),
      enroller: RecordingEnroller(shouldThrow: true)
    ).run()
    #expect(run.outcome == .quarantined(.enrollmentFailed))
  }

  @Test func alreadyEnrolledSameInstallationIsIdempotentOffWithoutEnrolling() async throws {
    let installationID = UUID()
    let existing = try lineage(installationID, epoch: 3, generation: 3)
    let host = try lineage(installationID, epoch: 3, generation: 4)
    let enroller = RecordingEnroller()
    let run = await migration(
      inventory: reader(hostLineage: host, rootStore: .enrolled(existing)),
      enroller: enroller
    ).run()
    #expect(run.outcome == .alreadyEnrolledOff(lineage: existing))
    #expect(run.outcome.isProvenOff)
    #expect(enroller.count == 0)
  }

  @Test func migrationNeverEmitsAStartActionOnAnyPath() async throws {
    // Exhaustively drive representative paths and assert the emitted actions are
    // always a subset of the inspection/stop/prove/reconcile/cleanup/enroll/
    // quarantine set — never a data-plane start.
    let installationID = UUID()
    let host = try lineage(installationID)
    let runs: [AuthorityMigrationRun] = [
      await migration(
        inventory: reader(runtime: .tunnelActive, hostLineage: host, rootStore: .empty)
      ).run(),
      await migration(
        inventory: reader(runtime: .ambiguous, hostLineage: host, rootStore: .empty)
      ).run(),
      await migration(
        inventory: reader(runtime: .systemProxyActive, rootStore: .empty),
        offProver: StubOffProver(provenOff(), failure: true)
      ).run(),
      await migration(inventory: reader(rootStore: .empty)).run(),
    ]

    let allowed: Set<Int> = [0, 1, 2, 3, 4, 5, 6]
    for run in runs {
      for action in run.actions {
        #expect(allowed.contains(actionTag(action)))
      }
      // Every terminal outcome is proven Off or Quarantined, never Active.
      switch run.outcome {
      case .enrolledOff, .alreadyEnrolledOff, .noMigrationNeededOff, .quarantined:
        break
      }
    }
  }

  private func actionTag(_ action: AuthorityMigrationAction) -> Int {
    switch action {
    case .inspected: 0
    case .stoppedTemporaryActivity: 1
    case .provedGlobalOff: 2
    case .reconciledManagedManager: 3
    case .cleanedLegacyRemnants: 4
    case .enrolledLineage: 5
    case .quarantined: 6
    }
  }
}

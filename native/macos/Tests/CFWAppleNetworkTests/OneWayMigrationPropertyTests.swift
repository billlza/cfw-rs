import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAppleNetwork

// MARK: - Property 12: Migration failures never revive a retired path
//
// For all generated temporary/legacy inventory states, host identities, and
// migration/recovery failures, the emitted action set is a subset of the closed
// inspect / stop / prove-Off / reconcile / cleanup / enroll / quarantine
// vocabulary — never a start, legacy-revive, direct-payload, or private-API
// action — and every terminal outcome is proven Off or Quarantined.
//
// This is a deterministic generative test driving the pure
// `AuthorityEnrollmentMigration` and `AuthorityMigrationRecovery` orchestrators
// (and their `AuthorityMigrationAction` vocabulary) over randomized inventories,
// identities, conditions, and injected failures. No real launchd, Network
// Extension, Keychain, or Security.framework work is used; every boundary is a
// fake driven from a reproducible seed. On failure the seed and the shrunk
// counterexample are printed so the exact case replays.
//
// **Validates: Requirements 1.2, 7.3**

// MARK: - Deterministic seed source

/// Deterministic, seedable value source (SplitMix64). Reproducible across runs
/// and platforms so a printed seed replays the exact generated case.
private struct SplitMix64: RandomNumberGenerator {
  private var state: UInt64

  init(seed: UInt64) { state = seed }

  mutating func next() -> UInt64 {
    state = state &+ 0x9E37_79B9_7F4A_7C15
    var z = state
    z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
    z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
    return z ^ (z >> 31)
  }

  mutating func int(inRange range: ClosedRange<Int>) -> Int {
    let span = UInt64(range.upperBound - range.lowerBound + 1)
    return range.lowerBound + Int(next() % span)
  }

  mutating func bool() -> Bool { next() & 1 == 0 }

  mutating func uuid() -> UUID {
    let hi = next()
    let lo = next()
    var bytes = [UInt8](repeating: 0, count: 16)
    for index in 0..<8 {
      bytes[index] = UInt8((hi >> (UInt64(index) * 8)) & 0xff)
      bytes[8 + index] = UInt8((lo >> (UInt64(index) * 8)) & 0xff)
    }
    return UUID(
      uuid: (
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
      ))
  }
}

// MARK: - Allowed action vocabulary

/// Classifies every `AuthorityMigrationAction` into the closed, allowed
/// vocabulary. The switch is intentionally exhaustive with no `default`: if a
/// new action case is ever added (for example a data-plane start), this stops
/// compiling and forces the reviewer to reconsider the retired-path invariant.
/// Every existing case maps to a member of the allowed set {0...6}.
private func allowedActionTag(_ action: AuthorityMigrationAction) -> Int {
  switch action {
  case .inspected: 0  // inspection
  case .stoppedTemporaryActivity: 1  // stop
  case .provedGlobalOff: 2  // prove Off
  case .reconciledManagedManager: 3  // reconciliation
  case .cleanedLegacyRemnants: 4  // cleanup
  case .enrolledLineage: 5  // enrollment
  case .quarantined: 6  // quarantine
  }
}

private let allowedActionTags: Set<Int> = [0, 1, 2, 3, 4, 5, 6]

private func isEnroll(_ action: AuthorityMigrationAction) -> Bool {
  if case .enrolledLineage = action { return true }
  return false
}

private func isQuarantine(_ action: AuthorityMigrationAction) -> Bool {
  if case .quarantined = action { return true }
  return false
}

// MARK: - Fakes (file-private; distinct from other test files)

private final class PBTRuntimeInspector: MigrationTemporaryRuntimeInspecting, @unchecked Sendable {
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

private final class PBTDescriptorInspector: MigrationManagerDescriptorInspecting,
  @unchecked Sendable
{
  let value: ConfigurationDescriptor?
  init(_ value: ConfigurationDescriptor?) { self.value = value }
  func inspectSavedManagerDescriptor() async throws -> ConfigurationDescriptor? { value }
}

private final class PBTHostLineageInspector: MigrationHostLineageInspecting, @unchecked Sendable {
  let value: MigrationLineage?
  init(_ value: MigrationLineage?) { self.value = value }
  func inspectHostLineage() async throws -> MigrationLineage? { value }
}

private final class PBTProviderCursorInspector: MigrationProviderCursorInspecting,
  @unchecked Sendable
{
  let value: MigrationLineage?
  init(_ value: MigrationLineage?) { self.value = value }
  func inspectProviderLocalCursor() async throws -> MigrationLineage? { value }
}

private final class PBTLegacyInspector: MigrationLegacyRemnantInspecting, @unchecked Sendable {
  let value: MigrationLegacyRemnants
  init(_ value: MigrationLegacyRemnants) { self.value = value }
  func inspectLegacyRemnants() async throws -> MigrationLegacyRemnants { value }
}

private final class PBTRootStoreInspector: MigrationRootStoreInspecting, @unchecked Sendable {
  let value: MigrationRootStoreState
  let shouldThrow: Bool
  init(_ value: MigrationRootStoreState, shouldThrow: Bool = false) {
    self.value = value
    self.shouldThrow = shouldThrow
  }
  func inspectRootStore() async throws -> MigrationRootStoreState {
    if shouldThrow { throw CancellationError() }
    return value
  }
}

private struct PBTIdentityResolver: MigrationHostIdentityResolving {
  let identity: MigrationHostIdentity
  let shouldThrow: Bool
  func resolveHostIdentity() async throws -> MigrationHostIdentity {
    if shouldThrow { throw CancellationError() }
    return identity
  }
}

private struct PBTStopper: MigrationTemporaryActivityStopping {
  let shouldThrow: Bool
  func stopProductOwnedTemporaryActivity() async throws {
    if shouldThrow { throw CancellationError() }
  }
}

private struct PBTOffProver: MigrationGlobalOffProving {
  let observation: MigrationGlobalOffObservation
  let shouldThrow: Bool
  func proveGlobalOff() async throws -> MigrationGlobalOffObservation {
    if shouldThrow { throw CancellationError() }
    return observation
  }
}

private struct PBTReconciler: MigrationManagedManagerReconciling {
  let shouldThrow: Bool
  func reconcileManagedManager() async throws {
    if shouldThrow { throw CancellationError() }
  }
}

private struct PBTCleaner: MigrationLegacyRemnantCleaning {
  let shouldThrow: Bool
  func cleanupLegacyRemnants() async throws {
    if shouldThrow { throw CancellationError() }
  }
}

private struct PBTEnroller: MigrationLineageEnrolling {
  let shouldThrow: Bool
  func enroll(_ lineage: MigrationLineage) async throws -> UInt64 {
    if shouldThrow { throw CancellationError() }
    return 2
  }
}

// MARK: - Shared builders

private func provenOff() -> MigrationGlobalOffObservation {
  MigrationGlobalOffObservation(
    leaseReleased: true, ticketsAndSecretsCleared: true, ownerEndpointCleared: true,
    temporaryRuntimeStopped: true, managedTunnelDisconnected: true, systemProxyRestored: true)
}

private func partiallyOff() -> MigrationGlobalOffObservation {
  MigrationGlobalOffObservation(
    leaseReleased: true, ticketsAndSecretsCleared: true, ownerEndpointCleared: true,
    temporaryRuntimeStopped: true, managedTunnelDisconnected: false, systemProxyRestored: true)
}

private let runtimes: [MigrationTemporaryRuntime] = [
  .off, .systemProxyActive, .tunnelActive, .ambiguous,
]

private func hostIdentity(index: Int) -> MigrationHostIdentity {
  switch index {
  case 1:
    MigrationHostIdentity(
      signingID: "com.attacker.fake", teamID: MigrationHostIdentity.expectedTeamID,
      isLiveConsoleUser: true)
  case 2:
    MigrationHostIdentity(
      signingID: MigrationHostIdentity.expectedSigningID, teamID: "WRONGTEAMID0",
      isLiveConsoleUser: true)
  case 3:
    MigrationHostIdentity(
      signingID: MigrationHostIdentity.expectedSigningID,
      teamID: MigrationHostIdentity.expectedTeamID, isLiveConsoleUser: false)
  default:
    MigrationHostIdentity(
      signingID: MigrationHostIdentity.expectedSigningID,
      teamID: MigrationHostIdentity.expectedTeamID, isLiveConsoleUser: true)
  }
}

private func remnants(index: Int) -> MigrationLegacyRemnants {
  switch index {
  case 1: MigrationLegacyRemnants(tombstonedHelperPresent: true, retiredCoreRemnantPresent: false)
  case 2: MigrationLegacyRemnants(tombstonedHelperPresent: false, retiredCoreRemnantPresent: true)
  case 3: MigrationLegacyRemnants(tombstonedHelperPresent: true, retiredCoreRemnantPresent: true)
  default: .none
  }
}

private func descriptor(
  installationID: UUID, epoch: UInt64, generation: UInt64, tunnel: Bool
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: tunnel ? .tunnel : .systemProxy,
    tunnelOptions: tunnel ? try TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500) : nil,
    installationID: installationID,
    epoch: epoch,
    generation: generation,
    byteCount: 2,
    sha256: try SHA256Digest(hex: String(repeating: "ab", count: 32)),
    identitySHA256: try SHA256Digest(hex: String(repeating: "cd", count: 32)))
}

// MARK: - Failure injection

/// The single stage (if any) at which a generated run is forced to fail. Kept
/// small and ordered so a counterexample can shrink toward `.none`.
private enum FailurePoint: Int, CaseIterable {
  case none
  case inventoryUnavailable
  case stopFailed
  case offProverThrew
  case offNotProven
  case reconcileFailed
  case identityRejected
  case enrollmentFailed
  case cleanupFailed
}

// MARK: - Enrollment property

/// Numeric choices that fully determine a generated enrollment scenario.
private struct EnrollmentChoices: Equatable {
  var runtimeIndex: Int
  var hasHostLineage: Bool
  var hasDescriptor: Bool
  var descriptorSameInstallation: Bool
  var descriptorNewerThanHost: Bool
  var rootStoreEnrolled: Bool
  var enrolledSameInstallation: Bool
  var identityIndex: Int
  var remnantIndex: Int
  var hasProviderCursor: Bool
  var modeIsTunnel: Bool
  var failure: FailurePoint

  static let cleanSuccess = EnrollmentChoices(
    runtimeIndex: 0, hasHostLineage: true, hasDescriptor: false,
    descriptorSameInstallation: true, descriptorNewerThanHost: false,
    rootStoreEnrolled: false, enrolledSameInstallation: true, identityIndex: 0,
    remnantIndex: 0, hasProviderCursor: false, modeIsTunnel: true, failure: .none)
}

private struct EnrollmentProperty {
  func randomChoices(using rng: inout SplitMix64) -> EnrollmentChoices {
    EnrollmentChoices(
      runtimeIndex: rng.int(inRange: 0...3),
      hasHostLineage: rng.bool(),
      hasDescriptor: rng.bool(),
      descriptorSameInstallation: rng.bool(),
      descriptorNewerThanHost: rng.bool(),
      rootStoreEnrolled: rng.bool(),
      enrolledSameInstallation: rng.bool(),
      identityIndex: rng.int(inRange: 0...3),
      remnantIndex: rng.int(inRange: 0...3),
      hasProviderCursor: rng.bool(),
      modeIsTunnel: rng.bool(),
      failure: FailurePoint.allCases[rng.int(inRange: 0...(FailurePoint.allCases.count - 1))])
  }

  func run(
    _ c: EnrollmentChoices, using rng: inout SplitMix64
  ) async throws -> AuthorityMigrationRun {
    let installationID = rng.uuid()
    let otherID = rng.uuid()

    let hostEpoch: UInt64 = 3
    let hostGeneration: UInt64 = 3
    let host: MigrationLineage? =
      c.hasHostLineage
      ? try MigrationLineage(
        installationID: installationID, epoch: hostEpoch, generation: hostGeneration)
      : nil

    let descriptorValue: ConfigurationDescriptor?
    if c.hasDescriptor {
      let descID = c.descriptorSameInstallation ? installationID : otherID
      let epoch = c.descriptorNewerThanHost ? hostEpoch + 1 : hostEpoch
      descriptorValue = try descriptor(
        installationID: descID, epoch: epoch, generation: 1, tunnel: c.modeIsTunnel)
    } else {
      descriptorValue = nil
    }

    let rootState: MigrationRootStoreState
    if c.rootStoreEnrolled {
      let enrolledID = c.enrolledSameInstallation ? installationID : otherID
      rootState = .enrolled(
        try MigrationLineage(installationID: enrolledID, epoch: 2, generation: 2))
    } else {
      rootState = .empty
    }

    let cursor: MigrationLineage? =
      c.hasProviderCursor
      ? try MigrationLineage(installationID: rng.uuid(), epoch: 9, generation: 9) : nil

    let reader = AuthorityMigrationInventoryReader(
      runtime: PBTRuntimeInspector(runtimes[c.runtimeIndex]),
      manager: PBTDescriptorInspector(descriptorValue),
      hostLineage: PBTHostLineageInspector(host),
      providerCursor: PBTProviderCursorInspector(cursor),
      legacy: PBTLegacyInspector(remnants(index: c.remnantIndex)),
      rootStore: PBTRootStoreInspector(
        rootState, shouldThrow: c.failure == .inventoryUnavailable))

    let observation = c.failure == .offNotProven ? partiallyOff() : provenOff()

    let migration = AuthorityEnrollmentMigration(
      inventoryReader: reader,
      identityResolver: PBTIdentityResolver(
        identity: hostIdentity(index: c.identityIndex),
        shouldThrow: c.failure == .identityRejected),
      stopper: PBTStopper(shouldThrow: c.failure == .stopFailed),
      offProver: PBTOffProver(
        observation: observation, shouldThrow: c.failure == .offProverThrew),
      reconciler: PBTReconciler(shouldThrow: c.failure == .reconcileFailed),
      cleaner: PBTCleaner(shouldThrow: c.failure == .cleanupFailed),
      enroller: PBTEnroller(shouldThrow: c.failure == .enrollmentFailed))

    return await migration.run()
  }

  /// Returns nil when the run satisfies Property 12, or a violation description.
  func evaluate(_ c: EnrollmentChoices, seed: UInt64) async -> String? {
    var rng = SplitMix64(seed: seed)
    let run: AuthorityMigrationRun
    do {
      run = try await self.run(c, using: &rng)
    } catch {
      return "fixture construction failed: \(error)"
    }
    return check(run)
  }

  /// The shared safety oracle for an enrollment run.
  func check(_ run: AuthorityMigrationRun) -> String? {
    // (1) Every emitted action is within the closed allowed vocabulary.
    for action in run.actions where !allowedActionTags.contains(allowedActionTag(action)) {
      return "emitted action outside allowed vocabulary: \(action)"
    }

    // (2) Terminal outcome is proven Off or Quarantined — never a running plane.
    let quarantined: Bool
    switch run.outcome {
    case .enrolledOff, .alreadyEnrolledOff, .noMigrationNeededOff:
      quarantined = false
      if !run.outcome.isProvenOff {
        return "non-quarantine outcome did not report proven Off"
      }
    case .quarantined:
      quarantined = true
    }

    // (3) Retired-path invariant: the only forward/mutating action, enrollment,
    // may appear ONLY after a proven global Off barrier and a reconcile, and
    // only when the outcome is enrolledOff. A failure can never revive it.
    let enrollActions = run.actions.filter(isEnroll)
    if enrollActions.count > 1 {
      return "enrollment emitted more than once: \(run.actions)"
    }
    if let enrollIndex = run.actions.firstIndex(where: isEnroll) {
      guard case .enrolledOff = run.outcome else {
        return "enrollment action emitted without an enrolledOff outcome: \(run.outcome)"
      }
      let prefix = run.actions[..<enrollIndex]
      guard prefix.contains(.provedGlobalOff) else {
        return "enrollment emitted without a proven global Off barrier"
      }
      guard prefix.contains(.reconciledManagedManager) else {
        return "enrollment emitted without reconciling the managed manager"
      }
    } else if case .enrolledOff = run.outcome {
      return "enrolledOff outcome without an enrollment action"
    }

    // (4) A quarantined outcome ends with exactly one trailing quarantine action
    // and never enrolls.
    if quarantined {
      guard run.actions.last.map(isQuarantine) == true else {
        return "quarantined outcome without a trailing quarantine action"
      }
      if !enrollActions.isEmpty {
        return "quarantined outcome still emitted an enrollment action"
      }
    } else if run.actions.contains(where: isQuarantine) {
      return "non-quarantine outcome emitted a quarantine action"
    }

    return nil
  }

  // MARK: Shrinking

  private func shrinkCandidates(_ c: EnrollmentChoices) -> [EnrollmentChoices] {
    var out: [EnrollmentChoices] = []
    func mutate(_ transform: (inout EnrollmentChoices) -> Void) {
      var copy = c
      transform(&copy)
      if copy != c { out.append(copy) }
    }
    if c.failure != .none { mutate { $0.failure = .none } }
    if c.runtimeIndex != 0 { mutate { $0.runtimeIndex = 0 } }
    if c.identityIndex != 0 { mutate { $0.identityIndex = 0 } }
    if c.remnantIndex != 0 { mutate { $0.remnantIndex = 0 } }
    if c.hasDescriptor { mutate { $0.hasDescriptor = false } }
    if c.rootStoreEnrolled { mutate { $0.rootStoreEnrolled = false } }
    if c.hasProviderCursor { mutate { $0.hasProviderCursor = false } }
    if c.descriptorNewerThanHost { mutate { $0.descriptorNewerThanHost = false } }
    if !c.descriptorSameInstallation { mutate { $0.descriptorSameInstallation = true } }
    if !c.hasHostLineage { mutate { $0.hasHostLineage = true } }
    return out
  }

  func shrink(_ c: EnrollmentChoices, seed: UInt64) async -> EnrollmentChoices {
    var current = c
    var improved = true
    while improved {
      improved = false
      for candidate in shrinkCandidates(current) {
        if await evaluate(candidate, seed: seed) != nil {
          current = candidate
          improved = true
          break
        }
      }
    }
    return current
  }
}

// MARK: - Recovery property

/// Numeric choices that fully determine a generated recovery scenario.
private struct RecoveryChoices: Equatable {
  var conditionIndex: Int
  var runtimeIndex: Int
  var remnantIndex: Int
  var hasHostLineage: Bool
  var hasDescriptor: Bool
  var failure: FailurePoint

  static let cleanCleanup = RecoveryChoices(
    conditionIndex: 0, runtimeIndex: 0, remnantIndex: 0, hasHostLineage: false,
    hasDescriptor: false, failure: .none)
}

private struct RecoveryProperty {
  /// The recovery conditions. Indices map to a broad spread of both
  /// inspect-then-quarantine and cleanup-to-proven-Off policies.
  func condition(index: Int) -> AuthorityMigrationRecoveryCondition {
    switch index {
    case 0: .crashRecovery(.pendingVerifyOff)
    case 1: .crashRecovery(.pendingStopOwner)
    case 2: .crashRecovery(.pendingReattestOwner)
    case 3: .registrationDenied
    case 4: .protocolIncompatible
    case 5: .downgrade
    case 6: .replacement
    case 7: .authorityUninstall
    case 8: .crashRecovery(.ambiguous)
    case 9: .migrationDisagreement(.lineageConflict)
    case 10: .migrationDisagreement(.ownerAmbiguous)
    default: .migrationDisagreement(.hostIdentityRejected)
    }
  }

  var conditionCount: Int { 12 }

  func randomChoices(using rng: inout SplitMix64) -> RecoveryChoices {
    RecoveryChoices(
      conditionIndex: rng.int(inRange: 0...(conditionCount - 1)),
      runtimeIndex: rng.int(inRange: 0...3),
      remnantIndex: rng.int(inRange: 0...3),
      hasHostLineage: rng.bool(),
      hasDescriptor: rng.bool(),
      failure: FailurePoint.allCases[rng.int(inRange: 0...(FailurePoint.allCases.count - 1))])
  }

  func run(
    _ c: RecoveryChoices, using rng: inout SplitMix64
  ) async throws -> AuthorityMigrationRecoveryRun {
    let installationID = rng.uuid()
    let host: MigrationLineage? =
      c.hasHostLineage
      ? try MigrationLineage(installationID: installationID, epoch: 3, generation: 3) : nil
    let descriptorValue =
      c.hasDescriptor
      ? try descriptor(installationID: installationID, epoch: 3, generation: 1, tunnel: true) : nil

    let reader = AuthorityMigrationInventoryReader(
      runtime: PBTRuntimeInspector(runtimes[c.runtimeIndex]),
      manager: PBTDescriptorInspector(descriptorValue),
      hostLineage: PBTHostLineageInspector(host),
      providerCursor: PBTProviderCursorInspector(nil),
      legacy: PBTLegacyInspector(remnants(index: c.remnantIndex)),
      rootStore: PBTRootStoreInspector(.empty, shouldThrow: c.failure == .inventoryUnavailable))

    let observation = c.failure == .offNotProven ? partiallyOff() : provenOff()

    let recovery = AuthorityMigrationRecovery(
      inventoryReader: reader,
      stopper: PBTStopper(shouldThrow: c.failure == .stopFailed),
      offProver: PBTOffProver(
        observation: observation, shouldThrow: c.failure == .offProverThrew),
      reconciler: PBTReconciler(shouldThrow: c.failure == .reconcileFailed),
      cleaner: PBTCleaner(shouldThrow: c.failure == .cleanupFailed))

    return await recovery.run(from: self.condition(index: c.conditionIndex))
  }

  func evaluate(_ c: RecoveryChoices, seed: UInt64) async -> String? {
    var rng = SplitMix64(seed: seed)
    let run: AuthorityMigrationRecoveryRun
    do {
      run = try await self.run(c, using: &rng)
    } catch {
      return "fixture construction failed: \(error)"
    }
    return check(run)
  }

  func check(_ run: AuthorityMigrationRecoveryRun) -> String? {
    // (1) Every emitted action is within the closed allowed vocabulary.
    for action in run.actions where !allowedActionTags.contains(allowedActionTag(action)) {
      return "emitted action outside allowed vocabulary: \(action)"
    }

    // (2) Recovery can NEVER enroll — that would be a forward mutation reviving a
    // path recovery must only tear down.
    if run.actions.contains(where: isEnroll) {
      return "recovery emitted an enrollment action: \(run.actions)"
    }

    // (3) Terminal outcome is proven Off (after cleanup) or Quarantined.
    switch run.outcome {
    case .cleanedOff:
      if !run.outcome.isProvenOff {
        return "cleanedOff outcome did not report proven Off"
      }
      // Cleanup can only conclude after a proven global Off barrier.
      guard run.actions.contains(.provedGlobalOff) else {
        return "cleanedOff without a proven global Off barrier"
      }
      if run.actions.contains(where: isQuarantine) {
        return "cleanedOff outcome emitted a quarantine action"
      }
    case .quarantined:
      guard run.actions.last.map(isQuarantine) == true else {
        return "quarantined outcome without a trailing quarantine action"
      }
    }

    return nil
  }

  // MARK: Shrinking

  private func shrinkCandidates(_ c: RecoveryChoices) -> [RecoveryChoices] {
    var out: [RecoveryChoices] = []
    func mutate(_ transform: (inout RecoveryChoices) -> Void) {
      var copy = c
      transform(&copy)
      if copy != c { out.append(copy) }
    }
    if c.failure != .none { mutate { $0.failure = .none } }
    if c.conditionIndex != 0 { mutate { $0.conditionIndex = 0 } }
    if c.runtimeIndex != 0 { mutate { $0.runtimeIndex = 0 } }
    if c.remnantIndex != 0 { mutate { $0.remnantIndex = 0 } }
    if c.hasDescriptor { mutate { $0.hasDescriptor = false } }
    if c.hasHostLineage { mutate { $0.hasHostLineage = false } }
    return out
  }

  func shrink(_ c: RecoveryChoices, seed: UInt64) async -> RecoveryChoices {
    var current = c
    var improved = true
    while improved {
      improved = false
      for candidate in shrinkCandidates(current) {
        if await evaluate(candidate, seed: seed) != nil {
          current = candidate
          improved = true
          break
        }
      }
    }
    return current
  }
}

// MARK: - Seeds

/// Base seed for the enrollment property. Override with
/// `CFW_PBT_SEED_PROP12_ENROLL` to replay a printed failure.
private func enrollmentBaseSeed() -> UInt64 {
  if let raw = ProcessInfo.processInfo.environment["CFW_PBT_SEED_PROP12_ENROLL"],
    let value = UInt64(raw)
  {
    return value
  }
  return 0xC0FF_EE12_1111_0001
}

/// Base seed for the recovery property. Override with
/// `CFW_PBT_SEED_PROP12_RECOVER` to replay a printed failure.
private func recoveryBaseSeed() -> UInt64 {
  if let raw = ProcessInfo.processInfo.environment["CFW_PBT_SEED_PROP12_RECOVER"],
    let value = UInt64(raw)
  {
    return value
  }
  return 0xC0FF_EE12_2222_0001
}

// MARK: - Tests

@Test func enrollmentMigrationFailuresNeverReviveARetiredPath() async {
  let property = EnrollmentProperty()
  let seed = enrollmentBaseSeed()
  let iterations = 140

  var successfulCases = 0
  var enrollments = 0
  var quarantines = 0
  var failuresInjected = 0
  var firstFailure: (seed: UInt64, choices: EnrollmentChoices, reason: String)?

  for index in 0..<iterations {
    let iterationSeed = seed &+ UInt64(index)
    var rng = SplitMix64(seed: iterationSeed)
    // Deterministically interleave a guaranteed clean success so the enrollment
    // path is always exercised and proven to reach a proven-Off enrollment.
    let choices: EnrollmentChoices =
      index % 5 == 0 ? .cleanSuccess : property.randomChoices(using: &rng)

    if let reason = await property.evaluate(choices, seed: iterationSeed) {
      let shrunk = await property.shrink(choices, seed: iterationSeed)
      let shrunkReason = await property.evaluate(shrunk, seed: iterationSeed) ?? reason
      firstFailure = (iterationSeed, shrunk, shrunkReason)
      break
    }

    // Coverage bookkeeping via a fresh, identical stream.
    var coverageRng = SplitMix64(seed: iterationSeed)
    if let run = try? await property.run(choices, using: &coverageRng) {
      if run.actions.contains(where: isEnroll) { enrollments += 1 }
      if case .quarantined = run.outcome { quarantines += 1 }
    }
    if choices.failure != .none { failuresInjected += 1 }
    successfulCases += 1
  }

  if let failure = firstFailure {
    Issue.record(
      """
      Property 12 (enrollment) counterexample found.
      reproduce with: CFW_PBT_SEED_PROP12_ENROLL=\(failure.seed)
      shrunk choices: \(failure.choices)
      violation: \(failure.reason)
      """)
  }

  #expect(firstFailure == nil)
  #expect(
    successfulCases >= 100,
    "expected at least 100 successful generated cases, ran \(successfulCases)")
  #expect(enrollments > 0, "generated batch never exercised a successful enrollment")
  #expect(quarantines > 0, "generated batch never exercised a quarantine")
  #expect(failuresInjected > 0, "generated batch never exercised an injected failure")
}

@Test func recoveryMigrationFailuresNeverReviveARetiredPath() async {
  let property = RecoveryProperty()
  let seed = recoveryBaseSeed()
  let iterations = 140

  var successfulCases = 0
  var cleanups = 0
  var quarantines = 0
  var failuresInjected = 0
  var firstFailure: (seed: UInt64, choices: RecoveryChoices, reason: String)?

  for index in 0..<iterations {
    let iterationSeed = seed &+ UInt64(index)
    var rng = SplitMix64(seed: iterationSeed)
    // Deterministically interleave a guaranteed clean cleanup-to-Off and a
    // guaranteed ambiguous quarantine so both recovery policies are exercised.
    let choices: RecoveryChoices
    switch index % 5 {
    case 0: choices = .cleanCleanup
    case 1:
      choices = RecoveryChoices(
        conditionIndex: 8, runtimeIndex: 0, remnantIndex: 0, hasHostLineage: false,
        hasDescriptor: false, failure: .none)
    default: choices = property.randomChoices(using: &rng)
    }

    if let reason = await property.evaluate(choices, seed: iterationSeed) {
      let shrunk = await property.shrink(choices, seed: iterationSeed)
      let shrunkReason = await property.evaluate(shrunk, seed: iterationSeed) ?? reason
      firstFailure = (iterationSeed, shrunk, shrunkReason)
      break
    }

    var coverageRng = SplitMix64(seed: iterationSeed)
    if let run = try? await property.run(choices, using: &coverageRng) {
      switch run.outcome {
      case .cleanedOff: cleanups += 1
      case .quarantined: quarantines += 1
      }
    }
    if choices.failure != .none { failuresInjected += 1 }
    successfulCases += 1
  }

  if let failure = firstFailure {
    Issue.record(
      """
      Property 12 (recovery) counterexample found.
      reproduce with: CFW_PBT_SEED_PROP12_RECOVER=\(failure.seed)
      shrunk choices: \(failure.choices)
      violation: \(failure.reason)
      """)
  }

  #expect(firstFailure == nil)
  #expect(
    successfulCases >= 100,
    "expected at least 100 successful generated cases, ran \(successfulCases)")
  #expect(cleanups > 0, "generated batch never exercised a cleanup-to-Off recovery")
  #expect(quarantines > 0, "generated batch never exercised a quarantine")
  #expect(failuresInjected > 0, "generated batch never exercised an injected failure")
}

import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAppleNetwork

// Shared by the Property 12 tests: the seed source, the allowed action
// vocabulary, the PBT fakes and builders, and the failure points.
// MARK: - Deterministic seed source

/// Deterministic, seedable value source (SplitMix64). Reproducible across runs
/// and platforms so a printed seed replays the exact generated case.
struct PBTSplitMix64: RandomNumberGenerator {
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
func allowedActionTag(_ action: AuthorityMigrationAction) -> Int {
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

let allowedActionTags: Set<Int> = [0, 1, 2, 3, 4, 5, 6]

func isEnroll(_ action: AuthorityMigrationAction) -> Bool {
  if case .enrolledLineage = action { return true }
  return false
}

func isQuarantine(_ action: AuthorityMigrationAction) -> Bool {
  if case .quarantined = action { return true }
  return false
}

// MARK: - Fakes (PBT-prefixed; distinct from other test files' fakes)

final class PBTRuntimeInspector: MigrationTemporaryRuntimeInspecting, @unchecked Sendable {
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

final class PBTDescriptorInspector: MigrationManagerDescriptorInspecting,
  @unchecked Sendable
{
  let value: ConfigurationDescriptor?
  init(_ value: ConfigurationDescriptor?) { self.value = value }
  func inspectSavedManagerDescriptor() async throws -> ConfigurationDescriptor? { value }
}

final class PBTHostLineageInspector: MigrationHostLineageInspecting, @unchecked Sendable {
  let value: MigrationLineage?
  init(_ value: MigrationLineage?) { self.value = value }
  func inspectHostLineage() async throws -> MigrationLineage? { value }
}

final class PBTProviderCursorInspector: MigrationProviderCursorInspecting,
  @unchecked Sendable
{
  let value: MigrationLineage?
  init(_ value: MigrationLineage?) { self.value = value }
  func inspectProviderLocalCursor() async throws -> MigrationLineage? { value }
}

final class PBTLegacyInspector: MigrationLegacyRemnantInspecting, @unchecked Sendable {
  let value: MigrationLegacyRemnants
  init(_ value: MigrationLegacyRemnants) { self.value = value }
  func inspectLegacyRemnants() async throws -> MigrationLegacyRemnants { value }
}

final class PBTRootStoreInspector: MigrationRootStoreInspecting, @unchecked Sendable {
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

struct PBTIdentityResolver: MigrationHostIdentityResolving {
  let identity: MigrationHostIdentity
  let shouldThrow: Bool
  func resolveHostIdentity() async throws -> MigrationHostIdentity {
    if shouldThrow { throw CancellationError() }
    return identity
  }
}

struct PBTStopper: MigrationTemporaryActivityStopping {
  let shouldThrow: Bool
  func stopProductOwnedTemporaryActivity() async throws {
    if shouldThrow { throw CancellationError() }
  }
}

struct PBTOffProver: MigrationGlobalOffProving {
  let observation: MigrationGlobalOffObservation
  let shouldThrow: Bool
  func proveGlobalOff() async throws -> MigrationGlobalOffObservation {
    if shouldThrow { throw CancellationError() }
    return observation
  }
}

struct PBTReconciler: MigrationManagedManagerReconciling {
  let shouldThrow: Bool
  func reconcileManagedManager() async throws {
    if shouldThrow { throw CancellationError() }
  }
}

struct PBTCleaner: MigrationLegacyRemnantCleaning {
  let shouldThrow: Bool
  func cleanupLegacyRemnants() async throws {
    if shouldThrow { throw CancellationError() }
  }
}

struct PBTEnroller: MigrationLineageEnrolling {
  let shouldThrow: Bool
  func enroll(_ lineage: MigrationLineage) async throws -> UInt64 {
    if shouldThrow { throw CancellationError() }
    return 2
  }
}

// MARK: - Shared builders

func pbtProvenOff() -> MigrationGlobalOffObservation {
  MigrationGlobalOffObservation(
    leaseReleased: true, ticketsAndSecretsCleared: true, ownerEndpointCleared: true,
    temporaryRuntimeStopped: true, managedTunnelDisconnected: true, systemProxyRestored: true)
}

func partiallyOff() -> MigrationGlobalOffObservation {
  MigrationGlobalOffObservation(
    leaseReleased: true, ticketsAndSecretsCleared: true, ownerEndpointCleared: true,
    temporaryRuntimeStopped: true, managedTunnelDisconnected: false, systemProxyRestored: true)
}

let runtimes: [MigrationTemporaryRuntime] = [
  .off, .systemProxyActive, .tunnelActive, .ambiguous,
]

func hostIdentity(index: Int) -> MigrationHostIdentity {
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

func remnants(index: Int) -> MigrationLegacyRemnants {
  switch index {
  case 1: MigrationLegacyRemnants(tombstonedHelperPresent: true, retiredCoreRemnantPresent: false)
  case 2: MigrationLegacyRemnants(tombstonedHelperPresent: false, retiredCoreRemnantPresent: true)
  case 3: MigrationLegacyRemnants(tombstonedHelperPresent: true, retiredCoreRemnantPresent: true)
  default: .none
  }
}

func pbtDescriptor(
  installationID: UUID, epoch: UInt64, generation: UInt64, tunnel: Bool
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: tunnel ? .tunnel : .systemProxy,
    tunnelOptions: tunnel ? try TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500) : nil,
    credentialAudience: try appleCredentialAudience(),
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
enum FailurePoint: Int, CaseIterable {
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

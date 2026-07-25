import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAppleNetwork

// Property 9 (Preference compensation preserves external changes).
// Validates: Requirements 3.4, 7.3
//
// This file is a self-contained, deterministic property-based test. It uses its
// own seeded generator (a SplitMix64 PRNG) rather than an external PBT dependency
// so the whole thing runs offline and reproducibly under
// `swift test -c release --filter CFWAppleNetworkTests`.
//
// The property under test: for ALL prior manager states, ALL post-save failure
// points (cancellation, reload mismatch, ticket expiry, synchronous start
// failure, provider rejection, readiness timeout, Authority revocation), and ALL
// concurrent external/administrator edits, the ordered compare-and-restore
// compensation ends ONLY in one of two globally-safe outcomes:
//
//   * verified Off  — the operation's write was cleanly reverted, and the OS
//                     proves the managed tunnel disconnected/invalid; or
//   * Quarantined   — a `compensationConflict` (an external/administrator change
//                     is refused, never overwritten) or a `cleanupUnproven`
//                     (bounded stop timeout / unverifiable restore).
//
// It further proves the invariants of Requirement 3.4 / Property 9:
//   * external changes are NEVER overwritten (they force conflict/quarantine),
//   * managers this operation created are removed on the verified-Off path,
//   * secrets are erased on EVERY terminal path (success, conflict, timeout,
//     thrown error).
//
// Every Authority/NetworkExtension side effect is a deterministic in-memory fake;
// no real NetworkExtension, XPC, or Authority is exercised. On failure the master
// seed, the failing case index, and the shrunk counterexample are printed so any
// failure is exactly reproducible.

// MARK: - Deterministic PRNG (own generator, no external PBT dependency)

private struct SplitMix64: RandomNumberGenerator {
  private var state: UInt64
  init(seed: UInt64) { state = seed }
  mutating func next() -> UInt64 {
    state &+= 0x9E37_79B9_7F4A_7C15
    var z = state
    z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
    z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
    return z ^ (z >> 31)
  }
}

extension SplitMix64 {
  mutating func int(in range: ClosedRange<Int>) -> Int {
    let span = UInt64(range.upperBound - range.lowerBound + 1)
    return range.lowerBound + Int(next() % span)
  }
  mutating func bool() -> Bool { next() & 1 == 0 }
  mutating func pick<T>(_ values: [T]) -> T { values[int(in: 0...(values.count - 1))] }
}

// MARK: - Deterministic fakes

private final class RecordingAuthorityRevoker: AuthorityPreparationRevoking, @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0
  var revokeCount: Int { lock.withLock { count } }
  func revokePreparation() async throws { lock.withLock { count += 1 } }
}

private final class EraseCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0
  var eraseCount: Int { lock.withLock { count } }
  var eraser: @Sendable () -> Void { { self.lock.withLock { self.count += 1 } } }
}

/// A durable-preference-store fake whose reads reflect any external/administrator
/// edit staged before compensation runs, and whose stop/apply/remove behaviour is
/// configurable so the generator can exercise every terminal path.
private final class StoreFake: ManagedTunnelPreferences, @unchecked Sendable {
  private let lock = NSLock()
  private var status: ManagedTunnelConnectionStatus
  private var values: ManagedTunnelPreferenceValues?
  private let stopReachesDisconnected: Bool
  private let applyMutatesStore: Bool
  private let removeMutatesStore: Bool
  private var applyCount = 0
  private var removeCount = 0
  private var stopCount = 0

  init(
    status: ManagedTunnelConnectionStatus,
    values: ManagedTunnelPreferenceValues?,
    stopReachesDisconnected: Bool,
    applyMutatesStore: Bool,
    removeMutatesStore: Bool
  ) {
    self.status = status
    self.values = values
    self.stopReachesDisconnected = stopReachesDisconnected
    self.applyMutatesStore = applyMutatesStore
    self.removeMutatesStore = removeMutatesStore
  }

  var currentValues: ManagedTunnelPreferenceValues? { lock.withLock { values } }
  var applies: Int { lock.withLock { applyCount } }
  var removes: Int { lock.withLock { removeCount } }
  var stops: Int { lock.withLock { stopCount } }

  func loadCurrentValues() async throws -> ManagedTunnelPreferenceValues? {
    lock.withLock { values }
  }

  func connectionStatus() async throws -> ManagedTunnelConnectionStatus {
    lock.withLock { status }
  }

  func stop() async throws {
    lock.withLock {
      stopCount += 1
      if stopReachesDisconnected { status = .disconnected }
    }
  }

  func apply(_ newValues: ManagedTunnelPreferenceValues) async throws {
    lock.withLock {
      applyCount += 1
      if applyMutatesStore {
        values = newValues
        status = .invalid
      }
    }
  }

  func removeManager() async throws {
    lock.withLock {
      removeCount += 1
      if removeMutatesStore {
        values = nil
        status = .invalid
      }
    }
  }
}

// MARK: - Scenario model

/// A generated post-save failure situation. `externalKind` captures the
/// concurrent external/administrator edit dimension; `trigger` records which of
/// the seven post-save failure points fired (the compensation is trigger-agnostic,
/// so the trigger only labels the counterexample).
private struct Scenario: Equatable, CustomStringConvertible {
  enum ExternalKind: String, Equatable, CaseIterable { case none, edited, removed }

  var createdManager: Bool
  var trigger: String
  var externalKind: ExternalKind
  var status: ManagedTunnelConnectionStatus
  var stopReaches: Bool
  var applyMutates: Bool
  var removeMutates: Bool
  // Distinct generation tags guarantee written/prior/external values are pairwise
  // unequal regardless of the other randomized fields.
  var writtenGen: Int
  var priorGen: Int
  var externalGen: Int
  var writtenEnabled: Bool
  var priorEnabled: Bool
  var externalEnabled: Bool
  var writtenIPv6: Bool
  var priorIPv6: Bool
  var externalIPv6: Bool
  var descIndex: Int

  static let triggers = [
    "cancellationBeforeStart", "reloadMismatch", "ticketExpiry",
    "synchronousStartFailure", "providerRejection", "readinessTimeout",
    "authorityRevocation",
  ]
  static let statuses: [ManagedTunnelConnectionStatus] = [
    .invalid, .disconnected, .connecting, .connected, .reasserting, .disconnecting,
  ]
  static let descriptions: [String?] = [
    "Clash for Mac Tunnel", "prior configuration", "administrator-edited", nil,
  ]

  var description: String {
    """
    Scenario(created=\(createdManager), trigger=\(trigger), external=\(externalKind.rawValue), \
    status=\(status), stopReaches=\(stopReaches), applyMutates=\(applyMutates), \
    removeMutates=\(removeMutates), gens[w=\(writtenGen),p=\(priorGen),e=\(externalGen)], \
    enabled[w=\(writtenEnabled),p=\(priorEnabled),e=\(externalEnabled)], \
    ipv6[w=\(writtenIPv6),p=\(priorIPv6),e=\(externalIPv6)], descIndex=\(descIndex))
    """
  }
}

private enum ScenarioGenerator {
  static func generate(using rng: inout SplitMix64) -> Scenario {
    // Three pairwise-distinct generation tags in 1...30.
    var gens = Set<Int>()
    while gens.count < 3 { gens.insert(rng.int(in: 1...30)) }
    let ordered = Array(gens)
    return Scenario(
      createdManager: rng.bool(),
      trigger: rng.pick(Scenario.triggers),
      externalKind: rng.pick(Scenario.ExternalKind.allCases),
      status: rng.pick(Scenario.statuses),
      stopReaches: rng.bool(),
      applyMutates: rng.bool(),
      removeMutates: rng.bool(),
      writtenGen: ordered[0],
      priorGen: ordered[1],
      externalGen: ordered[2],
      writtenEnabled: rng.bool(),
      priorEnabled: rng.bool(),
      externalEnabled: rng.bool(),
      writtenIPv6: rng.bool(),
      priorIPv6: rng.bool(),
      externalIPv6: rng.bool(),
      descIndex: rng.int(in: 0...(Scenario.descriptions.count - 1)))
  }

  /// Simpler candidates used to shrink a failing scenario toward a minimal report.
  static func shrink(_ scenario: Scenario) -> [Scenario] {
    var candidates: [Scenario] = []
    if scenario.createdManager {
      var next = scenario
      next.createdManager = false
      candidates.append(next)
    }
    if scenario.externalKind != .none {
      var next = scenario
      next.externalKind = .none
      candidates.append(next)
    }
    if scenario.status != .disconnected {
      var next = scenario
      next.status = .disconnected
      candidates.append(next)
    }
    for keyPath in [\Scenario.stopReaches, \Scenario.applyMutates, \Scenario.removeMutates] {
      if !scenario[keyPath: keyPath] {
        var next = scenario
        next[keyPath: keyPath] = true
        candidates.append(next)
      }
    }
    return candidates
  }
}

// MARK: - Value builders

private func makeValues(
  gen: Int,
  enabled: Bool,
  ipv6: Bool,
  description: String?
) throws -> ManagedTunnelPreferenceValues {
  let hex = String(format: "%064x", gen)
  let descriptor = try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: ipv6, mtu: 1_500),
    installationID: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
    epoch: 1,
    generation: UInt64(gen),
    byteCount: 2,
    sha256: SHA256Digest(hex: hex),
    identitySHA256: SHA256Digest(hex: hex))
  return ManagedTunnelPreferenceValues(
    descriptor: descriptor, isEnabled: enabled, localizedDescription: description)
}

// MARK: - Expected classification + executable check

private enum Expected { case verifiedOff, conflict, cleanupUnproven }

/// Mirrors the ordered compensation's decision points so the test knows the exact
/// safe outcome each scenario must produce.
private func classify(_ scenario: Scenario) -> Expected {
  let active = scenario.status.mayBeActive
  // Step 2: a possibly-active tunnel that never reaches disconnected times out.
  if active && !scenario.stopReaches { return .cleanupUnproven }
  // Step 3: any external/administrator edit (or removal) is a refused conflict.
  if scenario.externalKind != .none { return .conflict }
  // Step 3/4: the compare matched, so restore/remove runs and must verify.
  let restoreEffective = scenario.createdManager ? scenario.removeMutates : scenario.applyMutates
  return restoreEffective ? .verifiedOff : .cleanupUnproven
}

/// Runs the real compensation against deterministic fakes and returns a failure
/// description, or `nil` when every Property-9 invariant held for this scenario.
private func check(_ scenario: Scenario) async -> String? {
  do {
    let written = try makeValues(
      gen: scenario.writtenGen, enabled: scenario.writtenEnabled, ipv6: scenario.writtenIPv6,
      description: Scenario.descriptions[scenario.descIndex])
    let prior = try makeValues(
      gen: scenario.priorGen, enabled: scenario.priorEnabled, ipv6: scenario.priorIPv6,
      description: "prior")
    let external = try makeValues(
      gen: scenario.externalGen, enabled: scenario.externalEnabled, ipv6: scenario.externalIPv6,
      description: "administrator-edited")

    let storedValue: ManagedTunnelPreferenceValues?
    switch scenario.externalKind {
    case .none: storedValue = written
    case .edited: storedValue = external
    case .removed: storedValue = nil
    }

    let receipt = PreferenceMutationReceipt(
      operationID: UUID(),
      createdManager: scenario.createdManager,
      priorValues: scenario.createdManager ? nil : prior,
      writtenValues: written)

    let store = StoreFake(
      status: scenario.status,
      values: storedValue,
      stopReachesDisconnected: scenario.stopReaches,
      applyMutatesStore: scenario.applyMutates,
      removeMutatesStore: scenario.removeMutates)
    let authority = RecordingAuthorityRevoker()
    let secrets = EraseCounter()

    var thrown: AppleNetworkError?
    do {
      try await TunnelPreferenceCompensation.run(
        receipt: receipt,
        authority: authority,
        preferences: store,
        secretEraser: secrets.eraser,
        stopWait: TunnelPreferenceCompensation.StopWaitPolicy(maximumPolls: 3, sleep: {}))
    } catch let error as AppleNetworkError {
      thrown = error
    } catch {
      return "unexpected non-AppleNetworkError terminal outcome: \(error)"
    }

    // Universal invariants for EVERY terminal path.
    if authority.revokeCount != 1 {
      return "Authority revoke must run exactly once, saw \(authority.revokeCount)"
    }
    if secrets.eraseCount < 1 {
      return "secrets must be erased on every terminal path, saw \(secrets.eraseCount)"
    }

    let counts = "(applies=\(store.applies), removes=\(store.removes))"
    switch classify(scenario) {
    case .verifiedOff:
      if let thrown { return "expected verified Off but threw \(thrown)" }
      if scenario.createdManager {
        if store.currentValues != nil {
          return "created manager must be removed, still present: "
            + String(describing: store.currentValues)
        }
        if store.removes != 1 || store.applies != 0 {
          return "created path must remove once and never apply \(counts)"
        }
      } else {
        if store.currentValues != prior {
          return "restore must reinstate prior values, saw "
            + String(describing: store.currentValues)
        }
        if store.applies != 1 || store.removes != 0 {
          return "restore path must apply once and never remove \(counts)"
        }
      }

    case .conflict:
      guard case .compensationConflict? = thrown else {
        return "expected compensationConflict (Quarantined) but got "
          + String(describing: thrown)
      }
      // The external/administrator state must be preserved, never overwritten.
      if store.currentValues != storedValue {
        return "external change was overwritten: expected "
          + "\(String(describing: storedValue)), saw \(String(describing: store.currentValues))"
      }
      if store.applies != 0 || store.removes != 0 {
        return "conflict must not mutate preferences \(counts)"
      }

    case .cleanupUnproven:
      guard case .cleanupUnproven? = thrown else {
        return "expected cleanupUnproven (Quarantined) but got \(String(describing: thrown))"
      }
      // A stop timeout must occur before any restore/remove is attempted.
      if scenario.status.mayBeActive && !scenario.stopReaches {
        if store.applies != 0 || store.removes != 0 {
          return "stop timeout must precede any restore/remove \(counts)"
        }
      }
    }
    return nil
  } catch {
    return "scenario construction failed: \(error)"
  }
}

// MARK: - Seed

/// Master seed for the property. Defaults to a fixed value so the run is
/// reproducible; override with `CFW_PBT_SEED_PROP9` to replay a printed failure.
private func masterSeed() -> UInt64 {
  if let raw = ProcessInfo.processInfo.environment["CFW_PBT_SEED_PROP9"],
    let value = UInt64(raw)
  {
    return value
  }
  return 0x0C1A_54F0_C0DE_9009
}

// MARK: - Property test

@Suite(.serialized)
struct TunnelPreferenceCompensationPropertyTests {
  private static let caseCount = 256

  @Test func compensationEndsOnlyInVerifiedOffOrQuarantined() async throws {
    let masterSeed = masterSeed()
    var successes = 0
    for index in 0..<Self.caseCount {
      var rng = SplitMix64(seed: masterSeed &+ UInt64(index) &* 0x100_0001)
      let scenario = ScenarioGenerator.generate(using: &rng)

      if let failure = await check(scenario) {
        // Greedy shrink toward a minimal still-failing scenario.
        var minimal = scenario
        var minimalFailure = failure
        var improved = true
        while improved {
          improved = false
          for candidate in ScenarioGenerator.shrink(minimal) {
            if let candidateFailure = await check(candidate) {
              minimal = candidate
              minimalFailure = candidateFailure
              improved = true
              break
            }
          }
        }
        Issue.record(
          """
          Property 9 (Preference compensation preserves external changes) failed.
            reproduce with: CFW_PBT_SEED_PROP9=\(masterSeed)
            master seed: 0x\(String(masterSeed, radix: 16))
            failing case index: \(index)
            reason: \(minimalFailure)
            shrunk counterexample: \(minimal)
            original counterexample: \(scenario)
          """)
        return
      }
      successes += 1
    }
    // Prove the property held across at least 100 successful generated cases.
    #expect(successes == Self.caseCount)
    #expect(successes >= 100)
  }
}

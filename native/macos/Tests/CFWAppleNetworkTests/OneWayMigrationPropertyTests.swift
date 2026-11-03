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

  func randomChoices(using rng: inout PBTSplitMix64) -> RecoveryChoices {
    RecoveryChoices(
      conditionIndex: rng.int(inRange: 0...(conditionCount - 1)),
      runtimeIndex: rng.int(inRange: 0...3),
      remnantIndex: rng.int(inRange: 0...3),
      hasHostLineage: rng.bool(),
      hasDescriptor: rng.bool(),
      failure: FailurePoint.allCases[rng.int(inRange: 0...(FailurePoint.allCases.count - 1))])
  }

  func run(
    _ c: RecoveryChoices, using rng: inout PBTSplitMix64
  ) async throws -> AuthorityMigrationRecoveryRun {
    let installationID = rng.uuid()
    let host: MigrationLineage? =
      c.hasHostLineage
      ? try MigrationLineage(installationID: installationID, epoch: 3, generation: 3) : nil
    let descriptorValue =
      c.hasDescriptor
      ? try pbtDescriptor(installationID: installationID, epoch: 3, generation: 1, tunnel: true)
      : nil

    let reader = AuthorityMigrationInventoryReader(
      runtime: PBTRuntimeInspector(runtimes[c.runtimeIndex]),
      manager: PBTDescriptorInspector(descriptorValue),
      hostLineage: PBTHostLineageInspector(host),
      providerCursor: PBTProviderCursorInspector(nil),
      legacy: PBTLegacyInspector(remnants(index: c.remnantIndex)),
      rootStore: PBTRootStoreInspector(.empty, shouldThrow: c.failure == .inventoryUnavailable))

    let observation = c.failure == .offNotProven ? partiallyOff() : pbtProvenOff()

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
    var rng = PBTSplitMix64(seed: seed)
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
    var rng = PBTSplitMix64(seed: iterationSeed)
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

    var coverageRng = PBTSplitMix64(seed: iterationSeed)
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

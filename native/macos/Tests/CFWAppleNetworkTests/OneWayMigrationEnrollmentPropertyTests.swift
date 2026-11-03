import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAppleNetwork

// Property 12 for enrollment: generated enrollment migrations with injected
// failures never revive a retired path.
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
  func randomChoices(using rng: inout PBTSplitMix64) -> EnrollmentChoices {
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
    _ c: EnrollmentChoices, using rng: inout PBTSplitMix64
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
      descriptorValue = try pbtDescriptor(
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

    let observation = c.failure == .offNotProven ? partiallyOff() : pbtProvenOff()

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
    var rng = PBTSplitMix64(seed: seed)
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
    var rng = PBTSplitMix64(seed: iterationSeed)
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
    var coverageRng = PBTSplitMix64(seed: iterationSeed)
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

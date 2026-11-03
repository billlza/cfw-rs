import CFWSharedProtocol
import Foundation
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

// MARK: - Property 6: Recovery never resets permissively
//
// For all bounded valid, truncated, reordered, rolled-back, unknown-field,
// symlink, and hash-chain-inconsistent journal inputs and all owner
// reattestation outcomes, Authority restart reconstructs the exact committed
// high-water/state or enters Recovering/Quarantined; it never clears replay
// history, invents a ticket/secret, or grants a start from ambiguous state.
//
// This is a deterministic generative test that drives generated journal images
// through the pure `AuthorityJournalRecoveryReducer` (and the `AuthorityJournalCodec`).
// Each generated scenario builds a canonical, hash-chained journal from a valid
// committed-state chain, then applies one corruption class (truncation,
// bit-flip, reordering, durable rollback, trailing/rolled-back head, unknown
// canonical field, broken hash chain, interrupted head replacement, missing or
// unexpected head, or the empty store) before recovery. Symlink following is a
// filesystem concern of `DescriptorRelativeAuthorityJournalStore`, which cannot
// exist for the pure in-memory reducer and is already covered by the
// descriptor-relative store's example tests; the pure reducer only ever sees an
// already-read journal image, so this property exhausts the image-level
// corruption classes instead.
//
// No real filesystem, XPC, launchd, or Network Extension boundary is used:
// every image is synthesized from a reproducible seed. After each generated
// case the harness checks the reducer's decision against an independent oracle
// and the three fail-closed invariants below. On failure the seed and the
// shrunk scenario are printed so the exact case can be replayed.
//
// Fail-closed invariants checked for every generated case:
//   1. `permitsStart` is always false — recovery never grants a start.
//   2. A valid image reconstructs the exact committed high-water state (never a
//      fabricated one, never a permissive reset to empty); an ambiguous or
//      corrupted image quarantines and never becomes a Recovering posture.
//   3. Replay history is preserved: a decodable committed high-water is either
//      reconstructed exactly or the posture is Quarantined (which blocks starts).
//
// **Validates: Requirements 2.6, 2.7, 7.3**

// MARK: - Seed

/// Base seed. Override with `CFW_PBT_SEED_PROP6` to replay a printed failure.
private func baseSeed() -> UInt64 {
  if let raw = ProcessInfo.processInfo.environment["CFW_PBT_SEED_PROP6"],
    let value = UInt64(raw)
  {
    return value
  }
  return 0xC0FF_EE13_A5A5_0006
}

@Test func recoveryNeverResetsPermissivelyAcrossCorruptedJournalImages() {
  let property = FailClosedJournalRecoveryProperty()
  let seed = baseSeed()
  let iterations = 220

  var successfulCases = 0
  var aggregate = FailClosedJournalRecoveryProperty.Outcome()
  var failure: (seed: UInt64, scenario: RecoveryScenario, reason: String)?

  for index in 0..<iterations {
    let iterationSeed = seed &+ UInt64(index)
    var rng = RecoverySplitMix64(seed: iterationSeed)
    let scenario = property.randomScenario(using: &rng, index: index)

    var outcome = FailClosedJournalRecoveryProperty.Outcome()
    if let reason = property.run(scenario, into: &outcome) {
      let shrunk = property.shrink(scenario)
      let shrunkReason = property.evaluate(shrunk) ?? reason
      failure = (iterationSeed, shrunk, shrunkReason)
      break
    }

    aggregate.mutationsCovered.formUnion(outcome.mutationsCovered)
    aggregate.actionsCovered.formUnion(outcome.actionsCovered)
    aggregate.quarantineReasons.formUnion(outcome.quarantineReasons)
    aggregate.preservedHighWaterOnTrailing += outcome.preservedHighWaterOnTrailing
    aggregate.reconstructedExactHighWater += outcome.reconstructedExactHighWater
    successfulCases += 1
  }

  if let failure {
    Issue.record(
      """
      Property 6 counterexample found.
      reproduce with: CFW_PBT_SEED_PROP6=\(failure.seed)
      shrunk scenario: \(failure.scenario)
      violation: \(failure.reason)
      """)
  }

  #expect(failure == nil)
  #expect(
    successfulCases >= 100,
    "expected at least 100 successful generated cases, ran \(successfulCases)")

  // The batch must actually exercise every corruption class this property
  // guards, both recovery actions and quarantine, and the two high-water
  // outcomes (exact reconstruction and preserved-on-quarantine).
  #expect(
    aggregate.mutationsCovered.count == RecoveryMutation.allCases.count,
    "not every corruption class was generated: \(aggregate.mutationsCovered)")
  #expect(
    aggregate.actionsCovered.count >= 3,
    "generated batch never exercised every recovery action: \(aggregate.actionsCovered)")
  #expect(
    aggregate.quarantineReasons.count >= 5,
    "generated batch never exercised a range of quarantine reasons: \(aggregate.quarantineReasons)")
  #expect(
    aggregate.reconstructedExactHighWater > 0,
    "generated batch never reconstructed an exact committed high-water")
  #expect(
    aggregate.preservedHighWaterOnTrailing > 0,
    "generated batch never preserved a high-water while quarantining a rolled-back head")
}

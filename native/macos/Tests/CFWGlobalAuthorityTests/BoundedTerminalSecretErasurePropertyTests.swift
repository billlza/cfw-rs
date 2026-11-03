import CFWSharedProtocol
import Foundation
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

// MARK: - Property 7: Secret lifecycle is bounded and terminally erased
//
// For all generated secret payloads and every success, rejection, cancellation,
// timeout, ticket expiry, XPC interruption, and owner crash path, out-of-bound
// material is rejected before retention and every Authority/transport-owned
// in-bound buffer is erased by its terminal path without appearing in any
// serializable snapshot or journal model.
//
// This is a deterministic generative test that drives generated payloads through
// the pure `TunnelSecretLifecycle` plus the `SensitiveBytes`/`StartTicket`/
// transport primitives it owns. A reproducible SplitMix64 seed selects one
// terminal path (or one out-of-bound rejection class) and the payload shape
// (configuration size, credential slot count, per-slot secret size, and a unique
// secret marker). Each generated case is then checked against these three
// fail-closed invariants:
//
//   1. Out-of-bound rejection before retention — any payload that exceeds an
//      individual-secret, total-secret, credential-slot-count, configuration, or
//      preparation-lifetime bound (or fails an exact configuration/credential
//      digest match) is rejected, no pending material is retained, and every
//      input buffer supplied to the rejected call is already erased.
//   2. Terminal erasure — after the case's terminal path runs (success redeem,
//      cancellation, ticket expiry, XPC interruption, owner crash, recovery, or
//      generic error), every Authority-owned pending buffer and every
//      transport-owned in-bound buffer reports `isErased`, and the lifecycle
//      retains no pending material.
//   3. No serializable secret leak — the secret marker never appears in any
//      serializable Authority snapshot or journal model built from the same
//      operation (`AuthoritySnapshot`, `AuthorityCommittedState`, `ReplayCursor`,
//      `LeaseView`), and the lifecycle/transport/secret primitives are not
//      `Encodable`.
//
// No real filesystem, XPC, launchd, or Network Extension boundary is used: the
// lifecycle is driven with an injected deterministic clock and a fixed
// randomness source, and every buffer is synthesized from the seed. On failure
// the seed and the shrunk scenario are printed so the exact case replays.
//
// **Validates: Requirements 2.8, 6.4**

// MARK: - Seed

/// Base seed. Override with `CFW_PBT_SEED_PROP7` to replay a printed failure.
private func baseSeed() -> UInt64 {
  if let raw = ProcessInfo.processInfo.environment["CFW_PBT_SEED_PROP7"],
    let value = UInt64(raw)
  {
    return value
  }
  return 0xC0FF_EE13_A5A5_0007
}

@Test func secretLifecycleIsBoundedAndTerminallyErasedAcrossEveryPath() {
  let property = BoundedTerminalSecretErasureProperty()
  let seed = baseSeed()
  let iterations = 240

  var successfulCases = 0
  var aggregate = BoundedTerminalSecretErasureProperty.Outcome()
  var failure: (seed: UInt64, scenario: SecretScenario, reason: String)?

  for index in 0..<iterations {
    let iterationSeed = seed &+ UInt64(index)
    var rng = ErasureSplitMix64(seed: iterationSeed)
    let scenario = property.randomScenario(using: &rng)

    var outcome = BoundedTerminalSecretErasureProperty.Outcome()
    if let reason = property.run(scenario, into: &outcome) {
      let shrunk = property.shrink(scenario)
      let shrunkReason = property.evaluate(shrunk) ?? reason
      failure = (iterationSeed, shrunk, shrunkReason)
      break
    }

    aggregate.kindsCovered.formUnion(outcome.kindsCovered)
    aggregate.rejectionsCovered += outcome.rejectionsCovered
    aggregate.terminalErasuresChecked += outcome.terminalErasuresChecked
    aggregate.snapshotsScanned += outcome.snapshotsScanned
    successfulCases += 1
  }

  if let failure {
    Issue.record(
      """
      Property 7 counterexample found.
      reproduce with: CFW_PBT_SEED_PROP7=\(failure.seed)
      shrunk scenario: \(failure.scenario)
      violation: \(failure.reason)
      """)
  }

  #expect(failure == nil)
  #expect(
    successfulCases >= 100,
    "expected at least 100 successful generated cases, ran \(successfulCases)")

  // The batch must exercise every terminal path and every rejection class, and
  // must actually check terminal erasure, rejection-before-retention, and the
  // serializable-model leak scan.
  #expect(
    aggregate.kindsCovered.count == ScenarioKind.allCases.count,
    "not every terminal/rejection kind was generated: \(aggregate.kindsCovered)")
  #expect(
    aggregate.terminalErasuresChecked > 0,
    "generated batch never checked terminal erasure on an accepted payload")
  #expect(
    aggregate.rejectionsCovered > 0,
    "generated batch never rejected an out-of-bound payload before retention")
  #expect(
    aggregate.snapshotsScanned > 0,
    "generated batch never scanned a serializable snapshot/journal model")

  // The sensitive primitives must never be serializable.
  #expect(
    !(TunnelSecretLifecycle(
      randomness: FixedTicketRandomness(
        value: Data(repeating: 0, count: AuthorityV1Limits.ticketBytes)),
      clock: TestMonotonicClock(1)) is any Encodable))
}

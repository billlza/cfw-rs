import CFWSharedProtocol
import Foundation
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

// Shared by the Property 6 tests: the seed source, the fixed identities and
// digests, the generated scenario and its expected classification.
// MARK: - Deterministic seed source

/// Deterministic, seedable value source (SplitMix64). Reproducible across runs
/// and platforms so a printed seed replays the exact generated case.
struct RecoverySplitMix64: RandomNumberGenerator {
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
}

// MARK: - Fixed shared identities / digests

let recoveryInstallation = AuthorityIdentifier(
  UUID(uuidString: "0b000000-0000-0000-0000-0000000000b1")!)
let recoveryOperation = AuthorityIdentifier(
  UUID(uuidString: "0b000000-0000-0000-0000-0000000000b2")!)
let recoveryLease = AuthorityIdentifier(
  UUID(uuidString: "0b000000-0000-0000-0000-0000000000b3")!)
let recoveryConfigDigest = try! SHA256Digest(hex: String(repeating: "a", count: 64))

/// Owner states an authenticated owner might have to reattest after a restart.
/// Cycling the last committed state across these exercises every recovery
/// action (verify-Off, stop-owner, reattest-owner) the reducer can select.
let ownerStateTable: [AuthorityState] = [
  .off, .preparing, .starting, .active, .stopping,
]

// MARK: - Generated scenario

/// One corruption class applied to an otherwise-valid journal image.
enum RecoveryMutation: Int, CaseIterable {
  case none
  case truncate
  case bitFlip
  case reorder
  case rollback
  case trailingHead
  case unknownField
  case brokenChain
  case temporaryHead
  case unexpectedHead
  case missingHead
  case empty
}

/// A fully self-contained, seed-derived scenario. Every field is a small scalar
/// so a counterexample can be shrunk (fewer records, smaller offsets) and
/// re-derived deterministically during replay.
struct RecoveryScenario {
  var recordCount: Int
  var mutation: RecoveryMutation
  var kindSeeds: [Int]
  var lastKindSelector: Int
  var bitFlipOffset: Int
  var trailingHeadK: Int
}

// MARK: - Expected classification

enum RecoveryExpectation {
  /// A valid (or trailing-head prefix) image whose recovery must land in
  /// Recovering with the exact committed high-water state (which may be nil only
  /// for the empty store).
  case recovering(action: AuthorityRecoveryAction, committed: AuthorityCommittedState?)
  /// An ambiguous or corrupted image that must quarantine. `reason` nil means any
  /// quarantine reason is acceptable (e.g. an arbitrary bit-flip). `committed`
  /// records a preserved high-water where the reducer keeps it for diagnostics.
  case quarantined(reason: AuthorityJournalValidationError?, committed: AuthorityCommittedState?)
}

import CFWSharedProtocol
import Foundation
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

// Shared by the secret lifecycle tests: the Property 7 seed source, a test
// clock, fixed ticket randomness, a requested transport failure, and the
// generated scenario.
// MARK: - Deterministic seed source

/// Deterministic, seedable value source (SplitMix64). Reproducible across runs
/// and platforms so a printed seed replays the exact generated case.
struct ErasureSplitMix64: RandomNumberGenerator {
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

// MARK: - Deterministic lifecycle boundaries

final class TestMonotonicClock: AuthorityMonotonicClock, @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64

  init(_ value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { lock.withLock { value } }
  func advance(by amount: UInt64) { lock.withLock { value += amount } }
}

struct FixedTicketRandomness: AuthorityTicketRandomness {
  let value: Data
  func randomBytes(count _: Int) throws -> Data { value }
}

enum RequestedTransportFailure: Error { case requested }

// MARK: - Scenario

/// One in-bound terminal path or one out-of-bound rejection class.
enum ScenarioKind: Int, CaseIterable {
  // In-bound terminal paths (payload is accepted, then terminated).
  case success
  case cancellation
  case ticketExpiry
  case xpcInterruption
  case ownerCrash
  case recovery
  case genericError
  // Out-of-bound rejection classes (payload must be rejected before retention).
  case oversizeIndividualSecret
  case tooManyCredentialSlots
  case oversizeTotalSecret
  case oversizeConfiguration
  case lifetimeTooLong
  case configurationDigestMismatch
  case credentialReferenceMismatch

  var isRejection: Bool {
    switch self {
    case .oversizeIndividualSecret, .tooManyCredentialSlots, .oversizeTotalSecret,
      .oversizeConfiguration, .lifetimeTooLong, .configurationDigestMismatch,
      .credentialReferenceMismatch:
      return true
    default:
      return false
    }
  }
}

/// A fully seed-derived scenario. Every field is a small scalar so a
/// counterexample can be shrunk and re-derived deterministically during replay.
struct SecretScenario {
  var kind: ScenarioKind
  var slotCount: Int
  var secretSize: Int
  var configExtra: Int
  var markerHi: UInt64
  var markerLo: UInt64
}

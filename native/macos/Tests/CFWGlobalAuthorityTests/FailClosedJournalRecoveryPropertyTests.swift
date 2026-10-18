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
}

// MARK: - Fixed shared identities / digests

private let recoveryInstallation = AuthorityIdentifier(
  UUID(uuidString: "0b000000-0000-0000-0000-0000000000b1")!)
private let recoveryOperation = AuthorityIdentifier(
  UUID(uuidString: "0b000000-0000-0000-0000-0000000000b2")!)
private let recoveryLease = AuthorityIdentifier(
  UUID(uuidString: "0b000000-0000-0000-0000-0000000000b3")!)
private let recoveryConfigDigest = try! SHA256Digest(hex: String(repeating: "a", count: 64))

/// Owner states an authenticated owner might have to reattest after a restart.
/// Cycling the last committed state across these exercises every recovery
/// action (verify-Off, stop-owner, reattest-owner) the reducer can select.
private let ownerStateTable: [AuthorityState] = [
  .off, .preparing, .starting, .active, .stopping,
]

// MARK: - Generated scenario

/// One corruption class applied to an otherwise-valid journal image.
private enum RecoveryMutation: Int, CaseIterable {
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
private struct RecoveryScenario {
  var recordCount: Int
  var mutation: RecoveryMutation
  var kindSeeds: [Int]
  var lastKindSelector: Int
  var bitFlipOffset: Int
  var trailingHeadK: Int
}

// MARK: - Expected classification

private enum RecoveryExpectation {
  /// A valid (or trailing-head prefix) image whose recovery must land in
  /// Recovering with the exact committed high-water state (which may be nil only
  /// for the empty store).
  case recovering(action: AuthorityRecoveryAction, committed: AuthorityCommittedState?)
  /// An ambiguous or corrupted image that must quarantine. `reason` nil means any
  /// quarantine reason is acceptable (e.g. an arbitrary bit-flip). `committed`
  /// records a preserved high-water where the reducer keeps it for diagnostics.
  case quarantined(reason: AuthorityJournalValidationError?, committed: AuthorityCommittedState?)
}

// MARK: - Property harness

private struct FailClosedJournalRecoveryProperty {
  struct Outcome {
    var violation: String?
    var mutationsCovered: Set<Int> = []
    var actionsCovered: Set<String> = []
    var quarantineReasons: Set<String> = []
    var preservedHighWaterOnTrailing = 0
    var reconstructedExactHighWater = 0
  }

  // MARK: Scenario generation

  func randomScenario(using rng: inout SplitMix64, index: Int) -> RecoveryScenario {
    let mutation = RecoveryMutation.allCases[
      rng.int(inRange: 0...(RecoveryMutation.allCases.count - 1))]
    let kindSeeds = (0..<6).map { _ in rng.int(inRange: 0...(ownerStateTable.count - 1)) }
    return normalized(
      RecoveryScenario(
        recordCount: rng.int(inRange: 0...6),
        mutation: mutation,
        kindSeeds: kindSeeds,
        // Cycle the last committed owner state so every reattestation outcome
        // (and therefore every recovery action) is exercised across the batch.
        lastKindSelector: index % ownerStateTable.count,
        bitFlipOffset: rng.int(inRange: 0...4_095),
        trailingHeadK: rng.int(inRange: 1...5)))
  }

  /// Clamps `recordCount` to each mutation's structural minimum so `build` is
  /// total for any generated or shrunk scenario.
  func normalized(_ scenario: RecoveryScenario) -> RecoveryScenario {
    var scenario = scenario
    switch scenario.mutation {
    case .reorder, .brokenChain, .trailingHead:
      scenario.recordCount = min(max(2, scenario.recordCount), 6)
    case .empty:
      scenario.recordCount = 0
    case .unknownField:
      scenario.recordCount = 1
    default:
      scenario.recordCount = min(max(1, scenario.recordCount), 6)
    }
    return scenario
  }

  // MARK: State chain construction

  private func stateKind(_ selector: Int) -> AuthorityState {
    ownerStateTable[
      ((selector % ownerStateTable.count) + ownerStateTable.count) % ownerStateTable.count]
  }

  private func transition(for state: AuthorityState) -> AuthorityJournalTransition {
    switch state {
    case .off: return .globalOff
    case .preparing: return .prepare
    case .starting: return .bindOwner
    case .active: return .ready
    case .stopping: return .beginStop
    default: return .globalOff
    }
  }

  private func action(for state: AuthorityState) -> AuthorityRecoveryAction {
    switch state {
    case .active: return .reattestOwner
    case .preparing, .starting, .stopping: return .stopOwner
    default: return .verifyOff
    }
  }

  private func committedState(index: Int, kind: AuthorityState) throws -> AuthorityCommittedState {
    let hasOwner = kind != .off
    return try AuthorityCommittedState(
      installationID: recoveryInstallation,
      epoch: 4,
      generation: UInt64(index + 1),
      revision: UInt64(index + 1),
      transition: transition(for: kind),
      state: kind,
      operationID: hasOwner ? recoveryOperation : nil,
      mode: hasOwner ? .tunnel : nil,
      configSHA256: hasOwner ? recoveryConfigDigest : nil,
      leaseID: hasOwner ? recoveryLease : nil,
      ownerUID: hasOwner ? 501 : nil)
  }

  private func states(for scenario: RecoveryScenario) throws -> [AuthorityCommittedState] {
    guard scenario.recordCount > 0 else { return [] }
    var result: [AuthorityCommittedState] = []
    for index in 0..<scenario.recordCount {
      let isLast = index == scenario.recordCount - 1
      let selector = isLast ? scenario.lastKindSelector : scenario.kindSeeds[index]
      result.append(try committedState(index: index, kind: stateKind(selector)))
    }
    return result
  }

  /// Encodes a valid, hash-chained journal and captures per-record framing so
  /// individual mutations can be applied precisely.
  private struct EncodedChain {
    var frames: [Data]
    var frameDigests: [SHA256Digest]
    var cumulativeLengths: [Int]
    var journal: Data
    var head: AuthorityJournalHead
  }

  private func encodeChain(_ states: [AuthorityCommittedState]) throws -> EncodedChain {
    var journal = Data()
    var previous = AuthorityJournalCodec.zeroDigest
    var frames: [Data] = []
    var digests: [SHA256Digest] = []
    var lengths: [Int] = []
    var head: AuthorityJournalHead?
    for (index, state) in states.enumerated() {
      let record = try AuthorityJournalCodec.encodeRecord(
        state: state, sequence: UInt64(index + 1), previousSHA256: previous)
      frames.append(record.frame)
      digests.append(record.digest)
      journal.append(record.frame)
      lengths.append(journal.count)
      previous = record.digest
      head = try AuthorityJournalHead(
        sequence: UInt64(index + 1), committedLength: UInt64(journal.count),
        recordSHA256: record.digest)
    }
    guard let head else { throw RecoveryFixtureError.emptyChain }
    return EncodedChain(
      frames: frames, frameDigests: digests, cumulativeLengths: lengths,
      journal: journal, head: head)
  }

  private enum RecoveryFixtureError: Error { case emptyChain }

  // MARK: Case building

  private func build(
    _ scenario: RecoveryScenario
  ) throws -> (
    image: AuthorityJournalImage, minimumHead: AuthorityJournalHead?,
    expectation: RecoveryExpectation
  ) {
    let scenario = normalized(scenario)
    let states = try states(for: scenario)

    switch scenario.mutation {
    case .empty:
      return (
        AuthorityJournalImage(journal: nil, head: nil), nil,
        .recovering(action: .verifyOff, committed: nil)
      )

    case .unknownField:
      let (image, expectation) = try buildUnknownField(states)
      return (image, nil, expectation)

    case .brokenChain:
      let (image, expectation) = try buildBrokenChain(states)
      return (image, nil, expectation)

    default:
      break
    }

    let chain = try encodeChain(states)
    let last = try #require(states.last)
    let headData = try AuthorityJournalCodec.encodeHead(chain.head)

    switch scenario.mutation {
    case .none:
      return (
        AuthorityJournalImage(journal: chain.journal, head: headData), nil,
        .recovering(action: action(for: last.state), committed: last)
      )

    case .truncate:
      return (
        AuthorityJournalImage(journal: chain.journal.dropLast(), head: headData), nil,
        .quarantined(reason: .truncated, committed: nil)
      )

    case .bitFlip:
      var journal = chain.journal
      let offset = scenario.bitFlipOffset % journal.count
      let target = journal.index(journal.startIndex, offsetBy: offset)
      journal[target] ^= 0xff
      return (
        AuthorityJournalImage(journal: journal, head: headData), nil,
        .quarantined(reason: nil, committed: nil)
      )

    case .reorder:
      let firstEnd = chain.cumulativeLengths[0]
      let reordered =
        chain.journal.subdata(in: firstEnd..<chain.journal.count)
        + chain.journal.subdata(in: 0..<firstEnd)
      return (
        AuthorityJournalImage(journal: reordered, head: headData), nil,
        .quarantined(reason: nil, committed: nil)
      )

    case .rollback:
      // A durable head that is strictly ahead of the presented journal means the
      // store rolled back relative to the recorded high-water; recovery must
      // quarantine rather than accept the stale tail.
      let extendedKind = stateKind(scenario.kindSeeds[0])
      let extra = try committedState(index: states.count, kind: extendedKind)
      let extendedChain = try encodeChain(states + [extra])
      return (
        AuthorityJournalImage(journal: chain.journal, head: headData), extendedChain.head,
        .quarantined(reason: .rollback, committed: nil)
      )

    case .trailingHead:
      let k = min(max(1, scenario.trailingHeadK), states.count - 1)
      let prefixHead = try AuthorityJournalHead(
        sequence: UInt64(k), committedLength: UInt64(chain.cumulativeLengths[k - 1]),
        recordSHA256: chain.frameDigests[k - 1])
      return (
        AuthorityJournalImage(
          journal: chain.journal, head: try AuthorityJournalCodec.encodeHead(prefixHead)),
        nil,
        .quarantined(reason: .trailingData, committed: states[k - 1])
      )

    case .temporaryHead:
      return (
        AuthorityJournalImage(journal: chain.journal, head: headData, hasTemporaryHead: true), nil,
        .quarantined(reason: .interruptedHeadReplacement, committed: nil)
      )

    case .unexpectedHead:
      return (
        AuthorityJournalImage(journal: nil, head: headData), nil,
        .quarantined(reason: .unexpectedHead, committed: nil)
      )

    case .missingHead:
      return (
        AuthorityJournalImage(journal: chain.journal, head: nil), nil,
        .quarantined(reason: .missingHead, committed: nil)
      )

    case .empty, .unknownField, .brokenChain:
      // Handled above; unreachable.
      throw RecoveryFixtureError.emptyChain
    }
  }

  /// Frames a single record whose canonical payload carries an unknown field, so
  /// the canonical round-trip check must reject it before any state is trusted.
  private func buildUnknownField(
    _ states: [AuthorityCommittedState]
  ) throws -> (AuthorityJournalImage, RecoveryExpectation) {
    let state = try #require(states.first)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let canonical = try encoder.encode(state)
    var object = try #require(
      JSONSerialization.jsonObject(with: canonical) as? [String: Any])
    object["future_field"] = 1
    let payload = try JSONSerialization.data(
      withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    let framed = try frameRecord(
      payload: payload, sequence: 1, previous: AuthorityJournalCodec.zeroDigest)
    let head = try AuthorityJournalHead(
      sequence: 1, committedLength: UInt64(framed.frame.count), recordSHA256: framed.digest)
    return (
      AuthorityJournalImage(
        journal: framed.frame, head: try AuthorityJournalCodec.encodeHead(head)),
      .quarantined(reason: .noncanonicalRecord, committed: nil)
    )
  }

  /// Builds a two-record journal whose second record links to the wrong previous
  /// digest, so the hash chain is inconsistent even though every frame is
  /// individually well-formed.
  private func buildBrokenChain(
    _ states: [AuthorityCommittedState]
  ) throws -> (AuthorityJournalImage, RecoveryExpectation) {
    let first = try AuthorityJournalCodec.encodeRecord(
      state: states[0], sequence: 1, previousSHA256: AuthorityJournalCodec.zeroDigest)
    // Deliberately wrong: record 2 should chain off `first.digest`, not zero.
    let second = try AuthorityJournalCodec.encodeRecord(
      state: states[1], sequence: 2, previousSHA256: AuthorityJournalCodec.zeroDigest)
    var journal = first.frame
    journal.append(second.frame)
    let head = try AuthorityJournalHead(
      sequence: 2, committedLength: UInt64(journal.count), recordSHA256: second.digest)
    return (
      AuthorityJournalImage(journal: journal, head: try AuthorityJournalCodec.encodeHead(head)),
      .quarantined(reason: .brokenHashChain, committed: nil)
    )
  }

  // MARK: Evaluation

  /// Runs one scenario and checks it against the oracle plus the fail-closed
  /// invariants. Returns a violation description (or nil) and updates coverage.
  func run(_ scenario: RecoveryScenario, into outcome: inout Outcome) -> String? {
    let normalized = normalized(scenario)
    let built:
      (
        image: AuthorityJournalImage, minimumHead: AuthorityJournalHead?,
        expectation: RecoveryExpectation
      )
    do {
      built = try build(normalized)
    } catch {
      return "scenario build threw: \(error)"
    }

    let recovery = AuthorityJournalRecoveryReducer.recover(
      built.image, minimumHead: built.minimumHead)

    // Invariant 1: recovery never grants a start, for any input whatsoever.
    if recovery.permitsStart {
      return "recovery permitted a start from mutation \(normalized.mutation)"
    }

    outcome.mutationsCovered.insert(normalized.mutation.rawValue)

    switch built.expectation {
    case .recovering(let expectedAction, let expectedCommitted):
      guard case .recovering(let actualAction) = recovery.posture else {
        return
          "mutation \(normalized.mutation): expected Recovering but got \(recovery.posture)"
      }
      if actualAction != expectedAction {
        return
          "mutation \(normalized.mutation): expected action \(expectedAction) but got \(actualAction)"
      }
      if recovery.committedState != expectedCommitted {
        return
          "mutation \(normalized.mutation): committed high-water was not reconstructed exactly"
      }
      // Invariant 2/3: a valid non-empty journal must reconstruct its exact
      // committed high-water (never a permissive reset to nil, never fabricated).
      if let expectedCommitted {
        if recovery.committedState == nil {
          return "mutation \(normalized.mutation): replay history was cleared permissively"
        }
        if recovery.head == nil {
          return "mutation \(normalized.mutation): committed high-water lost its durable head"
        }
        _ = expectedCommitted
        outcome.reconstructedExactHighWater += 1
      }
      outcome.actionsCovered.insert(String(describing: actualAction))

    case .quarantined(let expectedReason, let expectedCommitted):
      guard case .quarantined(let actualReason) = recovery.posture else {
        return
          "mutation \(normalized.mutation): expected Quarantined but got \(recovery.posture)"
      }
      if let expectedReason, actualReason != expectedReason {
        return
          "mutation \(normalized.mutation): expected quarantine reason \(expectedReason) "
          + "but got \(actualReason)"
      }
      if recovery.committedState != expectedCommitted {
        return
          "mutation \(normalized.mutation): quarantine committed high-water mismatch"
      }
      if expectedCommitted != nil { outcome.preservedHighWaterOnTrailing += 1 }
      outcome.quarantineReasons.insert(String(describing: actualReason))
    }

    return nil
  }

  func evaluate(_ scenario: RecoveryScenario) -> String? {
    var scratch = Outcome()
    return run(scenario, into: &scratch)
  }

  // MARK: Shrinking

  /// Greedily reduces record count and offsets while the violation persists,
  /// terminating at a local minimum that still reproduces it.
  func shrink(_ scenario: RecoveryScenario) -> RecoveryScenario {
    var current = normalized(scenario)
    var improved = true
    while improved {
      improved = false
      for candidate in candidates(from: current) where evaluate(candidate) != nil {
        current = normalized(candidate)
        improved = true
        break
      }
    }
    return current
  }

  private func candidates(from scenario: RecoveryScenario) -> [RecoveryScenario] {
    var result: [RecoveryScenario] = []
    if scenario.recordCount > 1 {
      var smaller = scenario
      smaller.recordCount -= 1
      result.append(smaller)
    }
    if scenario.bitFlipOffset > 0 {
      var fewer = scenario
      fewer.bitFlipOffset = 0
      result.append(fewer)
    }
    if scenario.trailingHeadK > 1 {
      var earlier = scenario
      earlier.trailingHeadK -= 1
      result.append(earlier)
    }
    return result
  }

  // MARK: Frame helper (unknown-field construction)

  private func frameRecord(
    payload: Data, sequence: UInt64, previous: SHA256Digest
  ) throws -> (frame: Data, digest: SHA256Digest) {
    var prefix = Data("CFWAJR02".utf8)
    prefix.appendBigEndianInteger(UInt32(payload.count))
    prefix.appendBigEndianInteger(sequence)
    prefix.append(try digestBytes(previous))
    prefix.append(Data(SHA256.hash(data: payload)))
    var frame = prefix
    frame.appendBigEndianInteger(crc32(prefix + payload))
    frame.append(payload)
    let digest = try SHA256Digest(hex: Data(SHA256.hash(data: frame)).hexString)
    return (frame, digest)
  }

  private func digestBytes(_ digest: SHA256Digest) throws -> Data {
    guard let data = Data(hexString: digest.hex), data.count == 32 else {
      throw RecoveryFixtureError.emptyChain
    }
    return data
  }

  private func crc32(_ data: Data) -> UInt32 {
    var crc: UInt32 = 0xffff_ffff
    for byte in data {
      crc ^= UInt32(byte)
      for _ in 0..<8 {
        let mask = UInt32(bitPattern: -Int32(crc & 1))
        crc = (crc >> 1) ^ (0xedb8_8320 & mask)
      }
    }
    return ~crc
  }
}

// MARK: - Data hex / big-endian helpers

extension Data {
  fileprivate mutating func appendBigEndianInteger<T: FixedWidthInteger>(_ value: T) {
    var bigEndian = value.bigEndian
    Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
  }

  fileprivate var hexString: String { map { String(format: "%02x", $0) }.joined() }

  fileprivate init?(hexString: String) {
    guard hexString.count.isMultiple(of: 2) else { return nil }
    var bytes: [UInt8] = []
    var index = hexString.startIndex
    while index < hexString.endIndex {
      let next = hexString.index(index, offsetBy: 2)
      guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    self.init(bytes)
  }
}

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
    var rng = SplitMix64(seed: iterationSeed)
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

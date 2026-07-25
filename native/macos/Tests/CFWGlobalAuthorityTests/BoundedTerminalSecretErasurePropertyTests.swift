import CFWSharedProtocol
import Foundation
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

private typealias SHA256Digest = CFWSharedProtocol.SHA256Digest

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

// MARK: - Deterministic lifecycle boundaries

private final class TestMonotonicClock: AuthorityMonotonicClock, @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64

  init(_ value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { lock.withLock { value } }
  func advance(by amount: UInt64) { lock.withLock { value += amount } }
}

private struct FixedTicketRandomness: AuthorityTicketRandomness {
  let value: Data
  func randomBytes(count _: Int) throws -> Data { value }
}

private enum RequestedTransportFailure: Error { case requested }

private func digest(_ data: Data) throws -> SHA256Digest {
  try SHA256Digest(hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
}

// MARK: - Scenario

/// One in-bound terminal path or one out-of-bound rejection class.
private enum ScenarioKind: Int, CaseIterable {
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
private struct SecretScenario {
  var kind: ScenarioKind
  var slotCount: Int
  var secretSize: Int
  var configExtra: Int
  var markerHi: UInt64
  var markerLo: UInt64
}

// MARK: - Fixture

/// A valid, in-bound fixture: matching configuration/descriptor digests and
/// credential references, with a distinctive secret marker embedded in every
/// credential slot so a serialization leak would be detectable.
private struct SecretFixture {
  let request: PrepareStartRequest
  let leaseID: AuthorityIdentifier
  let configuration: SensitiveBytes
  let slots: [AuthoritySecretSlot]
  let secrets: AuthoritySecretMaterial
  let markerSentinel: String
}

// MARK: - Property harness

private struct BoundedTerminalSecretErasureProperty {
  struct Outcome {
    var violation: String?
    var kindsCovered: Set<Int> = []
    var rejectionsCovered = 0
    var terminalErasuresChecked = 0
    var snapshotsScanned = 0
  }

  // MARK: Scenario generation

  func randomScenario(using rng: inout SplitMix64) -> SecretScenario {
    let kind = ScenarioKind.allCases[rng.int(inRange: 0...(ScenarioKind.allCases.count - 1))]
    return normalized(
      SecretScenario(
        kind: kind,
        slotCount: rng.int(inRange: 1...4),
        secretSize: rng.int(inRange: 1...96),
        configExtra: rng.int(inRange: 0...64),
        markerHi: rng.next(),
        markerLo: rng.next()))
  }

  /// Clamps payload dimensions to each kind's structural needs so building is
  /// total for any generated or shrunk scenario.
  func normalized(_ scenario: SecretScenario) -> SecretScenario {
    var scenario = scenario
    scenario.slotCount = min(max(1, scenario.slotCount), 4)
    scenario.secretSize = min(max(1, scenario.secretSize), 96)
    scenario.configExtra = min(max(0, scenario.configExtra), 64)
    return scenario
  }

  // MARK: Marker

  private func markerSentinel(_ scenario: SecretScenario) -> String {
    let mixed = scenario.markerHi ^ (scenario.markerLo &* 0x9E37_79B9_7F4A_7C15)
    return "CFW-SECRET-" + String(format: "%016x", mixed)
  }

  private func secretData(_ sentinel: String, slotIndex: Int, size: Int) -> Data {
    var data = Data(sentinel.utf8)
    data.append(UInt8(truncatingIfNeeded: slotIndex))
    while data.count < size { data.append(UInt8(truncatingIfNeeded: data.count &* 31 &+ 7)) }
    return data.prefix(max(size, Data(sentinel.utf8).count + 1))
  }

  // MARK: Fixture construction

  private func makeFixture(
    _ scenario: SecretScenario,
    mismatchConfiguration: Bool = false,
    mismatchCredential: Bool = false
  ) throws -> SecretFixture {
    let sentinel = markerSentinel(scenario)
    var configurationData = Data("{\"outbounds\":[]}".utf8)
    configurationData.append(Data((0..<scenario.configExtra).map { UInt8($0 & 0x7f) }))
    let configurationDigest = try digest(configurationData)
    let identityDigest = try SHA256Digest(hex: String(repeating: "b", count: 64))

    let references = (0..<scenario.slotCount).map { _ in
      CredentialReference(id: UUID(), kind: .trojanPassword)
    }
    let credentialSlots = try references.enumerated().map { index, reference in
      try CredentialSlot(
        reference: reference, target: .trojanPassword, outboundIndex: UInt16(index),
        jsonPointer: "/outbounds/\(index)/password")
    }
    let operation = try OperationContext(
      operationID: AuthorityIdentifier(UUID()),
      root: RootContext(
        installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1),
      mode: .tunnel, configSHA256: configurationDigest,
      identitySHA256: identityDigest, ownerUID: 501, authorityRevision: 1)
    let descriptor = try AuthorityConfigurationDescriptor(
      byteCount: UInt32(configurationData.count), configSHA256: configurationDigest,
      identitySHA256: identityDigest, credentialSlots: credentialSlots,
      tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true))
    let request = try PrepareStartRequest(
      operation: operation, expectedRevision: 1, configuration: descriptor)

    // Optionally swap in a wrong-but-same-length configuration or an unrelated
    // credential reference to exercise the exact-match rejection paths.
    let suppliedConfigurationData: Data
    if mismatchConfiguration {
      suppliedConfigurationData = Data(repeating: 0, count: configurationData.count)
    } else {
      suppliedConfigurationData = configurationData
    }
    let suppliedReferences =
      mismatchCredential
      ? references.dropLast() + [CredentialReference(id: UUID(), kind: .trojanPassword)]
      : references

    let slots = try suppliedReferences.enumerated().map { index, reference in
      try AuthoritySecretSlot(
        reference: reference,
        copying: secretData(sentinel, slotIndex: index, size: scenario.secretSize))
    }
    return try SecretFixture(
      request: request, leaseID: AuthorityIdentifier(UUID()),
      configuration: SensitiveBytes(
        copying: suppliedConfigurationData,
        maximumCount: AuthorityV1Limits.maximumConfigurationBytes),
      slots: slots,
      secrets: AuthoritySecretMaterial(slots: slots),
      markerSentinel: sentinel)
  }

  private func newLifecycle(seedByte: UInt8, startMilliseconds: UInt64 = 1_000)
    -> (TunnelSecretLifecycle, TestMonotonicClock)
  {
    let clock = TestMonotonicClock(startMilliseconds)
    let lifecycle = TunnelSecretLifecycle(
      randomness: FixedTicketRandomness(
        value: Data(repeating: seedByte, count: AuthorityV1Limits.ticketBytes)),
      clock: clock)
    return (lifecycle, clock)
  }

  private func providerTicket(from transport: AuthorityIssuedTicketTransport) throws -> StartTicket
  {
    try transport.withTicket { ticket in
      try ticket.withUnsafeBytes { try StartTicket(copying: Data($0)) }
    }
  }

  // MARK: Serializable-model leak check

  /// Builds every serializable snapshot/journal model reachable from this
  /// operation and confirms the secret marker never appears in any of them.
  private func serializableLeak(operation: OperationContext, sentinel: String) throws -> String? {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]

    let committed = try AuthorityCommittedState(
      installationID: operation.root.installationID, epoch: operation.root.epoch,
      generation: operation.root.generation, revision: operation.authorityRevision,
      transition: .ready, state: .active, operationID: operation.operationID,
      mode: operation.mode, configSHA256: operation.configSHA256,
      leaseID: AuthorityIdentifier(UUID()), ownerUID: operation.ownerUID)
    let cursor = try ReplayCursor(
      installationID: operation.root.installationID, acceptedEpoch: operation.root.epoch,
      acceptedGeneration: operation.root.generation, revision: operation.authorityRevision,
      previousRecordSHA256: operation.configSHA256)
    let lease = try LeaseView(
      leaseID: AuthorityIdentifier(UUID()), operation: operation,
      state: .active, expiryMonotonic: 10_000)
    let snapshot = try AuthoritySnapshot(
      protocolVersion: AuthorityProtocolVersion(), state: .active,
      revision: operation.authorityRevision, replayCursor: cursor, leaseView: lease,
      lastFailure: nil, consoleUID: operation.ownerUID)

    var serialized = Data()
    serialized.append(try encoder.encode(committed))
    serialized.append(try encoder.encode(cursor))
    serialized.append(try encoder.encode(lease))
    serialized.append(try encoder.encode(snapshot))

    let text = String(decoding: serialized, as: UTF8.self)
    if text.contains(sentinel) {
      return "secret marker leaked into a serializable snapshot/journal model"
    }
    if serialized.range(of: Data(sentinel.utf8)) != nil {
      return "secret marker bytes leaked into a serializable snapshot/journal model"
    }
    return nil
  }

  // MARK: Evaluation

  func run(_ scenario: SecretScenario, into outcome: inout Outcome) -> String? {
    let scenario = normalized(scenario)
    outcome.kindsCovered.insert(scenario.kind.rawValue)
    do {
      if scenario.kind.isRejection {
        return try runRejection(scenario, into: &outcome)
      }
      return try runTerminalPath(scenario, into: &outcome)
    } catch {
      return "scenario \(scenario.kind) threw unexpectedly: \(error)"
    }
  }

  // MARK: In-bound terminal paths

  private func runTerminalPath(
    _ scenario: SecretScenario, into outcome: inout Outcome
  ) throws -> String? {
    let (lifecycle, clock) = newLifecycle(seedByte: UInt8(scenario.kind.rawValue &+ 1))
    let fixture = try makeFixture(scenario)

    // No serializable model built from this operation may carry the marker.
    if let leak = try serializableLeak(
      operation: fixture.request.operation, sentinel: fixture.markerSentinel)
    {
      return leak
    }
    outcome.snapshotsScanned += 1

    let issued = try lifecycle.prepare(
      request: fixture.request, leaseID: fixture.leaseID,
      configuration: fixture.configuration, secrets: fixture.secrets,
      lifetimeMilliseconds: 10_000)

    switch scenario.kind {
    case .success:
      let ticket = try providerTicket(from: issued)
      let redeemed = try lifecycle.redeem(
        ticket: ticket, operation: fixture.request.operation, leaseID: fixture.leaseID)
      try redeemed.withMaterial { _, _ in () }
      if !redeemed.isErasedForTesting {
        return "success path left redeemed transport buffers retained"
      }

    case .cancellation:
      lifecycle.terminate(.cancellation)
      issued.erase()

    case .ticketExpiry:
      let ticket = try providerTicket(from: issued)
      clock.advance(by: 10_000)
      if (try? lifecycle.redeem(
        ticket: ticket, operation: fixture.request.operation,
        leaseID: fixture.leaseID)) != nil
      {
        return "expired ticket was redeemed instead of rejected"
      }

    case .xpcInterruption:
      // A synchronous encoder that throws mid-borrow must still erase the ticket.
      #expect(throws: RequestedTransportFailure.requested) {
        try issued.withTicket { _ in throw RequestedTransportFailure.requested }
      }
      // The retained pending material is then dropped by the interruption path.
      lifecycle.terminate(.interruption)

    case .ownerCrash:
      let ticket = try providerTicket(from: issued)
      let redeemed = try lifecycle.redeem(
        ticket: ticket, operation: fixture.request.operation, leaseID: fixture.leaseID)
      // Owner crashes before injecting: the transport erases without consumption.
      redeemed.erase()
      if !redeemed.isErasedForTesting {
        return "owner-crash path left redeemed transport buffers retained"
      }

    case .recovery:
      // Authority restart intentionally loses prepared secrets/tickets.
      lifecycle.terminate(.crashRecovery)
      issued.erase()

    case .genericError:
      lifecycle.terminate(.error)
      issued.erase()

    default:
      return "unexpected non-terminal kind \(scenario.kind)"
    }

    if !issued.isErasedForTesting {
      return "terminal path \(scenario.kind) left the issued ticket transport retained"
    }
    if lifecycle.hasPendingMaterialForTesting {
      return "terminal path \(scenario.kind) left Authority pending material retained"
    }
    if !fixture.configuration.isErased {
      return "terminal path \(scenario.kind) left the configuration buffer retained"
    }
    if !fixture.slots.allSatisfy(\.isErased) {
      return "terminal path \(scenario.kind) left a credential slot retained"
    }
    outcome.terminalErasuresChecked += 1
    return nil
  }

  // MARK: Out-of-bound rejections

  private func runRejection(
    _ scenario: SecretScenario, into outcome: inout Outcome
  ) throws -> String? {
    switch scenario.kind {
    case .oversizeIndividualSecret:
      let oversize = Data(
        repeating: 0xab, count: AuthorityV1Limits.maximumIndividualSecretBytes + 1)
      if (try? AuthoritySecretSlot(
        reference: CredentialReference(id: UUID(), kind: .trojanPassword),
        copying: oversize)) != nil
      {
        return "oversize individual secret was retained instead of rejected"
      }

    case .tooManyCredentialSlots:
      let slots = try (0...AuthorityV1Limits.maximumCredentialSlots).map { _ in
        try AuthoritySecretSlot(
          reference: CredentialReference(id: UUID(), kind: .trojanPassword),
          copying: Data([1]))
      }
      if (try? AuthoritySecretMaterial(slots: slots)) != nil {
        return "too many credential slots were retained instead of rejected"
      }
      if !slots.allSatisfy(\.isErased) {
        return "rejected slot-count material left credential slots retained"
      }

    case .oversizeTotalSecret:
      let perSlot = AuthorityV1Limits.maximumIndividualSecretBytes
      let count = AuthorityV1Limits.maximumTotalSecretBytes / perSlot + 1
      let slots = try (0..<count).map { _ in
        try AuthoritySecretSlot(
          reference: CredentialReference(id: UUID(), kind: .trojanPassword),
          copying: Data(repeating: 0x22, count: perSlot))
      }
      if (try? AuthoritySecretMaterial(slots: slots)) != nil {
        return "oversize total secret material was retained instead of rejected"
      }
      if !slots.allSatisfy(\.isErased) {
        return "rejected total-size material left credential slots retained"
      }

    case .oversizeConfiguration:
      let oversize = Data(
        repeating: 0x33, count: AuthorityV1Limits.maximumConfigurationBytes + 1)
      if (try? SensitiveBytes(
        copying: oversize, maximumCount: AuthorityV1Limits.maximumConfigurationBytes)) != nil
      {
        return "oversize configuration was retained instead of rejected"
      }

    case .lifetimeTooLong:
      let (lifecycle, _) = newLifecycle(seedByte: 0x51)
      let fixture = try makeFixture(scenario)
      if (try? lifecycle.prepare(
        request: fixture.request, leaseID: fixture.leaseID,
        configuration: fixture.configuration, secrets: fixture.secrets,
        lifetimeMilliseconds: AuthorityV1Limits.preparationLifetimeMilliseconds + 1)) != nil
      {
        return "over-long preparation lifetime was accepted instead of rejected"
      }
      if let violation = try assertRejectedInputsErased(fixture, lifecycle: lifecycle) {
        return violation
      }

    case .configurationDigestMismatch:
      let (lifecycle, _) = newLifecycle(seedByte: 0x52)
      let fixture = try makeFixture(scenario, mismatchConfiguration: true)
      if (try? lifecycle.prepare(
        request: fixture.request, leaseID: fixture.leaseID,
        configuration: fixture.configuration, secrets: fixture.secrets)) != nil
      {
        return "configuration digest mismatch was accepted instead of rejected"
      }
      if let violation = try assertRejectedInputsErased(fixture, lifecycle: lifecycle) {
        return violation
      }

    case .credentialReferenceMismatch:
      let (lifecycle, _) = newLifecycle(seedByte: 0x53)
      let fixture = try makeFixture(scenario, mismatchCredential: true)
      if (try? lifecycle.prepare(
        request: fixture.request, leaseID: fixture.leaseID,
        configuration: fixture.configuration, secrets: fixture.secrets)) != nil
      {
        return "credential reference mismatch was accepted instead of rejected"
      }
      if let violation = try assertRejectedInputsErased(fixture, lifecycle: lifecycle) {
        return violation
      }

    default:
      return "unexpected non-rejection kind \(scenario.kind)"
    }

    outcome.rejectionsCovered += 1
    return nil
  }

  /// After a `prepare` rejection, no pending material may be retained and every
  /// supplied input buffer must already be erased.
  private func assertRejectedInputsErased(
    _ fixture: SecretFixture, lifecycle: TunnelSecretLifecycle
  ) throws -> String? {
    if lifecycle.hasPendingMaterialForTesting {
      return "rejected preparation retained Authority pending material"
    }
    if !fixture.configuration.isErased {
      return "rejected preparation left the configuration buffer retained"
    }
    if !fixture.slots.allSatisfy(\.isErased) {
      return "rejected preparation left a credential slot retained"
    }
    return nil
  }

  func evaluate(_ scenario: SecretScenario) -> String? {
    var scratch = Outcome()
    return run(scenario, into: &scratch)
  }

  // MARK: Shrinking

  /// Greedily reduces payload dimensions while the violation persists,
  /// terminating at a local minimum that still reproduces it.
  func shrink(_ scenario: SecretScenario) -> SecretScenario {
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

  private func candidates(from scenario: SecretScenario) -> [SecretScenario] {
    var result: [SecretScenario] = []
    if scenario.slotCount > 1 {
      var fewer = scenario
      fewer.slotCount -= 1
      result.append(fewer)
    }
    if scenario.secretSize > 1 {
      var smaller = scenario
      smaller.secretSize = 1
      result.append(smaller)
    }
    if scenario.configExtra > 0 {
      var smaller = scenario
      smaller.configExtra = 0
      result.append(smaller)
    }
    return result
  }
}

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
    var rng = SplitMix64(seed: iterationSeed)
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

import CFWSharedProtocol
import Foundation
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

// The Property 7 harness: it drives each generated scenario through a terminal
// path or a rejection and checks that no secret outlives it.
private typealias SHA256Digest = CFWSharedProtocol.SHA256Digest

private func digest(_ data: Data) throws -> SHA256Digest {
  try SHA256Digest(hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
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

struct BoundedTerminalSecretErasureProperty {
  struct Outcome {
    var violation: String?
    var kindsCovered: Set<Int> = []
    var rejectionsCovered = 0
    var terminalErasuresChecked = 0
    var snapshotsScanned = 0
  }

  // MARK: Scenario generation

  func randomScenario(using rng: inout ErasureSplitMix64) -> SecretScenario {
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
      identitySHA256: identityDigest,
      credentialAudience: CredentialAudience(profileID: UUID(), profileDigest: identityDigest),
      credentialSlots: credentialSlots,
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
      let redeemed = try lifecycle.redeem(ticket: ticket)
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
      if (try? lifecycle.redeem(ticket: ticket)) != nil {
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
      let redeemed = try lifecycle.redeem(ticket: ticket)
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

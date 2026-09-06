import CFWSharedProtocol
import CryptoKit
import Foundation
import Testing

@testable import CFWGlobalAuthority

private typealias SHA256Digest = CFWSharedProtocol.SHA256Digest

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

private struct SecretFixture {
  let request: PrepareStartRequest
  let leaseID: AuthorityIdentifier
  let configuration: SensitiveBytes
  let slot: AuthoritySecretSlot
  let secrets: AuthoritySecretMaterial
}

private func digest(_ data: Data) throws -> SHA256Digest {
  try SHA256Digest(
    hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
}

private func makeFixture(secret: Data = Data("credential-marker".utf8)) throws -> SecretFixture {
  let configurationData = Data("{\"outbounds\":[]}".utf8)
  let configurationDigest = try digest(configurationData)
  let identityDigest = try SHA256Digest(hex: String(repeating: "b", count: 64))
  let reference = CredentialReference(id: UUID(), kind: .trojanPassword)
  let credentialSlot = try CredentialSlot(
    reference: reference, target: .trojanPassword, outboundIndex: 0,
    jsonPointer: "/outbounds/0/password")
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
    credentialSlots: [credentialSlot],
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true))
  let request = try PrepareStartRequest(
    operation: operation, expectedRevision: 1, configuration: descriptor)
  let authoritySlot = try AuthoritySecretSlot(reference: reference, copying: secret)
  return try SecretFixture(
    request: request, leaseID: AuthorityIdentifier(UUID()),
    configuration: SensitiveBytes(
      copying: configurationData,
      maximumCount: AuthorityV1Limits.maximumConfigurationBytes),
    slot: authoritySlot,
    secrets: AuthoritySecretMaterial(slots: [authoritySlot]))
}

private func providerTickets(
  from transport: AuthorityIssuedTicketTransport, count: Int
) throws -> [StartTicket] {
  try transport.withTicket { ticket in
    try ticket.withUnsafeBytes { raw in
      try (0..<count).map { _ in try StartTicket(copying: Data(raw)) }
    }
  }
}

@Test func ticketIssuanceIs32RandomBytesHashOnlyAndAtMostTenSeconds() throws {
  let rawTicket = Data((0..<AuthorityV1Limits.ticketBytes).map(UInt8.init))
  let clock = TestMonotonicClock(5_000)
  let lifecycle = TunnelSecretLifecycle(
    randomness: FixedTicketRandomness(value: rawTicket), clock: clock)
  let fixture = try makeFixture()

  let issued = try lifecycle.prepare(
    request: fixture.request, leaseID: fixture.leaseID,
    configuration: fixture.configuration, secrets: fixture.secrets)
  #expect(issued.expiresMonotonic == 15_000)
  #expect(lifecycle.retainedTicketHashForTesting == (try digest(rawTicket)))
  #expect(lifecycle.hasPendingMaterialForTesting)
  #expect(!(lifecycle is any Encodable))

  let tickets = try providerTickets(from: issued, count: 1)
  #expect(issued.isErasedForTesting)
  tickets[0].erase()
  lifecycle.terminate(.cancellation)
}

@Test func redemptionIsSingleUseAndErasesEveryTransportExit() throws {
  let rawTicket = Data(repeating: 0x5a, count: AuthorityV1Limits.ticketBytes)
  let lifecycle = TunnelSecretLifecycle(
    randomness: FixedTicketRandomness(value: rawTicket),
    clock: TestMonotonicClock(1_000))
  let fixture = try makeFixture()
  let issued = try lifecycle.prepare(
    request: fixture.request, leaseID: fixture.leaseID,
    configuration: fixture.configuration, secrets: fixture.secrets)
  let tickets = try providerTickets(from: issued, count: 2)

  let redeemed = try lifecycle.redeem(ticket: tickets[0])
  #expect(!lifecycle.hasPendingMaterialForTesting)
  #expect(throws: AuthoritySecretLifecycleError.ticketAlreadyRedeemed) {
    try lifecycle.redeem(ticket: tickets[1])
  }

  let observed = try redeemed.withMaterial { configuration, secrets in
    #expect(!configuration.isErased)
    #expect(!secrets.slots[0].isErased)
    return (configuration.count, secrets.totalByteCount)
  }
  #expect(observed.0 == Int(fixture.request.configuration.byteCount))
  #expect(observed.1 == Data("credential-marker".utf8).count)
  #expect(redeemed.isErasedForTesting)
  #expect(throws: AuthoritySecretLifecycleError.transportConsumed) {
    try redeemed.withMaterial { _, _ in () }
  }
}

private enum RequestedTransportFailure: Error { case requested }

@Test func throwingTransportConsumersStillEraseTicketAndSecretBuffers() throws {
  let lifecycle = TunnelSecretLifecycle(
    randomness: FixedTicketRandomness(
      value: Data(repeating: 7, count: AuthorityV1Limits.ticketBytes)),
    clock: TestMonotonicClock(100))
  let fixture = try makeFixture()
  let issued = try lifecycle.prepare(
    request: fixture.request, leaseID: fixture.leaseID,
    configuration: fixture.configuration, secrets: fixture.secrets)
  var provider: StartTicket?
  #expect(throws: RequestedTransportFailure.requested) {
    try issued.withTicket { ticket in
      provider = try ticket.withUnsafeBytes { try StartTicket(copying: Data($0)) }
      throw RequestedTransportFailure.requested
    }
  }
  #expect(issued.isErasedForTesting)

  let redeemed = try lifecycle.redeem(ticket: try #require(provider))
  #expect(throws: RequestedTransportFailure.requested) {
    try redeemed.withMaterial { _, _ in throw RequestedTransportFailure.requested }
  }
  #expect(redeemed.isErasedForTesting)
}

@Test func everyAuthorityTerminalPathErasesRetainedConfigurationAndCredentials() throws {
  for (index, path) in AuthoritySecretTerminalPath.allCases.enumerated() {
    let lifecycle = TunnelSecretLifecycle(
      randomness: FixedTicketRandomness(
        value: Data(repeating: UInt8(index), count: 32)),
      clock: TestMonotonicClock(1_000))
    let fixture = try makeFixture()
    let issued = try lifecycle.prepare(
      request: fixture.request, leaseID: fixture.leaseID,
      configuration: fixture.configuration, secrets: fixture.secrets)

    lifecycle.terminate(path)

    #expect(!lifecycle.hasPendingMaterialForTesting)
    #expect(fixture.configuration.isErased)
    #expect(fixture.slot.isErased)
    issued.erase()
  }
}

@Test func expiryRejectsRedemptionAndErasesAuthorityAndInboundTicketBuffers() throws {
  let clock = TestMonotonicClock(2_000)
  let lifecycle = TunnelSecretLifecycle(
    randomness: FixedTicketRandomness(value: Data(repeating: 9, count: 32)),
    clock: clock)
  let fixture = try makeFixture()
  let issued = try lifecycle.prepare(
    request: fixture.request, leaseID: fixture.leaseID,
    configuration: fixture.configuration, secrets: fixture.secrets,
    lifetimeMilliseconds: 10_000)
  let ticket = try #require(providerTickets(from: issued, count: 1).first)
  clock.advance(by: 10_000)

  #expect(throws: AuthoritySecretLifecycleError.ticketExpired) {
    try lifecycle.redeem(ticket: ticket)
  }
  #expect(fixture.configuration.isErased)
  #expect(fixture.slot.isErased)
  #expect(throws: AuthorityV1ValidationError.secretUnavailable) {
    try ticket.withUnsafeBytes { _ in () }
  }
}

@Test func lifetimeAndCredentialBoundsRejectBeforeRetentionAndEraseInputs() throws {
  let lifecycle = TunnelSecretLifecycle(
    randomness: FixedTicketRandomness(value: Data(repeating: 1, count: 32)),
    clock: TestMonotonicClock(1))
  let fixture = try makeFixture()
  #expect(throws: AuthoritySecretLifecycleError.invalidPreparation) {
    try lifecycle.prepare(
      request: fixture.request, leaseID: fixture.leaseID,
      configuration: fixture.configuration, secrets: fixture.secrets,
      lifetimeMilliseconds: 10_001)
  }
  #expect(fixture.configuration.isErased)
  #expect(fixture.slot.isErased)
  #expect(!lifecycle.hasPendingMaterialForTesting)

  let tooMany = try (0...AuthorityV1Limits.maximumCredentialSlots).map { _ in
    try AuthoritySecretSlot(
      reference: CredentialReference(id: UUID(), kind: .trojanPassword),
      copying: Data([1]))
  }
  #expect(throws: AuthorityV1ValidationError.boundViolation) {
    try AuthoritySecretMaterial(slots: tooMany)
  }
  #expect(tooMany.allSatisfy { $0.isErased })

  let tooLargeTotal = try (0..<17).map { _ in
    try AuthoritySecretSlot(
      reference: CredentialReference(id: UUID(), kind: .trojanPassword),
      copying: Data(
        repeating: 2, count: AuthorityV1Limits.maximumIndividualSecretBytes))
  }
  #expect(throws: AuthorityV1ValidationError.boundViolation) {
    try AuthoritySecretMaterial(slots: tooLargeTotal)
  }
  #expect(tooLargeTotal.allSatisfy { $0.isErased })
}

@Test func exactConfigurationAndCredentialMismatchErasesRejectedInputs() throws {
  let lifecycle = TunnelSecretLifecycle(
    randomness: FixedTicketRandomness(value: Data(repeating: 3, count: 32)),
    clock: TestMonotonicClock(1))
  let fixture = try makeFixture()
  let wrongConfiguration = try SensitiveBytes(
    copying: Data(repeating: 0, count: Int(fixture.request.configuration.byteCount)),
    maximumCount: AuthorityV1Limits.maximumConfigurationBytes)

  #expect(throws: AuthoritySecretLifecycleError.invalidPreparation) {
    try lifecycle.prepare(
      request: fixture.request, leaseID: fixture.leaseID,
      configuration: wrongConfiguration, secrets: fixture.secrets)
  }
  #expect(wrongConfiguration.isErased)
  #expect(fixture.slot.isErased)
  #expect(!lifecycle.hasPendingMaterialForTesting)

  let credentialFixture = try makeFixture()
  let wrongSlot = try AuthoritySecretSlot(
    reference: CredentialReference(id: UUID(), kind: .trojanPassword),
    copying: Data("credential-marker".utf8))
  let wrongSecrets = try AuthoritySecretMaterial(slots: [wrongSlot])
  #expect(throws: AuthoritySecretLifecycleError.invalidPreparation) {
    try lifecycle.prepare(
      request: credentialFixture.request, leaseID: credentialFixture.leaseID,
      configuration: credentialFixture.configuration, secrets: wrongSecrets)
  }
  #expect(credentialFixture.configuration.isErased)
  #expect(wrongSlot.isErased)
  #expect(!lifecycle.hasPendingMaterialForTesting)
}

@Test func rejectedRedemptionAndRepeatedRandomTicketEraseAllOwnedBuffers() throws {
  let rawTicket = Data(repeating: 0x44, count: AuthorityV1Limits.ticketBytes)
  let lifecycle = TunnelSecretLifecycle(
    randomness: FixedTicketRandomness(value: rawTicket),
    clock: TestMonotonicClock(1_000))
  let fixture = try makeFixture()
  let issued = try lifecycle.prepare(
    request: fixture.request, leaseID: fixture.leaseID,
    configuration: fixture.configuration, secrets: fixture.secrets)
  let issuedTicket = try #require(providerTickets(from: issued, count: 1).first)
  var rejectedBytes = Data(repeating: 0x99, count: AuthorityV1Limits.ticketBytes)
  let rejectedTicket = try StartTicket(copying: rejectedBytes)
  rejectedBytes.resetBytes(in: rejectedBytes.startIndex..<rejectedBytes.endIndex)

  #expect(throws: AuthoritySecretLifecycleError.ticketInvalid) {
    try lifecycle.redeem(ticket: rejectedTicket)
  }
  #expect(lifecycle.hasPendingMaterialForTesting)
  #expect(throws: AuthorityV1ValidationError.secretUnavailable) {
    try rejectedTicket.withUnsafeBytes { _ in () }
  }

  let redeemed = try lifecycle.redeem(ticket: issuedTicket)
  try redeemed.withMaterial { _, _ in () }

  let collisionFixture = try makeFixture()
  #expect(throws: AuthoritySecretLifecycleError.randomGenerationFailed) {
    try lifecycle.prepare(
      request: collisionFixture.request, leaseID: collisionFixture.leaseID,
      configuration: collisionFixture.configuration, secrets: collisionFixture.secrets)
  }
  #expect(collisionFixture.configuration.isErased)
  #expect(collisionFixture.slot.isErased)
  #expect(!lifecycle.hasPendingMaterialForTesting)
}

import CFWSharedProtocol
import CryptoKit
import Foundation
import Testing

@testable import CFWGlobalAuthority

// Example coverage for task 9.11 that the existing suite does not already own:
// the authenticated XPC *service* boundary (`AuthenticatedAuthorityPeerService`)
// plus the pure protocol/recovery mappings it depends on. Lifecycle-level ticket
// bounds/erasure (TunnelSecretLifecycleTests), the concurrency/event queue
// (AuthorityBackpressureTests), journal fault injection/recovery
// (AuthorityJournalTests, AuthorityLivenessTests), and the audit-token policy
// (PeerAuthorizationTests) are covered elsewhere and are not duplicated here.
//
// Every boundary is a pure fake: no real launchd, Network Extension,
// SystemConfiguration, Security.framework, wall clock, or randomness is used.

// MARK: - Deterministic fakes

private final class ExampleJournal: AuthorityJournalCommitting, @unchecked Sendable {
  private let lock = NSLock()
  private(set) var states: [AuthorityCommittedState] = []

  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead {
    try lock.withLock {
      states.append(state)
      return try AuthorityJournalHead(
        sequence: UInt64(states.count), committedLength: UInt64(states.count),
        recordSHA256: exampleDigest(Data("journal-\(states.count)".utf8)))
    }
  }

  var count: Int { lock.withLock { states.count } }
}

private struct ExampleRandomness: AuthorityTicketRandomness {
  func randomBytes(count: Int) throws -> Data { Data(repeating: 0x5a, count: count) }
}

private final class MutableExampleClock: AuthorityMonotonicClock, @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64
  init(_ value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { lock.withLock { value } }
  func set(_ next: UInt64) { lock.withLock { value = next } }
}

private func exampleDigest(_ data: Data) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
}

private func examplePeer(_ role: AuthorityRole, ownerUID: UInt32 = 501) throws -> PeerIdentity {
  PeerIdentity(
    connectionIdentityDigest: try exampleDigest(Data("connection".utf8)),
    pid: 42, euid: role == .provider ? 0 : ownerUID,
    auditSessionID: role == .provider ? 0 : 7,
    role: role, consoleUID: 501)
}

private func authorityError(_ value: NSError?) -> AuthorityErrorCode? {
  guard let value,
    let raw = value.userInfo[AuthorityXPCErrorContract.stableCodeKey] as? String
  else { return nil }
  return AuthorityErrorCode(rawValue: raw)
}

// MARK: - Fixtures

private struct TunnelFixture {
  let request: PrepareStartRequest
  let configuration: Data
  let secretPayload: Data
  let marker: String
}

private func tunnelFixture(ownerUID: UInt32 = 501) throws -> TunnelFixture {
  let configuration = Data("{\"outbounds\":[]}".utf8)
  let configDigest = try exampleDigest(configuration)
  let identityDigest = try exampleDigest(Data("identity".utf8))
  let reference = CredentialReference(id: UUID(), kind: .trojanPassword)
  let slot = try CredentialSlot(
    reference: reference, target: .trojanPassword,
    outboundIndex: 0, jsonPointer: "/outbounds/0/password")
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1),
    mode: .tunnel, configSHA256: configDigest,
    identitySHA256: identityDigest, ownerUID: ownerUID, authorityRevision: 1)
  let descriptor = try AuthorityConfigurationDescriptor(
    byteCount: UInt32(configuration.count), configSHA256: configDigest,
    identitySHA256: identityDigest,
    credentialAudience: CredentialAudience(profileID: UUID(), profileDigest: identityDigest),
    credentialSlots: [slot],
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true))
  let request = try PrepareStartRequest(
    operation: operation, expectedRevision: 1, configuration: descriptor)
  let marker = "credential-marker-never-serialize"
  let secretSlot = try AuthoritySecretSlot(reference: reference, copying: Data(marker.utf8))
  let material = try AuthoritySecretMaterial(slots: [secretSlot])
  let encoded = try #require(try AuthoritySecretPayloadCodec.encode(material))
  let payload = try encoded.withUnsafeBytes { Data($0) }
  encoded.erase()
  material.erase()
  return TunnelFixture(
    request: request, configuration: configuration,
    secretPayload: payload, marker: marker)
}

private func makeCore(clock: any AuthorityMonotonicClock = MutableExampleClock(1_000))
  throws -> (journal: ExampleJournal, core: GlobalAuthorityServiceCore)
{
  let journal = ExampleJournal()
  let core = GlobalAuthorityServiceCore(
    reducer: try .unEnrolledOff(), journal: journal,
    randomness: ExampleRandomness(), clock: clock)
  return (journal, core)
}

private func makeService(
  role: AuthorityRole, ownerUID: UInt32 = 501,
  core: GlobalAuthorityServiceCore,
  reauthorize: (@Sendable () throws -> PeerIdentity)? = nil
) throws -> AuthenticatedAuthorityPeerService {
  let peer = try examplePeer(role, ownerUID: ownerUID)
  return AuthenticatedAuthorityPeerService(
    peerID: UUID(), peer: peer,
    reauthorize: reauthorize ?? { peer }, core: core,
    concurrency: AuthorityConcurrencyGate(), events: AuthorityEventHub())
}

/// Canonical Authority v1 JSON using the exact serialization options the codec
/// requires. Used to hand-build envelopes the strongly-typed models cannot
/// (unsupported versions/features) or whose request type has no public init.
private func canonicalEnvelope(_ object: [String: Any]) throws -> Data {
  try JSONSerialization.data(
    withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
}

private func redeemEnvelope(
  ticket: Data, requestID: AuthorityIdentifier
) throws -> Data {
  return try canonicalEnvelope([
    "command": [
      "kind": "redeem_tunnel_ticket",
      "payload": [
        "ticket": ticket.map(Int.init)
      ],
    ],
    "major": AuthorityV1Limits.major,
    "minor": AuthorityV1Limits.minor,
    "request_id": requestID.rawValue.uuidString.lowercased(),
    "required_feature_bits": 0,
  ])
}

// MARK: - Protocol negotiation

@Test func handshakeThroughServiceNegotiatesExactV1Bounds() throws {
  let objects = try makeCore()
  let service = try makeService(role: .host, core: objects.core)
  let requestID = AuthorityIdentifier(UUID())
  let envelope = try AuthorityRequestEnvelope(
    requestID: requestID,
    command: .handshake(HandshakeRequest(version: try AuthorityProtocolVersion())))

  var response: Data?
  var error: NSError?
  service.handshake(try AuthorityV1Codec.encode(envelope)) { data, value in
    response = data
    error = value
  }
  #expect(error == nil)
  let decoded = try AuthorityV1Codec.decodeResponse(
    HandshakeResponse.self, from: try #require(response))
  #expect(decoded.requestID == requestID)
  let negotiated = decoded.result
  #expect(negotiated.version == (try AuthorityProtocolVersion()))
  #expect(
    negotiated.maximumConfigurationBytes
      == UInt32(AuthorityV1Limits.maximumConfigurationBytes))
  #expect(
    negotiated.maximumTotalSecretBytes
      == UInt32(AuthorityV1Limits.maximumTotalSecretBytes))
  #expect(negotiated.maximumCredentialSlots == UInt16(AuthorityV1Limits.maximumCredentialSlots))
  #expect(
    negotiated.maximumQueuedEventsPerPeer
      == UInt16(AuthorityV1Limits.maximumQueuedEventsPerPeer))
  #expect(
    negotiated.preparationLifetimeMilliseconds
      == AuthorityV1Limits.preparationLifetimeMilliseconds)
  // Handshake is a read-only negotiation and never commits to the journal.
  #expect(objects.journal.count == 0)
}

@Test func unsupportedMajorAndRequiredFeatureBitsMapToProtocolMismatch() throws {
  let objects = try makeCore()
  let service = try makeService(role: .host, core: objects.core)

  // An envelope from a different wire major version is rejected as an
  // incompatible protocol before any dispatch or mutation.
  let futureMajor = try canonicalEnvelope([
    "command": ["kind": "snapshot", "payload": [String: Any]()],
    "major": 2,
    "minor": 0,
    "request_id": UUID().uuidString.lowercased(),
    "required_feature_bits": 0,
  ])
  var majorError: AuthorityErrorCode?
  service.snapshot(futureMajor) { _, error in majorError = authorityError(error) }
  #expect(majorError == .globalAuthorityProtocolMismatch)

  // An envelope demanding an unsupported required feature bit is likewise
  // rejected as incompatible rather than best-effort accepted.
  let unsupportedFeature = try canonicalEnvelope([
    "command": ["kind": "snapshot", "payload": [String: Any]()],
    "major": AuthorityV1Limits.major,
    "minor": AuthorityV1Limits.minor,
    "request_id": UUID().uuidString.lowercased(),
    "required_feature_bits": 1,
  ])
  var featureError: AuthorityErrorCode?
  service.snapshot(unsupportedFeature) { _, error in featureError = authorityError(error) }
  #expect(featureError == .globalAuthorityProtocolMismatch)

  #expect(objects.journal.count == 0)
}

// MARK: - Identity rejection at the authenticated service boundary

@Test func serviceRejectsWrongRoleWrongOwnerAndFailedReauthorization() throws {
  let fixture = try tunnelFixture()
  let requestID = AuthorityIdentifier(UUID())
  let envelope = try AuthorityV1Codec.encode(
    try AuthorityRequestEnvelope(
      requestID: requestID, command: .prepareStart(fixture.request)))

  // A non-Host role cannot prepare a start even though the message is valid.
  let providerObjects = try makeCore()
  let providerService = try makeService(role: .provider, core: providerObjects.core)
  var providerError: AuthorityErrorCode?
  providerService.prepareStart(
    envelope, configuration: fixture.configuration, secretPayload: fixture.secretPayload
  ) { _, error in providerError = authorityError(error) }
  #expect(providerError == .globalAuthorityIdentityRejected)
  #expect(providerObjects.journal.count == 0)

  // A Host whose effective UID does not equal the operation owner UID is rejected.
  let mismatchFixture = try tunnelFixture(ownerUID: 999)
  let mismatchEnvelope = try AuthorityV1Codec.encode(
    try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()),
      command: .prepareStart(mismatchFixture.request)))
  let ownerObjects = try makeCore()
  let ownerService = try makeService(role: .host, ownerUID: 501, core: ownerObjects.core)
  var ownerError: AuthorityErrorCode?
  ownerService.prepareStart(
    mismatchEnvelope, configuration: mismatchFixture.configuration,
    secretPayload: mismatchFixture.secretPayload
  ) { _, error in ownerError = authorityError(error) }
  #expect(ownerError == .globalAuthorityIdentityRejected)
  #expect(ownerObjects.journal.count == 0)

  // A re-authorization failure on a mutating command is mapped to the stable
  // identity-rejected code and never mutates state.
  let throwingObjects = try makeCore()
  let throwingService = try makeService(
    role: .host, core: throwingObjects.core,
    reauthorize: { throw GlobalAuthorityAuthorizationError.identityRejected })
  var reauthError: AuthorityErrorCode?
  throwingService.prepareStart(
    envelope, configuration: fixture.configuration, secretPayload: fixture.secretPayload
  ) { _, error in reauthError = authorityError(error) }
  #expect(reauthError == .globalAuthorityIdentityRejected)
  #expect(throwingObjects.journal.count == 0)
}

// MARK: - Ticket redemption through the full service path

@Test func providerRedeemReturnsMaterialOnceAndRejectsDuplicate() throws {
  let objects = try makeCore()
  let host = try makeService(role: .host, core: objects.core)
  let provider = try makeService(role: .provider, core: objects.core)
  let fixture = try tunnelFixture()

  let prepareID = AuthorityIdentifier(UUID())
  var preparedData: Data?
  host.prepareStart(
    try AuthorityV1Codec.encode(
      try AuthorityRequestEnvelope(
        requestID: prepareID, command: .prepareStart(fixture.request))),
    configuration: fixture.configuration, secretPayload: fixture.secretPayload
  ) { data, error in
    #expect(error == nil)
    preparedData = data
  }
  let prepared = try AuthorityPreparedStartCodec.decode(
    try #require(preparedData), requestID: prepareID,
    operationID: fixture.request.operation.operationID)
  let ticketBytes = try #require(prepared.ticket).withUnsafeBytes { Data($0) }
  prepared.ticket?.erase()

  // The Provider redeems configuration and secrets exactly once.
  var redeemError: NSError?
  var configurationMatches = false
  var secretMatchesMarker = false
  var responseContainsMarker = true
  provider.redeemTunnelTicket(
    try redeemEnvelope(
      ticket: ticketBytes, requestID: AuthorityIdentifier(UUID()))
  ) { response, configuration, secret, error in
    redeemError = error
    if let response {
      responseContainsMarker = String(decoding: response, as: UTF8.self)
        .contains(fixture.marker)
    }
    if let configuration { configurationMatches = configuration == fixture.configuration }
    if let secret,
      let material = try? AuthoritySecretPayloadCodec.decode(
        secret, descriptor: fixture.request.configuration)
    {
      let bytes = try? material.slots.first?.withUnsafeBytes { Data($0) }
      secretMatchesMarker = (bytes ?? Data()) == Data(fixture.marker.utf8)
      material.erase()
    }
  }
  #expect(redeemError == nil)
  #expect(configurationMatches)
  #expect(secretMatchesMarker)
  // The correlation reply metadata never carries secret bytes.
  #expect(!responseContainsMarker)

  // A second redemption of the same ticket fails closed as already redeemed.
  var duplicateError: AuthorityErrorCode?
  var duplicateReturnedMaterial = false
  provider.redeemTunnelTicket(
    try redeemEnvelope(
      ticket: ticketBytes, requestID: AuthorityIdentifier(UUID()))
  ) { _, configuration, secret, error in
    duplicateError = authorityError(error)
    duplicateReturnedMaterial = configuration != nil || secret != nil
  }
  #expect(duplicateError == .ticketAlreadyRedeemed)
  #expect(!duplicateReturnedMaterial)
}

@Test func expiredTicketRedemptionMapsToTicketExpiredWithoutMaterial() throws {
  let clock = MutableExampleClock(1_000)
  let objects = try makeCore(clock: clock)
  let host = try makeService(role: .host, core: objects.core)
  let provider = try makeService(role: .provider, core: objects.core)
  let fixture = try tunnelFixture()

  let prepareID = AuthorityIdentifier(UUID())
  var preparedData: Data?
  host.prepareStart(
    try AuthorityV1Codec.encode(
      try AuthorityRequestEnvelope(
        requestID: prepareID, command: .prepareStart(fixture.request))),
    configuration: fixture.configuration, secretPayload: fixture.secretPayload
  ) { data, _ in preparedData = data }
  let prepared = try AuthorityPreparedStartCodec.decode(
    try #require(preparedData), requestID: prepareID,
    operationID: fixture.request.operation.operationID)
  let ticketBytes = try #require(prepared.ticket).withUnsafeBytes { Data($0) }
  prepared.ticket?.erase()
  let committedAfterPrepare = objects.journal.count

  // Advance beyond the 10-second preparation lifetime, then redeem.
  clock.set(1_000 + AuthorityV1Limits.preparationLifetimeMilliseconds + 1)
  var expiryError: AuthorityErrorCode?
  var returnedMaterial = false
  provider.redeemTunnelTicket(
    try redeemEnvelope(
      ticket: ticketBytes, requestID: AuthorityIdentifier(UUID()))
  ) { _, configuration, secret, error in
    expiryError = authorityError(error)
    returnedMaterial = configuration != nil || secret != nil
  }
  #expect(expiryError == .ticketExpired)
  #expect(!returnedMaterial)
  // An expired redemption commits nothing new to the durable journal.
  #expect(objects.journal.count == committedAfterPrepare)
}

// MARK: - Redacted diagnostics

@Test func authorityDiagnosticsAreStableCodedAndRedactSecretsAndDigests() throws {
  let fullDigest = try exampleDigest(Data("sensitive-runtime-digest".utf8))
  let context = AuthorityDiagnosticContext(
    operationID: AuthorityIdentifier(UUID()), generation: 7,
    role: .provider, digest: fullDigest)
  let domain = AuthorityDomainError(code: .ticketInvalid, context: context)
  let rendered = domain.description

  // Diagnostics expose only stable, bounded fields: the digest is truncated to a
  // short prefix and the full hash never appears.
  #expect(rendered.contains("code=ticket_invalid"))
  #expect(rendered.contains("generation=7"))
  #expect(rendered.contains("role=provider"))
  #expect(rendered.contains("digest_prefix=\(String(fullDigest.hex.prefix(12)))"))
  #expect(!rendered.contains(fullDigest.hex))

  // Every stable error code round-trips through the XPC contract with a stable
  // code and message and never leaks localized OS text as policy input.
  for code in AuthorityErrorCode.allCases {
    let nsError = AuthorityXPCErrorContract.error(code)
    #expect(nsError.domain == AuthorityXPCErrorContract.domain)
    #expect(nsError.userInfo[AuthorityXPCErrorContract.stableCodeKey] as? String == code.rawValue)
    #expect((nsError.localizedDescription) == code.stableMessage)
    #expect(AuthorityXPCErrorContract.domainError(nsError).code == code)
  }
}

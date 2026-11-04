import CFWAppleNetwork
import CFWCredentialTransport
import CryptoKit
import Foundation
import Testing

@testable import CFWCredentialVault
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// The cutover preflight: both configurations checked without a data plane, an
// active owner never stopped, no System Extension installation for System
// Proxy, approval retries reattached, and a native state that is not Off.
private struct PreflightIdentityDocument: Encodable {
  let configurationSHA256: String
  let credentialAudience: CredentialAudience
  let credentialSlots: [CredentialSlot]
  let mode: String
  let networkOptions: TunnelNetworkOptions?
  let schemaVersion: UInt16

  private enum CodingKeys: String, CodingKey {
    case configurationSHA256 = "configuration_sha256"
    case credentialAudience = "credential_audience"
    case credentialSlots = "credential_slots"
    case mode
    case networkOptions = "network_options"
    case schemaVersion = "schema_version"
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(configurationSHA256, forKey: .configurationSHA256)
    try container.encode(credentialAudience, forKey: .credentialAudience)
    try container.encode(credentialSlots, forKey: .credentialSlots)
    try container.encode(mode, forKey: .mode)
    if let networkOptions {
      try container.encode(networkOptions, forKey: .networkOptions)
    } else {
      try container.encodeNil(forKey: .networkOptions)
    }
    try container.encode(schemaVersion, forKey: .schemaVersion)
  }
}

private func sha256(_ data: Data) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  )
}

func preflightRequest(target: EngineMode = .tunnel) throws -> CutoverPreflightRequest {
  let context = try EngineCommandContext(
    installationID: #require(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
    configEpoch: 2,
    generation: 7
  )
  let audience = CredentialAudience(
    profileID: try #require(UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")),
    profileDigest: try CFWSharedProtocol.SHA256Digest(hex: String(repeating: "ab", count: 32))
  )
  let configuration = Data(
    #"{"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}"#.utf8
  )
  let contentDigest = try sha256(configuration)
  let tunnelOptions = try TunnelNetworkOptions(ipv6Enabled: true)

  func request(options: TunnelNetworkOptions?) throws -> EngineStartRequest {
    let identity = PreflightIdentityDocument(
      configurationSHA256: contentDigest.hex,
      credentialAudience: audience,
      credentialSlots: [],
      mode: options == nil ? "system_proxy" : "tunnel",
      networkOptions: options,
      schemaVersion: NativeProtocolConstants.schemaVersion
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try EngineStartRequest(
      mode: options == nil ? .systemProxy : .tunnel,
      context: context,
      credentialAudience: audience,
      configJSON: String(decoding: configuration, as: UTF8.self),
      configContentDigest: contentDigest,
      configDigest: sha256(encoder.encode(identity)),
      credentialSlots: [],
      tunnelOptions: options
    )
  }

  return try CutoverPreflightRequest(
    target: target,
    systemProxyRequest: request(options: nil),
    tunnelRequest: request(options: tunnelOptions)
  )
}

@Test func cutoverPreflightChecksBothConfigsAndNeverStartsADataPlane() async throws {
  let proxy = RecordingProxyAgent()
  let tunnel = RecordingTunnelHost()
  let coordinator = makePreflightCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: EmptyCredentialVault()
  )

  let result = try await coordinator.execute(.preflightCutover(preflightRequest()))
  guard case .cutoverPreflight(.ready(let attestation)) = result else {
    Issue.record("preflight did not return a ready attestation")
    return
  }
  #expect(attestation.target == .tunnel)
  #expect(attestation.validForMillis == 300_000)
  #expect(await proxy.validationCount() == 2)
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await tunnel.mutationCounts() == (install: 1, cancel: 0, start: 0, stop: 0))
}

@Test func failedConfigPreflightLeavesInstallAndDataPlaneUntouched() async throws {
  let proxy = RecordingProxyAgent(rejectsValidation: true)
  let tunnel = RecordingTunnelHost()
  let coordinator = makePreflightCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: EmptyCredentialVault()
  )

  await #expect(throws: (any Error).self) {
    try await coordinator.execute(.preflightCutover(preflightRequest()))
  }
  #expect(await proxy.validationCount() == 1)
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await tunnel.mutationCounts() == (install: 0, cancel: 0, start: 0, stop: 0))
}

@Test(arguments: [false, true])
func onlineCandidateCheckNeverStopsTheActiveOwner(rejected: Bool) async throws {
  let request = try preflightRequest().systemProxyRequest
  let before = EngineSnapshot.proxyActive(
    configuration: try request.descriptor(slot: .systemProxy), sequence: 7)
  let proxy = RecordingProxyAgent(observedSnapshot: before, rejectsValidation: rejected)
  let tunnel = RecordingTunnelHost()
  let coordinator = makePreflightCoordinator(
    proxy: proxy, tunnel: tunnel, credentialVault: EmptyCredentialVault())
  let envelope = NativeRequestEnvelope(requestID: UUID(), command: .checkConfiguration(request))
  let decoded = try NativeBridgeProtocolCodec.decodeRequest(JSONEncoder().encode(envelope))
  if rejected {
    await #expect(throws: (any Error).self) { try await coordinator.execute(decoded.command) }
  } else {
    #expect(try await coordinator.execute(decoded.command) == .acknowledged)
  }
  #expect(await proxy.snapshot() == before)
  #expect(await proxy.validationCount() == 1)
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await tunnel.mutationCounts() == (install: 0, cancel: 0, start: 0, stop: 0))
}

@Test func systemProxyPreflightNeverRequestsSystemExtensionInstallation() async throws {
  let proxy = RecordingProxyAgent()
  let tunnel = RecordingTunnelHost()
  let coordinator = makePreflightCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: EmptyCredentialVault()
  )

  let result = try await coordinator.execute(
    .preflightCutover(preflightRequest(target: .systemProxy))
  )
  guard case .cutoverPreflight(.ready(let attestation)) = result else {
    Issue.record("System Proxy preflight did not return readiness")
    return
  }
  #expect(attestation.target == .systemProxy)
  #expect(await proxy.validationCount() == 2)
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await tunnel.mutationCounts() == (install: 0, cancel: 0, start: 0, stop: 0))
}

@Test func approvalRetryReattachesWithoutAbandoningRequestOrStartingTunnel() async throws {
  let proxy = RecordingProxyAgent()
  let tunnel = RecordingTunnelHost(installResults: [.awaitingApproval, .completed])
  let coordinator = makePreflightCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: EmptyCredentialVault()
  )
  let request = try preflightRequest()

  let first = try await coordinator.execute(.preflightCutover(request))
  guard case .cutoverPreflight(.awaitingApproval) = first else {
    Issue.record("first preflight did not surface approval")
    return
  }
  let second = try await coordinator.execute(.preflightCutover(request))
  guard case .cutoverPreflight(.ready) = second else {
    Issue.record("approved retry did not return readiness")
    return
  }
  #expect(await proxy.validationCount() == 4)
  #expect(await proxy.mutationCounts() == (0, 0))
  // The retry reattaches to the pending OS request. An explicit local cancel
  // would abandon its identity and allow a late callback to race a new request.
  #expect(await tunnel.mutationCounts() == (install: 2, cancel: 0, start: 0, stop: 0))
}

@Test func nonOffNativeStateBlocksPreflightBeforeValidationOrInstallation() async throws {
  let proxy = RecordingProxyAgent(
    observedSnapshot: .proxyFailed(
      EngineFailure(code: "owned", message: "retained", isRetryable: false),
      configuration: nil,
      sequence: 1
    )
  )
  let tunnel = RecordingTunnelHost()
  let coordinator = makePreflightCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: EmptyCredentialVault()
  )

  await #expect(throws: (any Error).self) {
    try await coordinator.execute(.preflightCutover(preflightRequest()))
  }
  #expect(await proxy.validationCount() == 0)
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await tunnel.mutationCounts() == (install: 0, cancel: 0, start: 0, stop: 0))
}

func preflightDescriptor(
  slot: ConfigurationSlot,
  reference: CredentialReference
) throws -> ConfigurationDescriptor {
  let digest = try CFWSharedProtocol.SHA256Digest(hex: String(repeating: "12", count: 32))
  let target: CredentialTarget =
    reference.kind == .trojanPassword ? .trojanPassword : .shadowsocksPassword
  let credentialSlot = try CredentialSlot(
    reference: reference,
    target: target,
    outboundIndex: 0,
    jsonPointer: "/outbounds/0/password"
  )
  return try ConfigurationDescriptor(
    slot: slot,
    tunnelOptions: slot == .tunnel ? TunnelNetworkOptions(ipv6Enabled: true) : nil,
    credentialAudience: CredentialAudience(
      profileID: #require(UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")),
      profileDigest: CFWSharedProtocol.SHA256Digest(hex: String(repeating: "ab", count: 32))),
    installationID: #require(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
    epoch: 2,
    generation: 7,
    byteCount: 2,
    sha256: digest,
    identitySHA256: digest,
    credentialSlots: [credentialSlot]
  )
}

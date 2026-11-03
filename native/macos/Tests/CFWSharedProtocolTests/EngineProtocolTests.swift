import CryptoKit
import Darwin
import Foundation
import Security
import Testing

@testable import CFWSharedProtocol

private struct EngineOwnerSchemaContract: Decodable {
  let configurationIdentitySchemaVersion: UInt16
  let engineOwnerSchemaVersion: UInt16

  private enum CodingKeys: String, CodingKey {
    case configurationIdentitySchemaVersion = "configuration_identity_schema_version"
    case engineOwnerSchemaVersion = "engine_owner_schema_version"
  }
}

func testCredentialAudience() throws -> CredentialAudience {
  CredentialAudience(
    profileID: UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")!,
    profileDigest: try SHA256Digest(hex: String(repeating: "ab", count: 32))
  )
}

@Test func inMemoryConfigurationValidationBindsExactBytesWithoutIO() throws {
  let configuration = Data("{}".utf8)
  let digest = SHA256.hash(data: configuration)
    .map { String(format: "%02x", $0) }
    .joined()
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111"))
  let descriptor = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 1,
    byteCount: UInt64(configuration.count),
    sha256: SHA256Digest(hex: digest)
  )

  try descriptor.validateConfigurationBytes(configuration)
  #expect(throws: ConfigurationBytesValidationError.self) {
    try descriptor.validateConfigurationBytes(Data("[]".utf8))
  }
  #expect(
    throws: ConfigurationBytesValidationError.byteCountMismatch(
      expected: 2,
      actual: 3)
  ) {
    try descriptor.validateConfigurationBytes(Data("{} ".utf8))
  }

  let invalidJSON = Data("xx".utf8)
  let invalidDigest = SHA256.hash(data: invalidJSON)
    .map { String(format: "%02x", $0) }
    .joined()
  let invalidDescriptor = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 2,
    byteCount: UInt64(invalidJSON.count),
    sha256: SHA256Digest(hex: invalidDigest)
  )
  #expect(throws: ConfigurationBytesValidationError.invalidJSON) {
    try invalidDescriptor.validateConfigurationBytes(invalidJSON)
  }
}

@Test func localProxyOwnerBoundaryRejectsSystemMutationEvenWithAnExactContentDigest() throws {
  let configuration = Data(
    #"{"inbounds":[{"type":"mixed","tag":"cfw-system-proxy","listen":"127.0.0.1","listen_port":7891,"set_system_proxy":true}]}"#
      .utf8)
  let digest = try SHA256Digest(
    hex: SHA256.hash(data: configuration).map { String(format: "%02x", $0) }.joined())
  let descriptor = try ConfigurationDescriptor(
    slot: .localProxy, tunnelOptions: nil, credentialAudience: testCredentialAudience(),
    installationID: UUID(), epoch: 1, generation: 1, byteCount: UInt64(configuration.count),
    sha256: digest, identitySHA256: digest)
  #expect(throws: NativeBridgeProtocolError.invalidConfiguration) {
    try descriptor.validateConfigurationBytes(configuration)
  }
}

@Test func requestEnvelopeRoundTripsWithoutLosingTypeInformation() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let digest = try SHA256Digest(hex: String(repeating: "ab", count: 32))
  let descriptor = try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 7,
    byteCount: 128,
    sha256: digest
  )
  let command = try NativeCommand(kind: .startTunnel, configuration: descriptor)
  let original = RequestEnvelope(command: command)

  let decoded = try ProtocolCodec.decodeRequest(ProtocolCodec.encode(original))

  #expect(decoded == original)
}

@Test func tunnelNetworkOptionsEnforcePublicPacketPumpMTUBound() throws {
  #expect(
    try TunnelNetworkOptions(
      ipv6Enabled: true,
      mtu: TunnelNetworkOptions.maximumMTU
    ).mtu == 1_500
  )
  #expect(throws: ProtocolValidationError.invalidTunnelOptions) {
    try TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_501)
  }
  #expect(throws: ProtocolValidationError.invalidTunnelOptions) {
    try TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_279)
  }
}

@Test func tunnelNetworkOptionsAdmitOnlyTheClosedCanonicalDirectIPv4HostSet() throws {
  let exact = try TunnelNetworkOptions(
    ipv6Enabled: true,
    directIPv4Hosts: [TunnelNetworkOptions.releasePacketTransportIPv4]
  )
  let encoded = try JSONEncoder().encode(exact)
  #expect(try JSONDecoder().decode(TunnelNetworkOptions.self, from: encoded) == exact)
  #expect(String(decoding: encoded, as: UTF8.self).contains("\"direct_ipv4_hosts\""))

  for invalid in [
    ["35.194.216.98", "35.194.216.98"],
    ["035.194.216.98"],
    ["35.194.216.99"],
    ["35.194.216.98", "1.1.1.1"],
  ] {
    #expect(throws: ProtocolValidationError.invalidTunnelOptions) {
      try TunnelNetworkOptions(ipv6Enabled: true, directIPv4Hosts: invalid)
    }
  }

  let missingRouteField = Data(
    #"{"ipv6_enabled":true,"bypass_private_networks":true,"mtu":1500}"#.utf8
  )
  #expect(throws: (any Error).self) {
    try JSONDecoder().decode(TunnelNetworkOptions.self, from: missingRouteField)
  }
}

@Test func commandRejectsConfigurationForWrongMode() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let descriptor = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )

  #expect(throws: ProtocolValidationError.invalidCommand) {
    try NativeCommand(kind: .startTunnel, configuration: descriptor)
  }
}

@Test func systemProxyStartRequiresExactConfigurationDescriptor() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let configuration = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )
  let command = try NativeCommand(
    kind: .startSystemProxy,
    configuration: configuration
  )
  #expect(command.configuration == configuration)
}

/// A restore before a stop names the exact System Proxy configuration whose
/// settings it gives back, and crosses the engine protocol unchanged.
@Test func aRestoreBeforeAStopNamesItsSystemProxyConfiguration() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  func configuration(_ slot: ConfigurationSlot) throws -> ConfigurationDescriptor {
    try ConfigurationDescriptor(
      slot: slot,
      tunnelOptions: nil,
      credentialAudience: try testCredentialAudience(),
      installationID: installationID,
      epoch: 1,
      generation: 1,
      byteCount: 2,
      sha256: SHA256Digest(hex: String(repeating: "00", count: 32)))
  }
  #expect(throws: ProtocolValidationError.invalidCommand) {
    try NativeCommand(kind: .restoreSettingsBeforeStop)
  }
  #expect(throws: ProtocolValidationError.invalidCommand) {
    try NativeCommand(kind: .restoreSettingsBeforeStop, configuration: configuration(.localProxy))
  }
  let request = RequestEnvelope(
    command: try NativeCommand(
      kind: .restoreSettingsBeforeStop, configuration: configuration(.systemProxy)))
  #expect(try ProtocolCodec.decodeRequest(ProtocolCodec.encode(request)) == request)
}

@Test func stopCommandRequiresExactConfigurationGeneration() throws {
  #expect(throws: ProtocolValidationError.invalidCommand) {
    try NativeCommand(kind: .stop)
  }
}

@Test func engineOwnerSchemaMatchesSharedContractAndRejectsV5() throws {
  var root = URL(fileURLWithPath: #filePath)
  for _ in 0..<5 { root.deleteLastPathComponent() }
  let contract = try JSONDecoder().decode(
    EngineOwnerSchemaContract.self,
    from: Data(
      contentsOf:
        root
        .appendingPathComponent("contracts/engine-owner-v7", isDirectory: true)
        .appendingPathComponent("schema-policy.json")
    )
  )
  #expect(contract.configurationIdentitySchemaVersion == NativeProtocolConstants.schemaVersion)
  #expect(contract.engineOwnerSchemaVersion == NativeProtocolConstants.schemaVersion)

  for rejected: UInt16 in [5, 6, 99] {
    let json = Data(
      """
      {"schemaVersion":\(rejected),"requestID":{"rawValue":"00000000-0000-0000-0000-000000000001"},"command":{"kind":"snapshot"}}
      """.utf8
    )
    #expect(throws: ProtocolValidationError.unsupportedSchemaVersion(rejected)) {
      try ProtocolCodec.decodeRequest(json)
    }
  }
}

@Test func ownerStartDeadlineIsFixedWhenTheRequestArrives() {
  let receivedAt = ContinuousClock.now
  let deadline = EngineStartDeadline(receivedAt: receivedAt)
  #expect(deadline.instant == receivedAt.advanced(by: EngineStartBudget.ownerLibboxStart))
}

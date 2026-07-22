import CryptoKit
import Foundation
import Testing

@testable import CFWSharedProtocol

private func exactJSONObject(byteCount: Int) -> Data {
  precondition(byteCount >= 8)
  return Data(("{\"v\":\"" + String(repeating: "a", count: byteCount - 8) + "\"}").utf8)
}

private func payloadDigest(_ data: Data) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  )
}

private func payloadDescriptor(
  configuration: Data,
  credentialSlots: [CredentialSlot] = []
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    installationID: #require(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
    epoch: 1,
    generation: 1,
    byteCount: UInt64(configuration.count),
    sha256: payloadDigest(configuration),
    credentialSlots: credentialSlots
  )
}

private func payloadCredentialSlot() throws -> CredentialSlot {
  try CredentialSlot(
    reference: CredentialReference(
      id: #require(UUID(uuidString: "22222222-2222-4222-8222-222222222222")),
      kind: .trojanPassword
    ),
    target: .trojanPassword,
    outboundIndex: 0,
    jsonPointer: "/outbounds/0/password"
  )
}

@Test func tunnelStartConfigurationAcceptsMaxMinusOneAndExactMaximum() throws {
  for count in [
    Int(NativeProtocolConstants.maximumConfigurationBytes) - 1,
    Int(NativeProtocolConstants.maximumConfigurationBytes),
  ] {
    let configuration = exactJSONObject(byteCount: count)
    let descriptor = try payloadDescriptor(configuration: configuration)
    let encoded = try TunnelStartPayloadCodec.encode(
      descriptor: descriptor,
      configuration: configuration,
      credentialPayload: nil
    )
    #expect(encoded.count <= NativeProtocolConstants.maximumMessageBytes)
    var decoded = try TunnelStartPayloadCodec.decode(encoded)
    #expect(decoded.descriptor == descriptor)
    #expect(decoded.configuration == configuration)
    decoded.erase()
  }
}

@Test func tunnelStartConfigurationRejectsMaximumPlusOneBeforeTransport() throws {
  let maximum = exactJSONObject(
    byteCount: Int(NativeProtocolConstants.maximumConfigurationBytes)
  )
  let oversized = exactJSONObject(byteCount: maximum.count + 1)
  let descriptor = try payloadDescriptor(configuration: maximum)
  #expect(
    throws: TunnelStartPayloadError.configurationTooLarge(oversized.count)
  ) {
    try TunnelStartPayloadCodec.encode(
      descriptor: descriptor,
      configuration: oversized,
      credentialPayload: nil
    )
  }
}

@Test func tunnelStartCredentialEnvelopeEnforcesExactOpaqueBound() throws {
  let configuration = Data(#"{"outbounds":[{"password":""}]}"#.utf8)
  let descriptor = try payloadDescriptor(
    configuration: configuration,
    credentialSlots: [payloadCredentialSlot()]
  )
  for count in [
    TunnelStartPayloadCodec.maximumCredentialPayloadBytes - 1,
    TunnelStartPayloadCodec.maximumCredentialPayloadBytes,
  ] {
    let encoded = try TunnelStartPayloadCodec.encode(
      descriptor: descriptor,
      configuration: configuration,
      credentialPayload: Data(repeating: 0x5a, count: count)
    )
    #expect(encoded.count <= NativeProtocolConstants.maximumMessageBytes)
  }
  #expect(
    throws: TunnelStartPayloadError.credentialPayloadTooLarge(
      TunnelStartPayloadCodec.maximumCredentialPayloadBytes + 1
    )
  ) {
    try TunnelStartPayloadCodec.encode(
      descriptor: descriptor,
      configuration: configuration,
      credentialPayload: Data(
        repeating: 0x5a,
        count: TunnelStartPayloadCodec.maximumCredentialPayloadBytes + 1
      )
    )
  }
}

@Test func tunnelStartRejectsDeepConfigurationAndOversizedWire() throws {
  let depth = 65
  let deepJSON = Data(
    (String(repeating: "{\"a\":", count: depth) + "0"
      + String(repeating: "}", count: depth)).utf8
  )
  let descriptor = try payloadDescriptor(configuration: deepJSON)
  #expect(throws: TunnelStartPayloadError.descriptorMismatch) {
    try TunnelStartPayloadCodec.encode(
      descriptor: descriptor,
      configuration: deepJSON,
      credentialPayload: nil
    )
  }
  #expect(
    throws: TunnelStartPayloadError.messageTooLarge(
      NativeProtocolConstants.maximumMessageBytes + 1
    )
  ) {
    try TunnelStartPayloadCodec.decode(
      Data(repeating: 0, count: NativeProtocolConstants.maximumMessageBytes + 1)
    )
  }
}

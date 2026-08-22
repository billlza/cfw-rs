import CryptoKit
import Foundation
import Testing

@testable import CFWSharedProtocol

private let firstCredentialReference = CredentialReference(
  id: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
  kind: .trojanPassword
)
private let secondCredentialReference = CredentialReference(
  id: UUID(uuidString: "22222222-2222-4222-8222-222222222222")!,
  kind: .trojanPassword
)

private struct ModernProtocolIdentityDocument: Encodable {
  let configurationSHA256: String
  let credentialAudience: CredentialAudience
  let credentialSlots: [CredentialSlot]

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
    try container.encode("system_proxy", forKey: .mode)
    try container.encodeNil(forKey: .networkOptions)
    try container.encode(NativeProtocolConstants.schemaVersion, forKey: .schemaVersion)
  }
}

private func modernProtocolDigest(_ data: Data) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  )
}

private func modernProtocolStartRequest(
  configuration: String,
  audience: CredentialAudience,
  slots: [CredentialSlot]
) throws -> EngineStartRequest {
  let configurationData = Data(configuration.utf8)
  let contentDigest = try modernProtocolDigest(configurationData)
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let identityData = try encoder.encode(
    ModernProtocolIdentityDocument(
      configurationSHA256: contentDigest.hex,
      credentialAudience: audience,
      credentialSlots: slots
    )
  )
  return try EngineStartRequest(
    context: EngineCommandContext(
      installationID: UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")!,
      configEpoch: 1,
      generation: 1
    ),
    credentialAudience: audience,
    configJSON: configuration,
    configContentDigest: contentDigest,
    configDigest: modernProtocolDigest(identityData),
    credentialSlots: slots,
    tunnelOptions: nil
  )
}

@Test func credentialProvisionWireRequiresCanonicalReferenceOrder() throws {
  let request = try CredentialProvisionRequest(
    audience: try testCredentialAudience(),
    requiredReferences: [firstCredentialReference, secondCredentialReference],
    entries: [
      try CredentialProvisionEntry(
        reference: firstCredentialReference,
        secret: "first-dummy-secret"
      ),
      try CredentialProvisionEntry(
        reference: secondCredentialReference,
        secret: "second-dummy-secret"
      ),
    ]
  )
  let envelope = NativeRequestEnvelope(
    requestID: UUID(uuidString: "33333333-3333-4333-8333-333333333333")!,
    command: .provisionCredentials(request)
  )
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let encoded = try encoder.encode(envelope)

  #expect(try NativeBridgeProtocolCodec.decodeRequest(encoded) == envelope)

  var root = try #require(
    JSONSerialization.jsonObject(with: encoded) as? [String: Any]
  )
  var command = try #require(root["command"] as? [String: Any])
  var payload = try #require(command["payload"] as? [String: Any])
  var decodedRequest = try #require(payload["request"] as? [String: Any])
  decodedRequest["entries"] = Array(
    try #require(decodedRequest["entries"] as? [Any]).reversed()
  )
  payload["request"] = decodedRequest
  command["payload"] = payload
  root["command"] = command
  let reversed = try JSONSerialization.data(
    withJSONObject: root,
    options: [.sortedKeys, .withoutEscapingSlashes]
  )

  #expect(throws: NativeBridgeProtocolError.invalidCredentialSlot) {
    try NativeBridgeProtocolCodec.decodeRequest(reversed)
  }
}

@Test func uuidCredentialProvisioningRequiresCanonicalHyphenatedValues() throws {
  for (index, kind) in [CredentialKind.vmessUUID, .vlessUUID, .tuicUUID].enumerated() {
    let reference = CredentialReference(
      id: UUID(uuidString: "00000000-0000-4000-8000-00000000000\(index + 1)")!,
      kind: kind
    )
    #expect(throws: NativeBridgeProtocolError.invalidCredentialSlot) {
      try CredentialProvisionEntry(reference: reference, secret: "not-a-uuid")
    }
    #expect(throws: NativeBridgeProtocolError.invalidCredentialSlot) {
      try CredentialProvisionEntry(
        reference: reference,
        secret: "11111111-1111-4111-8111-11111111111A"
      )
    }
    _ = try CredentialProvisionEntry(
      reference: reference,
      secret: "11111111-1111-4111-8111-111111111111"
    )
  }
}

@Test func modernProtocolCredentialSlotsKeepKindsAndPointersClosed() throws {
  let anytlsID = UUID(uuidString: "33333333-3333-4333-8333-333333333333")!
  let tuicUUIDID = UUID(uuidString: "44444444-4444-4444-8444-444444444444")!
  let tuicPasswordID = UUID(uuidString: "55555555-5555-4555-8555-555555555555")!
  let anytlsReference = CredentialReference(id: anytlsID, kind: .anytlsPassword)
  let tuicUUIDReference = CredentialReference(id: tuicUUIDID, kind: .tuicUUID)
  let tuicPasswordReference = CredentialReference(id: tuicPasswordID, kind: .tuicPassword)
  let slots = [
    try CredentialSlot(
      reference: anytlsReference,
      target: .anytlsPassword,
      outboundIndex: 0,
      jsonPointer: "/outbounds/0/password"
    ),
    try CredentialSlot(
      reference: tuicUUIDReference,
      target: .tuicUUID,
      outboundIndex: 1,
      jsonPointer: "/outbounds/1/uuid"
    ),
    try CredentialSlot(
      reference: tuicPasswordReference,
      target: .tuicPassword,
      outboundIndex: 1,
      jsonPointer: "/outbounds/1/password"
    ),
  ]

  #expect(CredentialKind.anytlsPassword.rawValue == "anytls_password")
  #expect(CredentialKind.tuicUUID.rawValue == "tuic_uuid")
  #expect(CredentialKind.tuicPassword.rawValue == "tuic_password")
  #expect(CredentialTarget.anytlsPassword.rawValue == "anytls_password")
  #expect(CredentialTarget.tuicUUID.rawValue == "tuic_uuid")
  #expect(CredentialTarget.tuicPassword.rawValue == "tuic_password")

  #expect(throws: NativeBridgeProtocolError.invalidCredentialSlot) {
    try CredentialSlot(
      reference: tuicUUIDReference,
      target: .tuicPassword,
      outboundIndex: 1,
      jsonPointer: "/outbounds/1/password"
    )
  }
  #expect(throws: NativeBridgeProtocolError.invalidCredentialSlot) {
    try CredentialSlot(
      reference: tuicUUIDReference,
      target: .tuicUUID,
      outboundIndex: 1,
      jsonPointer: "/outbounds/1/password"
    )
  }

  let audience = try testCredentialAudience()
  let request = try modernProtocolStartRequest(
    configuration:
      #"{"outbounds":[{"password":"","type":"anytls"},{"password":"","type":"tuic","uuid":""}]}"#,
    audience: audience,
    slots: slots
  )
  #expect(request.credentialSlots == slots)

  let envelope = NativeRequestEnvelope(
    requestID: UUID(uuidString: "66666666-6666-4666-8666-666666666666")!,
    command: .startSystemProxy(request)
  )
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let encoded = try encoder.encode(envelope)
  #expect(try NativeBridgeProtocolCodec.decodeRequest(encoded) == envelope)

  #expect(throws: NativeBridgeProtocolError.nonEmptyCredentialPlaceholder) {
    try modernProtocolStartRequest(
      configuration:
        #"{"outbounds":[{"password":"already-filled","type":"anytls"},{"password":"","type":"tuic","uuid":""}]}"#,
      audience: audience,
      slots: slots
    )
  }
}

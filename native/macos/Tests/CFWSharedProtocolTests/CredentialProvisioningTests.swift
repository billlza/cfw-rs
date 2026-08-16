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

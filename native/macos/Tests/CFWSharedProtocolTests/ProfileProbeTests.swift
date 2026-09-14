import Foundation
import Testing

@testable import CFWSharedProtocol

private func probeRequest(
  configuration: String, proxies: [String] = ["node"], timeoutMS: UInt16 = 5000
) throws -> ProfileDelayTestRequest {
  try ProfileDelayTestRequest(
    audience: CredentialAudience(
      profileID: UUID(), profileDigest: SHA256Digest(hex: String(repeating: "ab", count: 32))),
    configJSON: configuration, credentialSlots: [], proxies: proxies, timeoutMS: timeoutMS)
}

@Test func profileProbeRejectsIntegrationAndUnboundedInputs() throws {
  let valid = #"{"outbounds":[{"type":"direct","tag":"node"}]}"#
  #expect(throws: (any Error).self) {
    try probeRequest(configuration: #"{"outbounds":[],"inbounds":[]}"#)
  }
  #expect(throws: (any Error).self) {
    try probeRequest(configuration: valid, proxies: ["node", "node"])
  }
  #expect(throws: (any Error).self) { try probeRequest(configuration: valid, proxies: []) }
  #expect(throws: (any Error).self) { try probeRequest(configuration: valid, timeoutMS: 10001) }
  #expect(throws: (any Error).self) {
    try ProfileProxyDelay(name: "node", delay: 0, errorKind: nil)
  }
  #expect(throws: (any Error).self) {
    try ProfileProxyDelay(name: "node", delay: 3, errorKind: .timeout)
  }
  #expect(throws: (any Error).self) {
    try ProfileProxyDelay(name: "node", delay: nil, errorKind: nil)
  }
}

@Test func providerProbePreservesItsTargetAndRejectsMalformedStatusPolicies() throws {
  let request = try ProfileDelayTestRequest(
    audience: CredentialAudience(
      profileID: UUID(), profileDigest: SHA256Digest(hex: String(repeating: "ab", count: 32))),
    configJSON: #"{"outbounds":[{"type":"direct","tag":"node"}]}"#, credentialSlots: [],
    proxies: ["node"], timeoutMS: 1200, targetURL: "http://connectivity.example.com/probe",
    expectedStatus: "200-299/304")
  let data = try JSONEncoder().encode(request)
  #expect(try JSONDecoder().decode(ProfileDelayTestRequest.self, from: data) == request)
  for value in ["204/", "600", "299-200", "20", "+20"] {
    #expect(throws: (any Error).self) {
      try ProfileDelayTestRequest.validateTargetURL("https://example.com", expectedStatus: value)
    }
  }
  for target in [
    "file:///etc/hosts", "https://user:pass@example.com", "https://example.com/#fragment",
    "https://example.com:0/",
  ] {
    #expect(throws: (any Error).self) {
      try ProfileDelayTestRequest.validateTargetURL(target, expectedStatus: "204")
    }
  }
}

@Test func profileProbePoliciesPassThroughTheCompleteBridgeEnvelope() throws {
  for target in [nil, "https://connectivity.example.com/generate_204"] as [String?] {
    for status in [nil, "204"] as [String?] {
      let request = try ProfileDelayTestRequest(
        audience: CredentialAudience(
          profileID: UUID(), profileDigest: SHA256Digest(hex: String(repeating: "ab", count: 32))),
        configJSON: #"{"outbounds":[{"type":"direct","tag":"node"}]}"#,
        credentialSlots: [], proxies: ["node"], timeoutMS: 1200,
        targetURL: target, expectedStatus: status)
      let envelope = NativeRequestEnvelope(command: .testProfileDelays(request))
      let encoded = try JSONEncoder().encode(envelope)
      #expect(try NativeBridgeProtocolCodec.decodeRequest(encoded) == envelope)
      var root = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
      var command = try #require(root["command"] as? [String: Any])
      var payload = try #require(command["payload"] as? [String: Any])
      var wire = try #require(payload["request"] as? [String: Any])
      wire["unreviewed_policy"] = true
      payload["request"] = wire
      command["payload"] = payload
      root["command"] = command
      let unknown = try JSONSerialization.data(withJSONObject: root)
      #expect(throws: (any Error).self) { try NativeBridgeProtocolCodec.decodeRequest(unknown) }
    }
  }
}

@Test func profileProbeConsumesTheRustCommandFixture() throws {
  var root = URL(fileURLWithPath: #filePath)
  for _ in 0..<5 { root.deleteLastPathComponent() }
  let bytes = try Data(
    contentsOf: root.appendingPathComponent(
      "contracts/native-bridge-v10/profile-delay-request.json"))
  let envelope = try NativeBridgeProtocolCodec.decodeRequest(bytes)
  guard case .testProfileDelays(let request) = envelope.command else {
    Issue.record("Expected the profile delay command")
    return
  }
  #expect(request.targetURL == "https://connectivity.example.com/generate_204")
  #expect(request.expectedStatus == "204")
  #expect(request.timeoutMS == 1200)
}

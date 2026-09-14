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

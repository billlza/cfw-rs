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

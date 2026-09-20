import CFWSharedProtocol
import Foundation
import Testing

struct TunnelStartupFailureTests {
  private func descriptor(
    generation: UInt64 = 1, epoch: UInt64 = 1,
    installationID: UUID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
  ) throws -> ConfigurationDescriptor {
    try ConfigurationDescriptor(
      slot: .tunnel,
      tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
      credentialAudience: CredentialAudience(
        profileID: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
        profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
      installationID: installationID,
      epoch: epoch, generation: generation, byteCount: 2,
      sha256: SHA256Digest(hex: String(repeating: "ab", count: 32)))
  }

  @Test func expiredTicketSurvivesTheNSErrorSecureCodingBoundary() throws {
    let configuration = try descriptor()
    let error = TunnelStartupFailure.ticketExpiredError(configuration: configuration)
    let data = try NSKeyedArchiver.archivedData(withRootObject: error, requiringSecureCoding: true)
    let decoded = try #require(
      try NSKeyedUnarchiver.unarchivedObject(ofClass: NSError.self, from: data))
    #expect(
      TunnelStartupFailure.matchingFailure(decoded, configuration: configuration)
        == TunnelStartupFailure.ticketExpired)
    #expect(Set(decoded.userInfo.keys) == [NSLocalizedDescriptionKey, "start_context"])
    #expect(data.count < 2_048)
  }

  @Test func identicalConfigurationInAnotherGenerationCannotReuseTheLastError() throws {
    let original = try descriptor()
    let error = TunnelStartupFailure.ticketExpiredError(configuration: original)
    for changed in [
      try descriptor(generation: 2), try descriptor(epoch: 2),
      try descriptor(installationID: UUID()),
    ] {
      #expect(original.identitySHA256 == changed.identitySHA256)
      #expect(TunnelStartupFailure.matchingFailure(error, configuration: changed) == nil)
    }
  }

  @Test func absentForeignAndMalformedErrorsDoNotBecomeRetryEvidence() throws {
    let configuration = try descriptor()
    let valid = TunnelStartupFailure.ticketExpiredError(configuration: configuration)
    let errors: [NSError?] = [
      nil,
      NSError(domain: "unrelated", code: valid.code, userInfo: valid.userInfo),
      NSError(domain: valid.domain, code: 999, userInfo: valid.userInfo),
      NSError(domain: valid.domain, code: valid.code),
      NSError(domain: valid.domain, code: valid.code, userInfo: ["start_context": 1]),
    ]
    for error in errors {
      #expect(TunnelStartupFailure.matchingFailure(error, configuration: configuration) == nil)
    }
  }
}

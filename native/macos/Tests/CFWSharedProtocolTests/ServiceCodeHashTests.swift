import Foundation
import Security
import Testing

@testable import CFWSharedProtocol

@Suite struct ServiceCodeHashTests {
  @Test(arguments: [0, 4, 19, 21, 32, 64])
  func constructorRejectsNonCDHashLengths(_ count: Int) {
    #expect(throws: ServiceCodeHash.ValidationError.self) {
      try ServiceCodeHash(Data(repeating: 0x74, count: count))
    }
  }

  @Test(arguments: ["com.bill.clashformac.proxy-agent", "com.bill.clashformac.global-authority"])
  func reconnectionAfterCurrentOperationCannotRelaxSignerOrBuild(_ identifier: String) throws {
    let base = try CodeIdentityRequirement(
      expectedTeamIdentifier: "YKUPL7Z869", expectedBundleIdentifier: identifier
    ).requirementText
    let hash = try ServiceCodeHash(Data(repeating: 0x42, count: 20))
    var transportPolicy = ServiceConnectionBuildConstraint()
    // The same production policy is used by Proxy and the Host Authority remote.
    // Connections are disposable; the policy belongs to their longer-lived owner.
    var liveConnectionRequirement: String? = transportPolicy.requirement(
      base: base, currentCodeHash: hash, requestingCurrentBuild: false)
    #expect(liveConnectionRequirement == base)
    liveConnectionRequirement = nil  // interrupted observation connection
    liveConnectionRequirement = transportPolicy.requirement(
      base: base, currentCodeHash: hash, requestingCurrentBuild: true)
    let strict = try #require(liveConnectionRequirement)
    #expect(strict == base + " and cdhash H\"" + String(repeating: "42", count: 20) + "\"")
    var parsed: SecRequirement?
    #expect(SecRequirementCreateWithString(strict as CFString, [], &parsed) == errSecSuccess)
    #expect(parsed != nil)
    liveConnectionRequirement = nil  // interrupted prepare/start connection
    for _ in 0..<3 {
      liveConnectionRequirement = transportPolicy.requirement(
        base: base, currentCodeHash: hash, requestingCurrentBuild: false)
      #expect(liveConnectionRequirement == strict)
      #expect(transportPolicy.requiresCurrentBuild)
      liveConnectionRequirement = nil
    }
  }
}

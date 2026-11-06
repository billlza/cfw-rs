import Foundation
@preconcurrency import Security
import Testing

@testable import CFWAppleNetwork

@Suite struct ServiceCodeIdentityReaderTests {
  @Test func overwrittenExecutableKeepsItsAuthenticatedRunningIdentity() throws {
    let fixture = try ServiceIdentityProcessFixture.start()
    defer {
      do { try fixture.close() } catch { Issue.record(error) }
    }
    let pid = fixture.child.processIdentifier
    #expect(
      try ServiceCodeIdentityReader.process(pid, requirement: fixture.requirement)
        == fixture.original.identity)
    try fixture.replaceOnDisk()

    // Control: the exact Security API sequence used before the correction
    // rejects this live process after replacement, despite valid new disk code.
    var oldView: SecCode?
    #expect(
      SecCodeCopyGuestWithAttributes(
        nil, [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary, [], &oldView)
        == errSecSuccess)
    let code = try #require(oldView)
    #expect(
      SecCodeCheckValidity(
        code, [.noNetworkAccess, SecCSFlags(rawValue: kSecCSStrictValidate)],
        fixture.requirement) == errSecCSStaticCodeChanged)
    #expect(throws: CurrentAppServiceBuildError.identityUnavailable) {
      try ServiceCodeIdentityReader.process(pid, requirement: fixture.requirement)
    }
    #expect(
      try ServiceCodeIdentityReader.process(
        pid, requirement: fixture.requirement,
        replacedMetadata: { [fixture.newer, fixture.original] }) == fixture.original.identity)

    let tampered = try ServiceCodeMetadata(
      identity: fixture.original.identity,
      infoPlist: Data(
        String(decoding: fixture.original.infoPlist, as: UTF8.self)
          .replacingOccurrences(of: "50030", with: "50031").utf8))
    let wrongHash = try ServiceCodeMetadata(
      identity: .init(build: 50030, cdHash: Data(repeating: 0x42, count: 20)),
      infoPlist: fixture.original.infoPlist)
    for candidates in [
      [fixture.newer], [tampered], [wrongHash],
      Array(repeating: fixture.original, count: 9),
    ] {
      #expect(throws: CurrentAppServiceBuildError.identityUnavailable) {
        try ServiceCodeIdentityReader.process(
          pid, requirement: fixture.requirement, replacedMetadata: { candidates })
      }
    }
    let otherRequirement = try ServiceIdentityProcessFixture.makeRequirement(
      "org.cfm.tests.another-service")
    #expect(throws: CurrentAppServiceBuildError.identityUnavailable) {
      try ServiceCodeIdentityReader.process(
        pid, requirement: otherRequirement, replacedMetadata: { [fixture.original] })
    }
  }

  @Test func ordinaryIdentityFailuresDoNotEnterTheReplacementPath() throws {
    let fixture = try ServiceIdentityProcessFixture.start()
    defer {
      do { try fixture.close() } catch { Issue.record(error) }
    }
    let other = try ServiceIdentityProcessFixture.makeRequirement("org.cfm.tests.another-service")
    var requestedMetadata = false
    #expect(throws: CurrentAppServiceBuildError.identityUnavailable) {
      try ServiceCodeIdentityReader.process(
        fixture.child.processIdentifier, requirement: other,
        replacedMetadata: {
          requestedMetadata = true
          return [fixture.original]
        })
    }
    #expect(!requestedMetadata)
  }

  @Test func retainedMetadataDescribesExactlyItsComponentAndBuild() throws {
    for service in CurrentAppService.allCases {
      let records = try ServiceBuildMetadataCatalog.metadata(for: service)
      #expect(Set(records.map(\.identity.build)) == [50030, 51004])
      #expect(records.count == 2)
      for record in records {
        let value = try #require(
          try PropertyListSerialization.propertyList(from: record.infoPlist, format: nil)
            as? [String: Any])
        #expect(value["CFBundleVersion"] as? String == String(record.identity.build))
        #expect(
          value["CFBundleIdentifier"] as? String
            == (service == .proxyAgent
              ? "com.bill.clashformac.proxy-agent" : "com.bill.clashformac.global-authority"))
      }
    }
  }
}

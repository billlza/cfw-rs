import CryptoKit
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
          .replacingOccurrences(of: "<string>1</string>", with: "<string>3</string>").utf8))
    let wrongHash = try ServiceCodeMetadata(
      identity: .init(
        build: fixture.original.identity.build, cdHash: Data(repeating: 0x42, count: 20)),
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

  @Test func fixtureProcessesDoNotInheritTestRunnerLoaderOverrides() throws {
    var environment = ProcessInfo.processInfo.environment
    environment["DYLD_INSERT_LIBRARIES"] = "/nonexistent/cfm-test-runner-injection.dylib"
    environment["DYLD_FRAMEWORK_PATH"] = "/nonexistent/cfm-test-runner-frameworks"
    environment["DYLD_LIBRARY_PATH"] = "/nonexistent/cfm-test-runner-libraries"
    environment["SDKROOT"] = "/nonexistent/cfm-test-runner-sdk"
    environment["CODESIGN_ALLOCATE"] = "/nonexistent/cfm-test-runner-signing-helper"
    let fixture = try ServiceIdentityProcessFixture.start(environment: environment)
    defer {
      do { try fixture.close() } catch { Issue.record(error) }
    }
    #expect(
      try ServiceCodeIdentityReader.process(
        fixture.child.processIdentifier, requirement: fixture.requirement)
        == fixture.original.identity)
  }

  @Test func retainedMetadataDescribesExactlyItsComponentAndBuild() throws {
    for service in CurrentAppService.allCases {
      let records = try ServiceBuildMetadataCatalog.metadata(for: service)
      let expected: [String: String] =
        service == .proxyAgent
        ? [
          "6a14f77dd6a743e3bcf45c0d5f9e3ea21404080ba4327a0a96449d372780f397":
            "4e2c99d7617d81e19952e297f99865f833e46c2c",
          "12eef3efb03c1dbfad4859f9040c2fb481a91840c60c52a5a5bee80f6a194bb6":
            "744c3bf96d3b8e46b0d362b2e8aa85f62217e8c6",
        ]
        : [
          "a686f2c89d2696d8f1fd87fa6694688b2d2a20d74afedcbd8844fff7fb6edb81":
            "8f95c6ebb305f010ec4e1bde5093437d2474e14a",
          "4cc1e9b00a750b4b2a0e6ef2cd55b5898413a40c615094f578eb2d639d86a87c":
            "6db4c9697b107d21175019b58b1a1b8a1c763e63",
        ]
      var observed: Set<String> = []
      #expect(records.count == expected.count)
      for record in records {
        let digest = SHA256.hash(data: record.infoPlist).map { String(format: "%02x", $0) }.joined()
        #expect(observed.insert(digest).inserted)
        #expect(
          expected[digest] == record.identity.cdHash.map { String(format: "%02x", $0) }.joined())
        let value = try #require(
          try PropertyListSerialization.propertyList(from: record.infoPlist, format: nil)
            as? [String: Any])
        #expect(value["CFBundleVersion"] as? String == String(record.identity.build))
        #expect(
          value["CFBundleIdentifier"] as? String
            == (service == .proxyAgent
              ? "com.bill.clashformac.proxy-agent" : "com.bill.clashformac.global-authority"))
      }
      #expect(observed == Set(expected.keys))
    }
  }

  @Test func signedBuildTextRequiresACanonicalPositiveInteger() throws {
    let hash = Data(repeating: 1, count: 20)
    #expect(try CurrentAppServiceCodeIdentity(buildText: "1", cdHash: hash).build == 1)
    #expect(
      try CurrentAppServiceCodeIdentity(buildText: String(Int64.max), cdHash: hash).build
        == Int64.max)
    for value in [
      "", "0", "00", "01", "-1", "+1", " 1", "1 ", "1\n", "１", "1.0", "9223372036854775808",
    ] {
      #expect(throws: CurrentAppServiceBuildError.identityUnavailable) {
        try CurrentAppServiceCodeIdentity(buildText: value, cdHash: hash)
      }
    }
  }
}

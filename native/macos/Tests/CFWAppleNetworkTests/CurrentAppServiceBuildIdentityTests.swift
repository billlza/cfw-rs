import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAppleNetwork

@Suite struct CurrentAppServiceBuildIdentityTests {
  @Test func onlyStrictlyOlderVerifiedCodeIsEligibleForHandoff() throws {
    let expected = try CurrentAppServiceCodeIdentity(
      build: 50010, cdHash: Data(repeating: 0x42, count: 20))
    let older = try CurrentAppServiceCodeIdentity(
      build: 50009, cdHash: Data(repeating: 0x41, count: 20))
    let old = CurrentAppServiceBuildObservation(
      registration: .enabled, runningCode: older, expectedCode: expected)
    #expect(!old.isCurrent)
    try old.requireNonConflictingVersion()
    let current = CurrentAppServiceBuildObservation(
      registration: .enabled, runningCode: expected, expectedCode: expected)
    #expect(current.isCurrent)
    for build: Int64 in [50010, 50011] {
      let different = try CurrentAppServiceCodeIdentity(
        build: build, cdHash: Data(repeating: 0x41, count: 20))
      let conflicting = CurrentAppServiceBuildObservation(
        registration: .enabled, runningCode: different, expectedCode: expected)
      #expect(throws: CurrentAppServiceBuildError.conflictingVersion) {
        try conflicting.requireNonConflictingVersion()
      }
    }
  }

  @Test func absenceAndApprovalNeverMeanCurrent() throws {
    let code = try CurrentAppServiceCodeIdentity(
      build: 50010, cdHash: Data(repeating: 0x42, count: 20))
    #expect(
      !CurrentAppServiceBuildObservation(
        registration: .enabled, runningCode: nil, expectedCode: code
      ).isCurrent)
    for status in [CurrentAppServiceStatus.requiresApproval, .notRegistered, .notFound, .unknown] {
      #expect(
        !CurrentAppServiceBuildObservation(
          registration: status, runningCode: code, expectedCode: code
        ).isCurrent)
    }
    #expect(throws: CurrentAppServiceBuildError.identityUnavailable) {
      try CurrentAppServiceCodeIdentity(build: 0, cdHash: code.cdHash)
    }
  }
}

extension CurrentAppServiceBuildIdentityTests {
  @Test func otherLoggedInUsersProxyIsNotTheCurrentUsersDuplicate() throws {
    func process(real: uid_t, effective: uid_t) -> Installed40019KernelProcessIdentity {
      .init(
        processIdentifier: 42, effectiveUserIdentifier: effective,
        realUserIdentifier: real, startSeconds: 1, startMicroseconds: 0)
    }
    #expect(
      try CurrentAppServiceBuildObserver.belongsToServiceScope(
        name: "CFWProxyAgent", kernel: process(real: 501, effective: 501), invokingUID: 501))
    #expect(
      try !CurrentAppServiceBuildObserver.belongsToServiceScope(
        name: "CFWProxyAgent", kernel: process(real: 502, effective: 502), invokingUID: 501))
    #expect(
      try CurrentAppServiceBuildObserver.belongsToServiceScope(
        name: "CFWGlobalAuthority", kernel: process(real: 0, effective: 0), invokingUID: 501))
    #expect(
      try !CurrentAppServiceBuildObserver.belongsToServiceScope(
        name: "CFWGlobalAuthority", kernel: process(real: 501, effective: 501), invokingUID: 501))
    for identity in [process(real: 501, effective: 0), process(real: 0, effective: 501)] {
      #expect(throws: CurrentAppServiceBuildError.identityUnavailable) {
        try CurrentAppServiceBuildObserver.belongsToServiceScope(
          name: "CFWProxyAgent", kernel: identity, invokingUID: 501)
      }
    }
  }
}

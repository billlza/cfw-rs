import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWGlobalAuthority

private final class SequenceConsoleResolver:
  LiveConsoleUserResolving, @unchecked Sendable
{
  private let lock = NSLock()
  private var values: [uid_t?]
  private(set) var callCount = 0

  init(_ values: [uid_t?]) { self.values = values }

  func liveConsoleUID() -> uid_t? {
    lock.withLock {
      callCount += 1
      return values.isEmpty ? nil : values.removeFirst()
    }
  }
}

@Test func exactRoleScopedConnectionsAuthorizeExpectedKernelContexts() throws {
  let policy = GlobalAuthorityPeerPolicy()
  let host = try policy.authorizeRoleScopedConnection(
    role: .host, pid: 42, euid: 501, auditSessionID: 7,
    liveConsoleUID: 501, leaseOwnerUID: nil)
  #expect(host.role == .host)
  #expect(host.euid == 501)
  #expect(host.auditSessionID == 7)

  let proxy = try policy.authorizeRoleScopedConnection(
    role: .proxyAgent, pid: 43, euid: 501, auditSessionID: 7,
    liveConsoleUID: 501, leaseOwnerUID: 501)
  #expect(proxy.role == .proxyAgent)

  let provider = try policy.authorizeRoleScopedConnection(
    role: .provider, pid: 44, euid: 0, auditSessionID: 0,
    liveConsoleUID: nil, leaseOwnerUID: 501)
  #expect(provider.role == .provider)
  #expect(provider.euid == 0)

  #expect(host.connectionIdentityDigest != proxy.connectionIdentityDigest)
  #expect(proxy.connectionIdentityDigest != provider.connectionIdentityDigest)
}

@Test func roleScopedPolicyRejectsEveryInvalidPublicConnectionAttribute() {
  let policy = GlobalAuthorityPeerPolicy()
  let invalidHost: [(pid_t, uid_t, UInt32, uid_t?)] = [
    (0, 501, 7, 501),
    (42, 501, 0, 501),
    (42, 501, UInt32.max, 501),
    (42, 501, 7, nil),
    (42, 501, 7, 502),
  ]
  for (pid, euid, session, console) in invalidHost {
    #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
      try policy.authorizeRoleScopedConnection(
        role: .host, pid: pid, euid: euid,
        auditSessionID: session, liveConsoleUID: console,
        leaseOwnerUID: nil)
    }
  }

  for leaseOwner: uid_t? in [nil, 502] {
    #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
      try policy.authorizeRoleScopedConnection(
        role: .proxyAgent, pid: 42, euid: 501,
        auditSessionID: 7, liveConsoleUID: 501,
        leaseOwnerUID: leaseOwner)
    }
  }

  for (euid, session): (uid_t, UInt32) in [(501, 0), (0, 7)] {
    #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
      try policy.authorizeRoleScopedConnection(
        role: .provider, pid: 42, euid: euid,
        auditSessionID: session, liveConsoleUID: 501,
        leaseOwnerUID: 501)
    }
  }
}

@Test func everyAuthorizationRefreshesThePublicConsoleUser() throws {
  let console = SequenceConsoleResolver([501, 502])
  let authorizer = RoleScopedConnectionPeerAuthorizer(consoleResolver: console)

  let accepted = try authorizer.authorize(
    role: .host, processIdentifier: 42,
    effectiveUserIdentifier: 501, auditSessionIdentifier: 7,
    leaseOwnerUID: nil)
  #expect(accepted.consoleUID == 501)

  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorizer.authorize(
      role: .host, processIdentifier: 42,
      effectiveUserIdentifier: 501, auditSessionIdentifier: 7,
      leaseOwnerUID: nil)
  }
  #expect(console.callCount == 2)
}

@Test func authorizationFailuresExposeOnlyStableRedactedError() {
  let secretMarker = "sensitive-entitlement-or-requirement-marker"
  let error = GlobalAuthorityAuthorizationError.identityRejected
  let bridged = error as NSError

  #expect(String(describing: error) == "global_authority_identity_rejected")
  #expect(bridged.localizedDescription == "global_authority_identity_rejected")
  #expect(!String(describing: error).contains(secretMarker))
  #expect(!bridged.localizedDescription.contains(secretMarker))
}

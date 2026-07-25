import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWGlobalAuthority

private let goodDigest = try! SHA256Digest(hex: String(repeating: "1", count: 64))
private let badDigest = try! SHA256Digest(hex: String(repeating: "f", count: 64))

private func token() -> audit_token_t { audit_token_t() }

private func evidence(
  role: AuthorityRole = .host,
  pid: pid_t = 42,
  euid: uid_t? = nil,
  auditSessionID: UInt32? = nil,
  teamID: String = GlobalAuthorityPeerPolicy.teamID,
  signingID: String? = nil,
  requirementDigest: SHA256Digest? = nil,
  entitlementDigest: SHA256Digest? = nil,
  requirementValidated: Bool = true,
  auditTokenBound: Bool = true,
  adHocSigned: Bool = false,
  debugSigned: Bool = false,
  systemExtensionContext: Bool? = nil
) -> PeerAuthorizationEvidence {
  let rolePolicy = GlobalAuthorityPeerPolicy.policy(for: role)
  let defaultUID: uid_t = role == .provider ? 0 : 501
  let defaultSession: UInt32 = role == .provider ? 0 : 7
  return PeerAuthorizationEvidence(
    auditTokenDigest: goodDigest, pid: pid, euid: euid ?? defaultUID,
    auditSessionID: auditSessionID ?? defaultSession, teamID: teamID,
    signingID: signingID ?? rolePolicy.signingID,
    designatedRequirementDigest: requirementDigest
      ?? rolePolicy.designatedRequirementDigest,
    entitlementDigest: entitlementDigest ?? rolePolicy.entitlementDigest,
    requirementValidated: requirementValidated, auditTokenBound: auditTokenBound,
    adHocSigned: adHocSigned, debugSigned: debugSigned,
    systemExtensionContext: systemExtensionContext ?? (role == .provider))
}

private func authorize(
  _ value: PeerAuthorizationEvidence,
  consoleUID: uid_t? = 501,
  context: TrustedPeerSessionContext = .user(auditSessionID: 7, leaseOwnerUID: nil)
) throws -> PeerIdentity {
  try GlobalAuthorityPeerPolicy().authorize(
    value, liveConsoleUID: consoleUID, context: context)
}
@Test func exactRoleConjunctionAuthorizesOnlyExpectedContexts() throws {
  let host = try authorize(evidence())
  #expect(host.role == .host)
  #expect(host.euid == 501)
  #expect(host.auditSessionID == 7)

  let proxy = try authorize(
    evidence(role: .proxyAgent),
    context: .user(auditSessionID: 7, leaseOwnerUID: 501))
  #expect(proxy.role == .proxyAgent)

  let provider = try authorize(
    evidence(role: .provider), consoleUID: nil,
    context: .providerSystemExtension)
  #expect(provider.role == .provider)
  #expect(provider.euid == 0)
}

@Test func exactCommonConjunctionRejectsEveryChangedPredicate() {
  let rejected = [
    evidence(pid: 0),
    evidence(teamID: "AAAAAAAAAA"),
    evidence(signingID: "com.bill.clashformac.unknown"),
    evidence(requirementDigest: badDigest),
    evidence(entitlementDigest: badDigest),
    evidence(requirementValidated: false),
    evidence(auditTokenBound: false),
    evidence(adHocSigned: true),
    evidence(debugSigned: true),
  ]
  for candidate in rejected {
    #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
      try authorize(candidate)
    }
  }
}

@Test func hostRejectsNoConsoleUIDAndSessionMismatch() {
  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorize(evidence(), consoleUID: nil)
  }
  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorize(
      evidence(auditSessionID: 8),
      context: .user(auditSessionID: 7, leaseOwnerUID: nil))
  }
  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorize(
      evidence(auditSessionID: UInt32.max),
      context: .user(auditSessionID: UInt32.max, leaseOwnerUID: nil))
  }
}
@Test func proxyAgentRejectsFastUserSwitchAndLeaseOwnerMismatch() {
  let proxy = evidence(role: .proxyAgent)
  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorize(
      proxy, consoleUID: 502,
      context: .user(auditSessionID: 7, leaseOwnerUID: 501))
  }
  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorize(
      proxy,
      context: .user(auditSessionID: 7, leaseOwnerUID: 502))
  }
  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorize(
      proxy,
      context: .user(auditSessionID: 7, leaseOwnerUID: nil))
  }
}

@Test func providerRequiresRootSystemExtensionContext() {
  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorize(
      evidence(role: .provider, euid: 501), consoleUID: 501,
      context: .providerSystemExtension)
  }
  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorize(
      evidence(role: .provider, auditSessionID: 7),
      context: .providerSystemExtension)
  }
  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorize(
      evidence(role: .provider, systemExtensionContext: false),
      context: .providerSystemExtension)
  }
  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorize(
      evidence(role: .provider),
      context: .user(auditSessionID: 7, leaseOwnerUID: nil))
  }
}

private struct FixedIdentityResolver: AuditTokenIdentityResolving {
  let value: PeerAuthorizationEvidence
  func resolve(auditToken _: audit_token_t) throws -> PeerAuthorizationEvidence { value }
}

private final class SequenceConsoleResolver: LiveConsoleUserResolving, @unchecked Sendable {
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
@Test func mutatingAuthorizationRefreshesConsoleUIDAndRejectsStaleEvidence() throws {
  let console = SequenceConsoleResolver([501, 502])
  let authorizer = AuditTokenPeerAuthorizer(
    identityResolver: FixedIdentityResolver(value: evidence()),
    consoleResolver: console)

  let accepted = try authorizer.authorizeMutatingPeer(
    auditToken: token(),
    context: .user(auditSessionID: 7, leaseOwnerUID: nil))
  #expect(accepted.consoleUID == 501)

  #expect(throws: GlobalAuthorityAuthorizationError.identityRejected) {
    try authorizer.authorizeMutatingPeer(
      auditToken: token(),
      context: .user(auditSessionID: 7, leaseOwnerUID: nil))
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

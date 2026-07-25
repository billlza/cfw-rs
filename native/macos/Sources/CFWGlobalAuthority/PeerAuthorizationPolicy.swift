import CFWSharedProtocol
import Darwin
import Foundation

import struct CryptoKit.SHA256

public enum GlobalAuthorityAuthorizationError: Error, Equatable, Sendable {
  case identityRejected

  public static let stableCode = "global_authority_identity_rejected"
}

extension GlobalAuthorityAuthorizationError: CustomStringConvertible, LocalizedError {
  public var description: String { Self.stableCode }
  public var errorDescription: String? { Self.stableCode }
}

/// Authority-owned context. It is never decoded from a peer request.
public enum TrustedPeerSessionContext: Equatable, Sendable {
  case user(auditSessionID: UInt32, leaseOwnerUID: uid_t?)
  case providerSystemExtension
}

/// Minimal, redacted evidence emitted by an audit-token-bound resolver.
public struct PeerAuthorizationEvidence: Equatable, Sendable {
  public let auditTokenDigest: SHA256Digest
  public let pid: pid_t
  public let euid: uid_t
  public let auditSessionID: UInt32
  public let teamID: String
  public let signingID: String
  public let designatedRequirementDigest: SHA256Digest
  public let entitlementDigest: SHA256Digest
  public let requirementValidated: Bool
  public let auditTokenBound: Bool
  public let adHocSigned: Bool
  public let debugSigned: Bool
  public let systemExtensionContext: Bool
  public init(
    auditTokenDigest: SHA256Digest, pid: pid_t, euid: uid_t,
    auditSessionID: UInt32, teamID: String, signingID: String,
    designatedRequirementDigest: SHA256Digest, entitlementDigest: SHA256Digest,
    requirementValidated: Bool, auditTokenBound: Bool, adHocSigned: Bool,
    debugSigned: Bool, systemExtensionContext: Bool
  ) {
    self.auditTokenDigest = auditTokenDigest
    self.pid = pid
    self.euid = euid
    self.auditSessionID = auditSessionID
    self.teamID = teamID
    self.signingID = signingID
    self.designatedRequirementDigest = designatedRequirementDigest
    self.entitlementDigest = entitlementDigest
    self.requirementValidated = requirementValidated
    self.auditTokenBound = auditTokenBound
    self.adHocSigned = adHocSigned
    self.debugSigned = debugSigned
    self.systemExtensionContext = systemExtensionContext
  }
}

enum ExactEntitlementValue: Equatable, Sendable {
  case boolean(Bool)
  case strings([String])
}

struct ExactRolePolicy: Sendable {
  let role: AuthorityRole
  let signingID: String
  let designatedRequirement: String
  let designatedRequirementDigest: SHA256Digest
  let requiredEntitlements: [String: ExactEntitlementValue]
  let entitlementDigest: SHA256Digest
}

public struct GlobalAuthorityPeerPolicy: Sendable {
  public static let teamID = "YKUPL7Z869"
  static let authorityClientEntitlement =
    "com.bill.clashformac.global-authority.client"
  static let authorityEngineOwnerEntitlement =
    "com.bill.clashformac.global-authority.engine-owner"

  private let policiesBySigningID: [String: ExactRolePolicy]

  public init() {
    let policies = AuthorityRole.allCases.map(Self.makeRolePolicy)
    policiesBySigningID = Dictionary(uniqueKeysWithValues: policies.map { ($0.signingID, $0) })
  }
  public func authorize(
    _ evidence: PeerAuthorizationEvidence,
    liveConsoleUID: uid_t?,
    context: TrustedPeerSessionContext
  ) throws -> PeerIdentity {
    guard evidence.auditTokenBound, evidence.pid > 0,
      evidence.teamID == Self.teamID,
      !evidence.adHocSigned, !evidence.debugSigned,
      let rolePolicy = policiesBySigningID[evidence.signingID],
      evidence.requirementValidated,
      evidence.designatedRequirementDigest == rolePolicy.designatedRequirementDigest,
      evidence.entitlementDigest == rolePolicy.entitlementDigest
    else { throw GlobalAuthorityAuthorizationError.identityRejected }

    switch rolePolicy.role {
    case .host:
      guard case .user(let sessionID, _) = context,
        let liveConsoleUID,
        evidence.euid == liveConsoleUID,
        validUserSession(evidence.auditSessionID, expected: sessionID)
      else { throw GlobalAuthorityAuthorizationError.identityRejected }
    case .proxyAgent:
      guard case .user(let sessionID, let leaseOwnerUID) = context,
        let liveConsoleUID, let leaseOwnerUID,
        evidence.euid == liveConsoleUID,
        evidence.euid == leaseOwnerUID,
        validUserSession(evidence.auditSessionID, expected: sessionID)
      else { throw GlobalAuthorityAuthorizationError.identityRejected }
    case .provider:
      guard context == .providerSystemExtension,
        evidence.euid == 0, evidence.auditSessionID == 0,
        evidence.systemExtensionContext
      else { throw GlobalAuthorityAuthorizationError.identityRejected }
    }

    return PeerIdentity(
      auditTokenDigest: evidence.auditTokenDigest, pid: evidence.pid,
      euid: evidence.euid, auditSessionID: evidence.auditSessionID,
      teamID: evidence.teamID, signingID: evidence.signingID,
      designatedRequirementDigest: evidence.designatedRequirementDigest,
      entitlementDigest: evidence.entitlementDigest, role: rolePolicy.role,
      consoleUID: liveConsoleUID)
  }

  private func validUserSession(_ actual: UInt32, expected: UInt32) -> Bool {
    actual != 0 && actual != UInt32.max && actual == expected
  }

  static func policy(for role: AuthorityRole) -> ExactRolePolicy {
    makeRolePolicy(role)
  }
  private static func makeRolePolicy(_ role: AuthorityRole) -> ExactRolePolicy {
    let signingID: String
    let entitlements: [String: ExactEntitlementValue]
    switch role {
    case .host:
      signingID = "com.bill.clashformac"
      entitlements = [
        authorityClientEntitlement: .boolean(true),
        "com.apple.security.application-groups": .strings([
          "YKUPL7Z869.group.com.bill.clashformac"
        ]),
        "keychain-access-groups": .strings([
          "YKUPL7Z869.com.bill.clashformac",
          "YKUPL7Z869.com.bill.clashformac.credentials",
        ]),
      ]
    case .proxyAgent:
      signingID = "com.bill.clashformac.proxy-agent"
      entitlements = [
        authorityEngineOwnerEntitlement: .boolean(true),
        "com.apple.security.application-groups": .strings([
          "YKUPL7Z869.group.com.bill.clashformac"
        ]),
        "keychain-access-groups": .strings([
          "YKUPL7Z869.com.bill.clashformac.proxy-agent",
          "YKUPL7Z869.com.bill.clashformac.credentials",
        ]),
      ]
    case .provider:
      signingID = "com.bill.clashformac.packet-tunnel"
      entitlements = [
        authorityEngineOwnerEntitlement: .boolean(true),
        "com.apple.developer.networking.networkextension": .strings([
          "packet-tunnel-provider-systemextension"
        ]),
      ]
    }
    let requirement = developerIDRequirement(signingID: signingID)
    return ExactRolePolicy(
      role: role, signingID: signingID,
      designatedRequirement: requirement,
      designatedRequirementDigest: digest(Data(requirement.utf8)),
      requiredEntitlements: entitlements,
      entitlementDigest: entitlementDigest(entitlements))
  }

  private static func developerIDRequirement(signingID: String) -> String {
    "anchor apple generic and identifier \"\(signingID)\" "
      + "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
      + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
      + "and certificate leaf[subject.OU] = \"\(teamID)\""
  }
  static func entitlementDigest(
    _ values: [String: ExactEntitlementValue]
  ) -> SHA256Digest {
    var data = Data()
    for key in values.keys.sorted() {
      appendLengthPrefixed(Data(key.utf8), to: &data)
      switch values[key]! {
      case .boolean(let value):
        data.append(0x01)
        data.append(value ? 0x01 : 0x00)
      case .strings(let strings):
        data.append(0x02)
        appendUInt32(UInt32(strings.count), to: &data)
        for string in strings { appendLengthPrefixed(Data(string.utf8), to: &data) }
      }
    }
    return digest(data)
  }

  static func digest(_ data: Data) -> SHA256Digest {
    let hex = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    return try! SHA256Digest(hex: hex)
  }

  private static func appendLengthPrefixed(_ value: Data, to data: inout Data) {
    appendUInt32(UInt32(value.count), to: &data)
    data.append(value)
  }

  private static func appendUInt32(_ value: UInt32, to data: inout Data) {
    data.append(UInt8((value >> 24) & 0xff))
    data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
  }
}

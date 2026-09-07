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

/// Validates the live, public Foundation XPC connection attributes after the
/// role-specific listener has already enforced the exact code-signing and
/// entitlement requirement from `GlobalAuthorityConnectionContract`.
///
/// Request bytes cannot select a role, UID, audit session, signing identity, or
/// listener. The returned digest is a local correlation value over only the
/// kernel-populated connection identity; it is not represented as audit-token or
/// entitlement evidence.
public struct GlobalAuthorityPeerPolicy: Sendable {
  public init() {}

  public func authorizeRoleScopedConnection(
    role: AuthorityRole,
    pid: pid_t,
    euid: uid_t,
    auditSessionID: UInt32,
    liveConsoleUID: uid_t?,
    leaseOwnerUID: uid_t?
  ) throws -> PeerIdentity {
    guard pid > 0 else {
      throw GlobalAuthorityAuthorizationError.identityRejected
    }
    switch role {
    case .host:
      guard let liveConsoleUID, euid == liveConsoleUID,
        validUserSession(auditSessionID)
      else { throw GlobalAuthorityAuthorizationError.identityRejected }
    case .proxyAgent:
      guard let liveConsoleUID, let leaseOwnerUID,
        euid == liveConsoleUID, euid == leaseOwnerUID,
        validUserSession(auditSessionID)
      else { throw GlobalAuthorityAuthorizationError.identityRejected }
    case .provider:
      guard euid == 0, auditSessionID == 0 else {
        throw GlobalAuthorityAuthorizationError.identityRejected
      }
    }

    var connectionIdentity = Data(role.rawValue.utf8)
    Self.appendUInt32(UInt32(bitPattern: pid), to: &connectionIdentity)
    Self.appendUInt32(UInt32(euid), to: &connectionIdentity)
    Self.appendUInt32(auditSessionID, to: &connectionIdentity)
    return PeerIdentity(
      connectionIdentityDigest: try Self.digest(connectionIdentity),
      pid: pid,
      euid: euid,
      auditSessionID: auditSessionID,
      role: role,
      consoleUID: liveConsoleUID)
  }

  private func validUserSession(_ value: UInt32) -> Bool {
    value != 0 && value != UInt32.max
  }

  private static func digest(_ data: Data) throws -> SHA256Digest {
    let hex = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    return try SHA256Digest(hex: hex)
  }

  private static func appendUInt32(_ value: UInt32, to data: inout Data) {
    data.append(UInt8((value >> 24) & 0xff))
    data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
  }
}

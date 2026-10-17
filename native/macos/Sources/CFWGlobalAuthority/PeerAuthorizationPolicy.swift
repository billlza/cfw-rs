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

/// What a ProxyAgent's connection or call needs of the lease the Authority
/// holds. Another user's lease keeps the agent out either way.
public enum ProxyAgentLeaseRequirement: Sendable {
  /// The agent's user owns the lease. Every call but one needs it.
  case ownedLease
  /// The agent's user owns the lease, or there is none: enough to connect, and
  /// to ask whether the lease the agent bound still exists once it ended.
  case ownedLeaseOrNone
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
    leaseOwnerUID: uid_t?,
    agentLease: ProxyAgentLeaseRequirement = .ownedLease
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
      guard let liveConsoleUID, euid == liveConsoleUID,
        leaseOwnerUID.map({ $0 == euid }) ?? (agentLease == .ownedLeaseOrNone),
        validUserSession(auditSessionID)
      else { throw GlobalAuthorityAuthorizationError.identityRejected }
    case .provider:
      // launchd can assign a nonzero audit session to a root system extension.
      // It is connection context, not a fixed identifier for the Provider role;
      // the role-specific listener has already verified the signed identity.
      // AU_ASSIGN_ASID (-1) requests allocation and is not an assigned session.
      guard euid == 0, auditSessionID != UInt32.max else {
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

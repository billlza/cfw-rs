import CFWSharedProtocol
import Darwin
import Foundation
@preconcurrency import SystemConfiguration

public protocol LiveConsoleUserResolving: Sendable {
  func liveConsoleUID() -> uid_t?
}

public struct SystemConfigurationLiveConsoleUserResolver:
  LiveConsoleUserResolving, Sendable
{
  public init() {}

  public func liveConsoleUID() -> uid_t? {
    var uid: uid_t = 0
    var gid: gid_t = 0
    guard let name = SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) as String?,
      name != "loginwindow", uid != uid_t.max
    else { return nil }
    return uid
  }
}

/// Revalidates public NSXPC connection attributes against the live user/lease
/// context. The listener has already enforced the exact role code-signing
/// requirement before this object is invoked.
public struct RoleScopedConnectionPeerAuthorizer: Sendable {
  private let consoleResolver: any LiveConsoleUserResolving
  private let policy: GlobalAuthorityPeerPolicy

  public init(
    consoleResolver: any LiveConsoleUserResolving =
      SystemConfigurationLiveConsoleUserResolver(),
    policy: GlobalAuthorityPeerPolicy = GlobalAuthorityPeerPolicy()
  ) {
    self.consoleResolver = consoleResolver
    self.policy = policy
  }

  public func authorize(
    role: AuthorityRole,
    processIdentifier: pid_t,
    effectiveUserIdentifier: uid_t,
    auditSessionIdentifier: UInt32,
    leaseOwnerUID: uid_t?
  ) throws -> PeerIdentity {
    try policy.authorizeRoleScopedConnection(
      role: role,
      pid: processIdentifier,
      euid: effectiveUserIdentifier,
      auditSessionID: auditSessionIdentifier,
      liveConsoleUID: consoleResolver.liveConsoleUID(),
      leaseOwnerUID: leaseOwnerUID)
  }
}

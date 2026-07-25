import CFWSharedProtocol
import Darwin
import Foundation
@preconcurrency import Security
@preconcurrency import SystemConfiguration

import struct CryptoKit.SHA256

public protocol AuthorityPeerAuthorizing: Sendable {
  func authorize(
    auditToken: audit_token_t, leaseOwnerUID: uid_t?
  ) throws -> PeerIdentity
}

public protocol AuditTokenIdentityResolving: Sendable {
  func resolve(auditToken: audit_token_t) throws -> PeerAuthorizationEvidence
}

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

public struct AuditTokenPeerAuthorizer: AuthorityPeerAuthorizing, Sendable {
  private let identityResolver: any AuditTokenIdentityResolving
  private let consoleResolver: any LiveConsoleUserResolving
  private let policy: GlobalAuthorityPeerPolicy

  public init(
    identityResolver: any AuditTokenIdentityResolving = SecurityAuditTokenIdentityResolver(),
    consoleResolver: any LiveConsoleUserResolving =
      SystemConfigurationLiveConsoleUserResolver(),
    policy: GlobalAuthorityPeerPolicy = GlobalAuthorityPeerPolicy()
  ) {
    self.identityResolver = identityResolver
    self.consoleResolver = consoleResolver
    self.policy = policy
  }

  /// Resolves identity once from the kernel token, derives the role context
  /// only from that resolved signing identity, and reuses the exact policy.
  public func authorize(
    auditToken: audit_token_t, leaseOwnerUID: uid_t?
  ) throws -> PeerIdentity {
    let liveConsoleUID = consoleResolver.liveConsoleUID()
    do {
      let evidence = try identityResolver.resolve(auditToken: auditToken)
      let context: TrustedPeerSessionContext
      switch evidence.signingID {
      case GlobalAuthorityPeerPolicy.policy(for: .provider).signingID:
        context = .providerSystemExtension
      case GlobalAuthorityPeerPolicy.policy(for: .host).signingID:
        context = .user(auditSessionID: evidence.auditSessionID, leaseOwnerUID: nil)
      case GlobalAuthorityPeerPolicy.policy(for: .proxyAgent).signingID:
        context = .user(
          auditSessionID: evidence.auditSessionID,
          leaseOwnerUID: leaseOwnerUID)
      default:
        throw GlobalAuthorityAuthorizationError.identityRejected
      }
      return try policy.authorize(
        evidence, liveConsoleUID: liveConsoleUID, context: context)
    } catch {
      throw GlobalAuthorityAuthorizationError.identityRejected
    }
  }

  public func authorizeConnection(
    auditToken: audit_token_t,
    leaseOwnerUID: uid_t?
  ) throws -> PeerIdentity {
    let liveConsoleUID = consoleResolver.liveConsoleUID()
    do {
      let evidence = try identityResolver.resolve(auditToken: auditToken)
      let context: TrustedPeerSessionContext =
        evidence.signingID
          == GlobalAuthorityPeerPolicy.policy(for: .provider).signingID
        ? .providerSystemExtension
        : .user(
          auditSessionID: evidence.auditSessionID,
          leaseOwnerUID: leaseOwnerUID)
      return try policy.authorize(
        evidence, liveConsoleUID: liveConsoleUID, context: context)
    } catch {
      throw GlobalAuthorityAuthorizationError.identityRejected
    }
  }

  /// Re-resolves the public SystemConfiguration console UID on every call.
  public func authorizeMutatingPeer(
    auditToken: audit_token_t,
    context: TrustedPeerSessionContext
  ) throws -> PeerIdentity {
    let liveConsoleUID = consoleResolver.liveConsoleUID()
    do {
      let evidence = try identityResolver.resolve(auditToken: auditToken)
      return try policy.authorize(
        evidence, liveConsoleUID: liveConsoleUID, context: context)
    } catch {
      throw GlobalAuthorityAuthorizationError.identityRejected
    }
  }
}

private enum SecurityIdentityResolutionError: Error {
  case rejected
}

public struct SecurityAuditTokenIdentityResolver:
  AuditTokenIdentityResolving, Sendable
{
  public init() {}

  public func resolve(
    auditToken: audit_token_t
  ) throws -> PeerAuthorizationEvidence {
    let tokenData = withUnsafeBytes(of: auditToken) { Data($0) }
    let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
      let code
    else { throw SecurityIdentityResolutionError.rejected }

    var staticCode: SecStaticCode?
    var information: CFDictionary?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
      let staticCode,
      SecCodeCopySigningInformation(
        staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
        == errSecSuccess,
      let values = information as? [CFString: Any],
      let teamID = values[kSecCodeInfoTeamIdentifier] as? String,
      let signingID = values[kSecCodeInfoIdentifier] as? String,
      let rolePolicy = Self.rolePolicy(signingID: signingID)
    else { throw SecurityIdentityResolutionError.rejected }

    let requirement = try Self.requirementEvidence(
      code: code, staticCode: staticCode, policy: rolePolicy)
    let entitlements = values[kSecCodeInfoEntitlementsDict] as? [String: Any] ?? [:]
    let entitlementDigest = try Self.entitlementDigest(
      entitlements, policy: rolePolicy)
    // CodeDirectory's public ad-hoc bit is not imported by the Swift Security overlay.
    let codeDirectoryAdHocFlag: UInt32 = 0x0000_0002
    let flags = (values[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0
    let debugSigned = Self.exactBoolean(entitlements["get-task-allow"]) == true
    let euid = uid_t(auditToken.val.1)
    let exactProviderEntitlements = entitlementDigest == rolePolicy.entitlementDigest

    return PeerAuthorizationEvidence(
      auditTokenDigest: GlobalAuthorityPeerPolicy.digest(tokenData),
      pid: pid_t(bitPattern: auditToken.val.5), euid: euid,
      auditSessionID: auditToken.val.6, teamID: teamID, signingID: signingID,
      designatedRequirementDigest: requirement.digest,
      entitlementDigest: entitlementDigest,
      requirementValidated: requirement.validated, auditTokenBound: true,
      adHocSigned: flags & codeDirectoryAdHocFlag != 0,
      debugSigned: debugSigned,
      systemExtensionContext: rolePolicy.role == .provider && euid == 0
        && exactProviderEntitlements)
  }
  private static func rolePolicy(signingID: String) -> ExactRolePolicy? {
    AuthorityRole.allCases.map(GlobalAuthorityPeerPolicy.policy).first {
      $0.signingID == signingID
    }
  }

  private static func requirementEvidence(
    code: SecCode, staticCode: SecStaticCode, policy: ExactRolePolicy
  ) throws -> (digest: SHA256Digest, validated: Bool) {
    var expected: SecRequirement?
    guard
      SecRequirementCreateWithString(
        policy.designatedRequirement as CFString, [], &expected) == errSecSuccess,
      let expected
    else { throw SecurityIdentityResolutionError.rejected }

    var actual: SecRequirement?
    guard SecCodeCopyDesignatedRequirement(staticCode, [], &actual) == errSecSuccess,
      let actual,
      let expectedText = requirementText(expected),
      let actualText = requirementText(actual)
    else { throw SecurityIdentityResolutionError.rejected }

    let exact = expectedText == actualText
    let valid = SecCodeCheckValidity(code, [], expected) == errSecSuccess
    return (
      exact
        ? policy.designatedRequirementDigest
        : GlobalAuthorityPeerPolicy.digest(Data(actualText.utf8)),
      exact && valid
    )
  }

  private static func requirementText(_ requirement: SecRequirement) -> String? {
    var text: CFString?
    guard SecRequirementCopyString(requirement, [], &text) == errSecSuccess else {
      return nil
    }
    return text as String?
  }

  private static func entitlementDigest(
    _ actual: [String: Any], policy: ExactRolePolicy
  ) throws -> SHA256Digest {
    var selected: [String: ExactEntitlementValue] = [:]
    for (key, expected) in policy.requiredEntitlements {
      guard let value = actual[key] else {
        return GlobalAuthorityPeerPolicy.entitlementDigest([:])
      }
      switch expected {
      case .boolean:
        guard let boolean = exactBoolean(value) else {
          return GlobalAuthorityPeerPolicy.entitlementDigest([:])
        }
        selected[key] = .boolean(boolean)
      case .strings:
        guard let strings = value as? [String] else {
          return GlobalAuthorityPeerPolicy.entitlementDigest([:])
        }
        selected[key] = .strings(strings)
      }
    }
    return GlobalAuthorityPeerPolicy.entitlementDigest(selected)
  }

  private static func exactBoolean(_ value: Any?) -> Bool? {
    guard let value else { return nil }
    let object = value as CFTypeRef
    guard CFGetTypeID(object) == CFBooleanGetTypeID() else { return nil }
    return (value as? NSNumber)?.boolValue
  }
}

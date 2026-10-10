import Foundation

/// Fixed launchd/XPC identity contract shared by every Global Authority peer.
///
/// Each role uses a separate Mach service so the listener can apply an exact,
/// public code-signing requirement before Foundation constructs a peer
/// connection. This avoids caller-supplied role claims and private audit-token
/// accessors while keeping one Authority process and one durable lease state.
public enum GlobalAuthorityConnectionContract {
  public static let teamIdentifier = "YKUPL7Z869"
  public static let appGroupIdentifier =
    "YKUPL7Z869.group.com.bill.clashformac"
  public static let authoritySigningIdentifier =
    "com.bill.clashformac.global-authority"

  public static let authorityDesignatedRequirement = developerIDRequirement(
    signingIdentifier: authoritySigningIdentifier)

  public static func machServiceName(for role: AuthorityRole) -> String {
    let suffix: String
    switch role {
    case .host: suffix = "host"
    case .proxyAgent: suffix = "proxy-agent"
    case .provider: suffix = "provider"
    }
    return "\(appGroupIdentifier).global-authority.\(suffix)"
  }

  /// Requirement installed on the role-specific Authority listener. A caller
  /// cannot choose its role: each Mach service has its own exact Team/bundle
  /// requirement, with standard Apple entitlements proving the capabilities
  /// that are relevant to that product.
  public static func peerRequirement(for role: AuthorityRole) -> String {
    var additionalRequirements: [String] = []
    switch role {
    case .host:
      additionalRequirements = [
        entitlementRequirement(
          key: "com.apple.security.application-groups",
          string: appGroupIdentifier)
      ]
    case .proxyAgent:
      additionalRequirements = [
        entitlementRequirement(
          key: "com.apple.security.application-groups",
          string: appGroupIdentifier)
      ]
    case .provider:
      additionalRequirements = [
        entitlementRequirement(
          key: "com.apple.developer.networking.networkextension",
          string: "packet-tunnel-provider-systemextension"),
        "entitlement[\"com.apple.security.app-sandbox\"] exists",
      ]
    }
    return
      ([developerIDRequirement(signingIdentifier: signingIdentifier(for: role))]
      + additionalRequirements).joined(separator: " and ")
  }

  public static func signingIdentifier(for role: AuthorityRole) -> String {
    switch role {
    case .host: "com.bill.clashformac"
    case .proxyAgent: "com.bill.clashformac.proxy-agent"
    case .provider: "com.bill.clashformac.packet-tunnel"
    }
  }

  private static func developerIDRequirement(
    signingIdentifier: String
  ) -> String {
    "anchor apple generic and identifier \"\(signingIdentifier)\" "
      + "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
      + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
      + "and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
  }

  private static func entitlementRequirement(
    key: String,
    string: String
  ) -> String {
    "entitlement[\"\(key)\"] = \"\(string)\""
  }
}

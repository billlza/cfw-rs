import CFWSharedProtocol
import Dispatch
import Foundation

public enum GlobalAuthorityProductIdentity {
  public static let teamIdentifier =
    GlobalAuthorityConnectionContract.teamIdentifier
  public static let signingIdentifier =
    GlobalAuthorityConnectionContract.authoritySigningIdentifier
  public static let launchdLabel = signingIdentifier
  public static let executableName = "CFWGlobalAuthority"
  public static let launchDaemonPlistName = "com.bill.clashformac.global-authority.plist"
  public static let machServiceNames = Dictionary(
    uniqueKeysWithValues: AuthorityRole.allCases.map {
      ($0, GlobalAuthorityConnectionContract.machServiceName(for: $0))
    })
  public static let designatedRequirement =
    GlobalAuthorityConnectionContract.authorityDesignatedRequirement
}

/// The product is deliberately only an XPC control-plane host. The authenticated,
/// bounded service delegate is supplied by the service layer; this runtime has no
/// networking, process-launch, plug-in, or arbitrary-file surface.
public enum GlobalAuthorityDaemonRuntime {
  public static func run(
    delegates: [AuthorityRole: any NSXPCListenerDelegate]
  ) -> Never {
    precondition(
      Set(delegates.keys) == Set(AuthorityRole.allCases),
      "Every Global Authority role must have a listener delegate.")
    var listeners: [NSXPCListener] = []
    for role in AuthorityRole.allCases {
      guard let delegate = delegates[role] else { preconditionFailure() }
      let listener = NSXPCListener(
        machServiceName:
          GlobalAuthorityConnectionContract.machServiceName(for: role))
      listener.setConnectionCodeSigningRequirement(
        GlobalAuthorityConnectionContract.peerRequirement(for: role))
      listener.delegate = delegate
      listener.activate()
      listeners.append(listener)
    }
    withExtendedLifetime(listeners) {
      dispatchMain()
    }
  }
}

/// Until the authenticated v1 service is installed, all connections fail closed.
public final class FailClosedGlobalAuthorityListenerDelegate: NSObject,
  NSXPCListenerDelegate
{
  public override init() {}

  public func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection newConnection: NSXPCConnection
  ) -> Bool {
    false
  }
}

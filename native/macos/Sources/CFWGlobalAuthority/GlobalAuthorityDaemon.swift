import Dispatch
import Foundation

public enum GlobalAuthorityProductIdentity {
  public static let teamIdentifier = "YKUPL7Z869"
  public static let signingIdentifier = "com.bill.clashformac.global-authority"
  public static let launchdLabel = signingIdentifier
  public static let executableName = "CFWGlobalAuthority"
  public static let launchDaemonPlistName = "com.bill.clashformac.global-authority.plist"
  public static let machServiceName =
    "YKUPL7Z869.group.com.bill.clashformac.global-authority"
  public static let designatedRequirement =
    "anchor apple generic and identifier \"com.bill.clashformac.global-authority\" "
    + "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
    + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
    + "and certificate leaf[subject.OU] = \"YKUPL7Z869\""
}

/// The product is deliberately only an XPC control-plane host. The authenticated,
/// bounded service delegate is supplied by the service layer; this runtime has no
/// networking, process-launch, plug-in, or arbitrary-file surface.
public enum GlobalAuthorityDaemonRuntime {
  public static func run(delegate: any NSXPCListenerDelegate) -> Never {
    let listener = NSXPCListener(
      machServiceName: GlobalAuthorityProductIdentity.machServiceName)
    listener.delegate = delegate
    listener.resume()
    dispatchMain()
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

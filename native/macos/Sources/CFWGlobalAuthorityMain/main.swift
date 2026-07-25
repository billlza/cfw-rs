import CFWGlobalAuthority
import Foundation

let delegate: any NSXPCListenerDelegate
do {
  delegate = try AuthenticatedGlobalAuthorityListenerDelegate.production()
} catch {
  delegate = FailClosedGlobalAuthorityListenerDelegate()
}

GlobalAuthorityDaemonRuntime.run(delegate: delegate)

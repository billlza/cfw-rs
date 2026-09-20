import CFWGlobalAuthority
import Darwin
import Foundation

do {
  let delegates = try AuthenticatedGlobalAuthorityListenerDelegate.production()
  GlobalAuthorityDaemonRuntime.run(delegates: delegates)
} catch {
  fputs("Global Authority initialization failed.\n", stderr)
  exit(EXIT_FAILURE)
}

import CFWAppleNetwork
import CFWSharedProtocol
import Foundation

enum UnusedSystemProxyStartPreparerError: Error {
  case unexpectedInvocation
}

/// Fails explicitly if a read-only or preflight test accidentally crosses the
/// machine-wide System Proxy authorization boundary.
struct UnusedSystemProxyStartPreparer: SystemProxyStartPreparing {
  func prepareSystemProxyStart(
    configuration: Data,
    descriptor: ConfigurationDescriptor
  ) async throws -> HostPreparedSystemProxyStart {
    _ = configuration
    _ = descriptor
    throw UnusedSystemProxyStartPreparerError.unexpectedInvocation
  }

  func cancelSystemProxyStart(
    _ prepared: HostPreparedSystemProxyStart
  ) async throws {
    prepared.erase()
    throw UnusedSystemProxyStartPreparerError.unexpectedInvocation
  }
}

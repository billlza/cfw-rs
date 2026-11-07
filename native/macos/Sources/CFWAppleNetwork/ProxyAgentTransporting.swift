import CFWSharedProtocol
import Foundation

public protocol ProxyAgentTransporting: Sendable {
  func testProfileProxies(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) async throws
    -> [ProfileProxyDelay]
  func authorizeSystemProxy(restorationOnly: Bool) async throws
  func registrationStatus() async -> ProxyAgentRegistrationStatus
  func ensureRegistered() async throws
  func start(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    authorization: HostPreparedSystemProxyStart
  ) async throws
  func stop(configuration: ConfigurationDescriptor) async throws
  /// Has the ProxyAgent restore the System Proxy settings of the session the
  /// configuration names while its engine keeps running, before its stop.
  /// Only the current build understands this, so it needs that build.
  func restoreSettingsBeforeStop(configuration: ConfigurationDescriptor) async throws
  func snapshot() async throws -> EngineSnapshot
  func validateConfiguration(
    _ configuration: Data,
    descriptor: ConfigurationDescriptor
  ) async throws
}

/// The one-release, read-only compatibility boundary for the installed 40019
/// ProxyAgent. It is deliberately separate from `ProxyAgentTransporting`: the
/// current engine protocol remains strictly v6 and has no legacy fallback.
package protocol Installed40019ProxySnapshotting: Sendable {
  func snapshotInstalled40019ForMigration() async throws -> EngineSnapshot
}

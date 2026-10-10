import Foundation

/// Non-secret, generation-bound failure carried by NetworkExtension's public
/// last-disconnect-error channel before a Provider has a live snapshot service.
/// This is diagnostic evidence only; it never grants authority to start again.
public enum TunnelStartupFailure {
  public static let errorDomain = "com.bill.clashformac.tunnel-start"
  private static let ticketExpiredCode = 1
  private static let contextKey = "start_context"

  public static var ticketExpired: EngineFailure {
    EngineFailure(
      code: NativeBridgeErrorCode.ticketExpired.rawValue,
      message: "The Tunnel start ticket expired while macOS was starting the extension.",
      isRetryable: true)
  }

  public static func ticketExpiredError(configuration: ConfigurationDescriptor) -> NSError {
    NSError(
      domain: errorDomain,
      code: ticketExpiredCode,
      userInfo: [
        NSLocalizedDescriptionKey: ticketExpired.message,
        contextKey: startContext(configuration),
      ])
  }

  /// Ignore an OS-cached error from an older generation or unrelated provider.
  public static func matchingFailure(
    _ error: NSError?, configuration: ConfigurationDescriptor
  ) -> EngineFailure? {
    guard configuration.slot == .tunnel,
      let error, error.domain == errorDomain, error.code == ticketExpiredCode,
      let context = error.userInfo[contextKey] as? String,
      context == startContext(configuration)
    else { return nil }
    return ticketExpired
  }

  private static func startContext(_ configuration: ConfigurationDescriptor) -> String {
    // The configuration digest can stay identical across starts. Include the
    // full lineage so the OS's previous error cannot be attributed to a retry.
    "\(configuration.installationID.uuidString):\(configuration.epoch):\(configuration.generation):\(configuration.identitySHA256.hex)"
  }
}

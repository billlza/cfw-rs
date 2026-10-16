import Foundation

/// Non-secret, generation-bound failure carried by NetworkExtension's public
/// last-disconnect-error channel before a Provider has a live snapshot service.
/// It names only the startup causes the Host must not mistake for Off: an
/// expired ticket (fresh-generation retry evidence), a libbox start that ran
/// past its deadline, and a runtime libbox could not close. It never grants
/// authority to start again.
public enum TunnelStartupFailure {
  public static let errorDomain = "com.bill.clashformac.tunnel-start"
  private static let ticketExpiredCode = 1
  private static let engineStartTimedOutCode = 2
  private static let engineUnclosableCode = 3
  private static let contextKey = "start_context"

  public static var ticketExpired: EngineFailure {
    EngineFailure(
      .startTicketExpired,
      message: "The Tunnel start ticket expired while macOS was starting the extension.")
  }

  /// The Provider's libbox start ran past its deadline and was interrupted.
  public static var engineStartTimedOut: EngineFailure {
    EngineFailure(
      .engineStartTimedOut,
      message: "Packet tunnel engine startup did not finish in time and was interrupted.")
  }

  /// libbox could not close the Provider's runtime, so the Provider ends its
  /// process, and its cleanup cannot be proven.
  public static var engineUnclosable: EngineFailure {
    EngineFailure(.engineUnclosable, message: "Packet tunnel could not close its engine.")
  }

  public static func ticketExpiredError(configuration: ConfigurationDescriptor) -> NSError {
    error(code: ticketExpiredCode, failure: ticketExpired, configuration: configuration)
  }

  public static func engineStartTimedOutError(configuration: ConfigurationDescriptor) -> NSError {
    error(code: engineStartTimedOutCode, failure: engineStartTimedOut, configuration: configuration)
  }

  public static func engineUnclosableError(configuration: ConfigurationDescriptor) -> NSError {
    error(code: engineUnclosableCode, failure: engineUnclosable, configuration: configuration)
  }

  /// Ignore an OS-cached error from an older generation or unrelated provider.
  public static func matchingFailure(
    _ error: NSError?, configuration: ConfigurationDescriptor
  ) -> EngineFailure? {
    guard configuration.slot == .tunnel,
      let error, error.domain == errorDomain,
      let context = error.userInfo[contextKey] as? String,
      context == startContext(configuration)
    else { return nil }
    switch error.code {
    case ticketExpiredCode: return ticketExpired
    case engineStartTimedOutCode: return engineStartTimedOut
    case engineUnclosableCode: return engineUnclosable
    default: return nil
    }
  }

  private static func error(
    code: Int, failure: EngineFailure, configuration: ConfigurationDescriptor
  ) -> NSError {
    NSError(
      domain: errorDomain,
      code: code,
      userInfo: [
        NSLocalizedDescriptionKey: failure.message,
        contextKey: startContext(configuration),
      ])
  }

  private static func startContext(_ configuration: ConfigurationDescriptor) -> String {
    // The configuration digest can stay identical across starts. Include the
    // full lineage so the OS's previous error cannot be attributed to a retry.
    "\(configuration.installationID.uuidString):\(configuration.epoch):\(configuration.generation):\(configuration.identitySHA256.hex)"
  }
}

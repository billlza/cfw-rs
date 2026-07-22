import Foundation

@objc public protocol CFWProxyAgentXPCProtocol {
  /// Executes one versioned command envelope. A malformed envelope is returned
  /// as an NSError because it cannot be safely correlated to a trusted request
  /// identifier. Domain failures use a typed ResponseEnvelope instead.
  func execute(
    _ request: Data,
    withReply reply: @escaping (Data?, NSError?) -> Void
  )

  /// Validates one bounded, fully injected configuration in the signed
  /// ProxyAgent's source-built libbox without starting a listener or runtime.
  /// The request is a versioned NativeCommand carrying the exact descriptor;
  /// configuration bytes remain a separate XPC Data argument to avoid base64
  /// expansion and additional secret-bearing JSON copies.
  func validateConfiguration(
    _ configuration: Data,
    request: Data,
    withReply reply: @escaping (Data?, NSError?) -> Void
  )
}

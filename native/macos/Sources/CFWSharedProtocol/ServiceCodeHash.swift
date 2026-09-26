import Foundation

/// A CodeDirectory identity obtained from verified signing information. Apple
/// CDHashes are 20 bytes, including truncated SHA-256 CodeDirectory identities.
/// This value can only strengthen the client's existing signer/identifier rule.
public struct ServiceCodeHash: Equatable, Sendable {
  public let bytes: Data

  public enum ValidationError: Error { case invalidLength }

  public init(_ bytes: Data) throws {
    guard bytes.count == 20 else { throw ValidationError.invalidLength }
    self.bytes = bytes
  }

  package func constraining(_ requirement: String) -> String {
    requirement + " and cdhash H\"\(bytes.map { String(format: "%02x", $0) }.joined())\""
  }
}

/// Kept by the transport, not its disposable connection. Once this Host has
/// requested current code, an interruption cannot reopen a broader connection.
package struct ServiceConnectionBuildConstraint: Sendable {
  package private(set) var requiresCurrentBuild = false
  package init() {}

  package mutating func select(requestingCurrentBuild: Bool) -> Bool {
    requiresCurrentBuild = requiresCurrentBuild || requestingCurrentBuild
    return requiresCurrentBuild
  }

  package mutating func requirement(
    base: String, currentCodeHash: ServiceCodeHash, requestingCurrentBuild: Bool
  ) -> String {
    select(requestingCurrentBuild: requestingCurrentBuild)
      ? currentCodeHash.constraining(base) : base
  }
}

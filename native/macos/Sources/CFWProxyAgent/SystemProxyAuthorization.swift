import Foundation
import OSLog
import Security
import SystemConfiguration

/// One process-owned authorization reference, scoped to network preferences.
/// User interaction happens only in the explicit authorization RPC, before an
/// Authority lease or data plane exists. Every later transaction checks rights
/// without interaction, so cleanup cannot block on an authentication dialog.
final class SystemProxyAuthorizationSession: @unchecked Sendable {
  private static let logger = Logger(
    subsystem: "com.bill.clashformac", category: "system-proxy-authorization")
  // A synchronous preferences transaction keeps the reference alive while its
  // write boundary re-enters verify(). No lock is shared with the engine queue.
  private let lock = NSRecursiveLock()
  private let operations: SCPreferencesAuthorizationOperations
  private var reference: AuthorizationRef?

  init(operations: SCPreferencesAuthorizationOperations) {
    self.operations = operations
  }

  deinit {
    guard let reference else { return }
    let status = operations.freeAuthorization(reference, [])
    if status != errAuthorizationSuccess {
      Self.logger.fault("Authorization reference release failed: \(status, privacy: .public)")
    }
  }

  func authorize() throws {
    try lock.withLock { _ = try requireRights(interactionAllowed: true) }
  }

  func verify() throws {
    try lock.withLock { _ = try requireRights(interactionAllowed: false) }
  }

  func withPreferences<T>(_ operation: (SCPreferences) throws -> T) throws -> T {
    try lock.withLock {
      // A reference is sufficient for read-only observations. Rights are checked
      // before writes, so a no-op recovery does not need a new user interaction.
      let reference = try ensureReference()
      guard let preferences = operations.createPreferences(reference) else {
        throw SystemProxyPreferencesError.preferencesUnavailable
      }
      return try operation(preferences)
    }
  }

  func close() throws {
    try lock.withLock {
      guard let reference else { return }
      self.reference = nil
      let status = operations.freeAuthorization(reference, [])
      guard status == errAuthorizationSuccess else {
        throw SystemProxyPreferencesError.authorizationReleaseFailed(
          code: status, originalError: nil)
      }
    }
  }

  private func requireRights(interactionAllowed: Bool) throws -> AuthorizationRef {
    let current = try ensureReference()
    let status = operations.copyRights(current, interactionAllowed)
    switch status {
    case errAuthorizationSuccess:
      return current
    case errAuthorizationDenied, errAuthorizationCanceled, errAuthorizationInteractionNotAllowed:
      throw SystemProxyPreferencesError.authorizationDenied(status)
    default:
      throw SystemProxyPreferencesError.authorizationRequestFailed(status)
    }
  }

  private func ensureReference() throws -> AuthorizationRef {
    if let reference {
      return reference
    } else {
      let creation = operations.createAuthorization()
      guard creation.status == errAuthorizationSuccess else {
        throw SystemProxyPreferencesError.authorizationCreationFailed(creation.status)
      }
      guard let created = creation.reference else {
        throw SystemProxyPreferencesError.authorizationReferenceUnavailable
      }
      reference = created
      return created
    }
  }
}

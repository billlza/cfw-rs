import CFWSharedProtocol
import Foundation
import LocalAuthentication
import Synchronization

protocol InstallationRecoveryAuthenticating: Sendable {
  func authenticate() async throws
}

/// A fresh context for each explicit recovery. No reusable authentication
/// result or caller-supplied authorization flag crosses the Host boundary.
struct DeviceOwnerRecoveryAuthenticator: InstallationRecoveryAuthenticating {
  func authenticate() async throws {
    let evaluation = RecoveryAuthenticationEvaluation()
    defer { evaluation.invalidate() }
    try await withTaskCancellationHandler {
      try Task.checkCancellation()
      do {
        try await withCheckedThrowingContinuation {
          (continuation: CheckedContinuation<Void, Error>) in
          evaluation.begin { success, error in
            if success {
              continuation.resume()
            } else {
              continuation.resume(throwing: Self.failure(error))
            }
          }
        }
      } catch {
        try Task.checkCancellation()
        throw error
      }
      try Task.checkCancellation()
    } onCancel: {
      evaluation.invalidate()
    }
  }

  static func failure(_ error: Error?) -> NativeBridgeExecutionError {
    guard let error = error as? LAError else {
      return .failure(.internal, "System authentication failed without a recognized result.")
    }
    switch error.code {
    case .userCancel, .userFallback, .authenticationFailed:
      return .failure(.permissionDenied, "Installation identity recovery was not authorized.")
    case .appCancel, .systemCancel:
      return .failure(.approvalDenied, "System authentication was interrupted.")
    case .notInteractive, .passcodeNotSet, .biometryNotAvailable, .biometryNotEnrolled,
      .biometryLockout:
      return .failure(.unavailable, "System authentication is unavailable for this session.")
    default:
      return .failure(.internal, "System authentication could not complete.")
    }
  }

}

/// Serializes the context's evaluation and invalidation, including cancellation
/// from another executor. Each instance admits only one evaluation.
private final class RecoveryAuthenticationEvaluation: Sendable {
  private let context = Mutex(LAContext())

  func begin(_ reply: @escaping @Sendable (Bool, Error?) -> Void) {
    context.withLock {
      $0.evaluatePolicy(
        .deviceOwnerAuthentication,
        localizedReason: "Recover Clash for Mac's installation identity for this macOS account.",
        reply: reply)
    }
  }

  func invalidate() { context.withLock { $0.invalidate() } }
}

extension NativeBridgeCoordinator {
  func authorizeInstallationRecovery() async throws -> InstallationRecoveryState {
    let operation = try beginOperation()
    defer { endOperation(operation) }
    guard let before = try await installationRecoveryBoundary() else {
      return InstallationRecoveryState(identity: nil)
    }
    try await recoveryAuthenticator.authenticate()
    try Task.checkCancellation()
    let after = try await installationRecoveryBoundary()
    guard after == before else {
      throw NativeBridgeExecutionError.failure(
        .staleOperation, "Installation identity or console ownership changed during authentication."
      )
    }
    return InstallationRecoveryState(identity: after)
  }

  private func installationRecoveryBoundary() async throws -> InstallationRecoveryIdentity? {
    try await requireCurrentServiceBuilds(allowHandoff: false)
    guard try await queryStatus() == .off else {
      throw NativeBridgeExecutionError.failure(
        .busy, "Stop the network engine before recovering the installation identity.")
    }
    try await requireCurrentMaintenanceOwnersOff(
      for: servicePair(), requireAuthorityProof: true)
    guard let identity = try await engineLease.installationRecoveryIdentity().identity else {
      return nil
    }
    try identity.validateAuthorityV1()
    guard identity.consoleUID == geteuid() else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected, "Only the current console account may recover its installation identity."
      )
    }
    return identity
  }
}

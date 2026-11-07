import Foundation
@preconcurrency import SystemExtensions

public protocol SystemExtensionInstalling: Sendable {
  func install() async throws -> SystemExtensionInstallResult
  /// Waits, within a bounded time, for the terminal callback of the submitted
  /// request that is waiting for the person's approval. It neither takes the
  /// request over nor consumes its result, which stays for the next
  /// `install()`.
  func awaitApprovalResolution() async throws -> SystemExtensionApprovalWait
  /// Abandons only local wait/request identity. Public SystemExtensions API
  /// does not provide a way to withdraw a submitted activation request; its
  /// eventual callback is ignored and cannot affect a newer request.
  func cancelInstallationWait()
}

/// Uses only the public SystemExtensions API. The host supplies a callback so
/// it can surface the OS approval state without treating approval as success.
public final class OSSystemExtensionInstaller: NSObject, SystemExtensionInstalling,
  OSSystemExtensionRequestDelegate, @unchecked Sendable
{
  public typealias ApprovalHandler = @Sendable () -> Void

  private let extensionIdentifier: String
  private let approvalHandler: ApprovalHandler
  private let requestDeadline: CallbackDeadlineScheduler
  private let approvalWaitDeadline: CallbackDeadlineScheduler
  private let continuationGate =
    IdentityBoundContinuation<OSSystemExtensionRequest, SystemExtensionInstallResult>()

  /// `approvalWaitTimeout` bounds one wait for the person's approval inside
  /// the bridge's 300-second authorization budget.
  public init(
    extensionIdentifier: String,
    approvalHandler: @escaping ApprovalHandler,
    requestTimeout: Duration = .seconds(10),
    approvalWaitTimeout: Duration = .seconds(270)
  ) {
    self.extensionIdentifier = extensionIdentifier
    self.approvalHandler = approvalHandler
    requestDeadline = CallbackDeadlineScheduler(timeout: requestTimeout)
    approvalWaitDeadline = CallbackDeadlineScheduler(timeout: approvalWaitTimeout)
  }

  public func install() async throws -> SystemExtensionInstallResult {
    try Task.checkCancellation()
    let request = OSSystemExtensionRequest.activationRequest(
      forExtensionWithIdentifier: extensionIdentifier,
      queue: .main
    )
    let waitID = UUID()
    var cancelDeadline: CallbackDeadlineScheduler.Cancel?
    defer { cancelDeadline?() }
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        guard !Task.isCancelled else {
          continuation.resume(throwing: CancellationError())
          return
        }
        let action = continuationGate.install(
          request: request,
          waitID: waitID,
          continuation: continuation
        )
        guard action != .rejected else {
          continuation.resume(throwing: AppleNetworkError.installationAlreadyInProgress)
          return
        }
        guard action != .retirementCapacityExceeded else {
          continuation.resume(
            throwing: AppleNetworkError.systemExtensionRequestCapacityExceeded
          )
          return
        }
        guard action != .completed else { return }

        cancelDeadline = requestDeadline.schedule {
          self.continuationGate.finishWaitKeepingRequest(
            waitID: waitID,
            result: .failure(AppleNetworkError.systemExtensionInstallationTimedOut)
          )
        }
        guard action == .submit else { return }
        guard continuationGate.beginSubmission(request: request, waitID: waitID) else {
          return
        }

        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
      }
    } onCancel: {
      cancelWaitingTask(waitID)
    }
  }

  public func cancelInstallationWait() {
    continuationGate.cancelActiveWait()
  }

  public func awaitApprovalResolution() async throws -> SystemExtensionApprovalWait {
    try Task.checkCancellation()
    let observerID = UUID()
    var cancelDeadline: CallbackDeadlineScheduler.Cancel?
    defer { cancelDeadline?() }
    let observation = await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        continuationGate.observeTerminal(observerID: observerID, continuation: continuation)
        cancelDeadline = approvalWaitDeadline.schedule {
          self.continuationGate.finishObservation(observerID: observerID)
        }
      }
    } onCancel: {
      continuationGate.finishObservation(observerID: observerID)
    }
    try Task.checkCancellation()
    switch observation {
    case .terminalArrived: return .resolved
    case .stillPending: return .stillAwaiting
    case .noActiveRequest: return .noPendingRequest
    case .alreadyObserved: throw AppleNetworkError.installationAlreadyInProgress
    }
  }

  public func request(
    _ request: OSSystemExtensionRequest,
    didFinishWithResult result: OSSystemExtensionRequest.Result
  ) {
    let mapped: SystemExtensionInstallResult
    switch result {
    case .completed:
      mapped = .completed
    case .willCompleteAfterReboot:
      mapped = .requiresRestart
    @unknown default:
      finish(
        request,
        .failure(
          AppleNetworkError.unknownSystemExtensionResult(result.rawValue)
        )
      )
      return
    }
    finish(request, .success(mapped))
  }

  public func request(
    _ request: OSSystemExtensionRequest,
    didFailWithError error: Error
  ) {
    let failure = NetworkExtensionOperationFailure(error)
    finish(
      request,
      .failure(
        AppleNetworkError.systemExtensionInstallationFailed(
          domain: failure.domain,
          code: failure.code,
          message: failure.diagnostic
        )
      )
    )
  }

  public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
    if continuationGate.completeWaitKeepingRequest(
      request: request,
      value: .awaitingApproval
    ) {
      approvalHandler()
    }
  }

  public func request(
    _ request: OSSystemExtensionRequest,
    actionForReplacingExtension existing: OSSystemExtensionProperties,
    withExtension extension: OSSystemExtensionProperties
  ) -> OSSystemExtensionRequest.ReplacementAction {
    Self.replacementAction(
      existingBundleVersion: existing.bundleVersion,
      candidateBundleVersion: `extension`.bundleVersion
    )
  }

  static func replacementAction(
    existingBundleVersion: String,
    candidateBundleVersion: String
  ) -> OSSystemExtensionRequest.ReplacementAction {
    guard
      let existing = canonicalReleaseBundleVersion(existingBundleVersion),
      let candidate = canonicalReleaseBundleVersion(candidateBundleVersion),
      candidate > existing
    else {
      return .cancel
    }
    return .replace
  }

  /// Release builds use the repository-wide canonical `CFBundleVersion`
  /// contract: one positive signed-64-bit base-10 integer, with no leading zero. Foundation's
  /// numeric string comparison orders malformed/suffixed values such as `abc`
  /// or `42.8b1`, so it must not decide a privileged extension replacement.
  private static func canonicalReleaseBundleVersion(_ value: String) -> Int64? {
    guard !value.isEmpty, value.utf8.count <= 19, value.utf8.first != 48,
      value.utf8.allSatisfy({ (48...57).contains($0) }),
      let parsed = Int64(value), parsed > 0
    else {
      return nil
    }
    return parsed
  }

  private func finish(
    _ request: OSSystemExtensionRequest,
    _ result: Result<SystemExtensionInstallResult, Error>
  ) {
    continuationGate.finish(request: request, result: result)
  }

  private func cancelWaitingTask(_ waitID: UUID) {
    continuationGate.finishWaitKeepingRequest(
      waitID: waitID,
      result: .failure(CancellationError())
    )
  }
}

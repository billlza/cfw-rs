import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension

private struct TunnelManagerList: @unchecked Sendable {
  let values: [NETunnelProviderManager]
}

// Read-only manager I/O and bounded callbacks. Transaction state remains private
// to NetworkExtensionHostBridge; all methods retain its actor isolation.
extension NetworkExtensionHostBridge {
  func providerSnapshot(_ manager: NETunnelProviderManager) async throws -> EngineSnapshot {
    guard let session = manager.connection as? NETunnelProviderSession else {
      throw AppleNetworkError.providerDidNotRespond
    }
    let command = try NativeCommand(kind: .snapshot)
    let request = RequestEnvelope(command: command)
    let requestData = try ProtocolCodec.encode(request)
    let responseData: Data = try await awaitBoundedCallback(
      deadline: callbackDeadline,
      timeoutError: AppleNetworkError.providerMessageTimedOut
    ) { finish in
      do {
        try session.sendProviderMessage(requestData) { data in
          guard let data else {
            finish(.failure(AppleNetworkError.providerDidNotRespond))
            return
          }
          finish(.success(data))
        }
      } catch {
        finish(
          .failure(
            AppleNetworkError.providerMessageFailed(error.localizedDescription)
          )
        )
      }
    }
    let response = try ProtocolCodec.decodeResponse(responseData)
    guard response.requestID == request.requestID else {
      throw AppleNetworkError.providerResponseMismatch
    }
    if let failure = response.failure {
      throw AppleNetworkError.providerFailure(failure)
    }
    guard let providerSnapshot = response.result?.snapshot,
      providerSnapshot.configuration == (try manager.configurationDescriptor()),
      providerSnapshot.state.kind == .tunnelActive
        || providerSnapshot.state.kind == .failed
    else {
      throw AppleNetworkError.providerResponseMismatch
    }
    return providerSnapshot
  }

  func soleManager() async throws -> NETunnelProviderManager? {
    let managerList: TunnelManagerList = try await awaitBoundedCallback(
      deadline: callbackDeadline,
      timeoutError: AppleNetworkError.preferenceLoadTimedOut
    ) { finish in
      NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if let error {
          finish(
            .failure(
              AppleNetworkError.preferenceLoadFailed(
                NetworkExtensionOperationFailure(error)
              )
            )
          )
        } else {
          finish(.success(TunnelManagerList(values: managers ?? [])))
        }
      }
    }
    return try Self.classifyManagerInventory(managerList.values)
  }

  static func classifyManagerInventory(
    _ managers: [NETunnelProviderManager]
  ) throws -> NETunnelProviderManager? {
    guard managers.count <= 1 else {
      throw AppleNetworkError.duplicateTunnelManagers(managers.count)
    }
    return managers.first
  }

  func reload(_ manager: NETunnelProviderManager) async throws {
    let _: Void = try await awaitBoundedCallback(
      deadline: callbackDeadline,
      timeoutError: AppleNetworkError.preferenceLoadTimedOut
    ) { finish in
      manager.loadFromPreferences { error in
        if let error {
          finish(
            .failure(
              AppleNetworkError.preferenceLoadFailed(
                NetworkExtensionOperationFailure(error)
              )
            )
          )
        } else {
          finish(.success(()))
        }
      }
    }
  }

  func awaitPreferenceMutationCallback(
    _ wait: PreferenceSaveWait,
    submission: @escaping @Sendable (@escaping @Sendable (Error?) -> Void) -> Void
  ) async throws {
    var cancelDeadline: CallbackDeadlineScheduler.Cancel?
    defer { cancelDeadline?() }
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        wait.install(continuation)
        guard !Task.isCancelled else {
          wait.cancel()
          return
        }
        cancelDeadline = callbackDeadline.schedule { wait.timeout() }
        guard wait.beginSubmission() else { return }
        submission { error in wait.finish(error) }
      }
    } onCancel: {
      wait.cancel()
    }
  }

  func managedConnectionStatus(
    _ manager: NETunnelProviderManager
  ) throws -> ManagedTunnelConnectionStatus {
    switch manager.connection.status {
    case .invalid: return .invalid
    case .disconnected: return .disconnected
    case .connecting: return .connecting
    case .connected: return .connected
    case .reasserting: return .reasserting
    case .disconnecting: return .disconnecting
    @unknown default:
      throw AppleNetworkError.cleanupUnproven(
        "NetworkExtension returned an unknown status during preference reconciliation."
      )
    }
  }
}

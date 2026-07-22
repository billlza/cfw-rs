import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
@preconcurrency import SystemExtensions

private struct TunnelManagerList: @unchecked Sendable {
  let values: [NETunnelProviderManager]
}

final class ProviderResponseGate: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Data, Error>?
  private var completedResult: Result<Data, Error>?

  func install(_ continuation: CheckedContinuation<Data, Error>) {
    lock.lock()
    if let completedResult {
      lock.unlock()
      continuation.resume(with: completedResult)
      return
    }
    precondition(self.continuation == nil, "Provider response continuation installed twice")
    self.continuation = continuation
    lock.unlock()
  }

  func finish(_ result: Result<Data, Error>) {
    lock.lock()
    guard completedResult == nil else {
      lock.unlock()
      return
    }
    completedResult = result
    let continuation = continuation
    self.continuation = nil
    lock.unlock()
    continuation?.resume(with: result)
  }
}

final class IdentityBoundContinuation<Request: AnyObject, Value: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private var activeRequest: Request?
  private var continuation: CheckedContinuation<Value, Error>?

  func install(
    request: Request,
    continuation: CheckedContinuation<Value, Error>
  ) -> Bool {
    lock.lock()
    guard activeRequest == nil else {
      lock.unlock()
      return false
    }
    activeRequest = request
    self.continuation = continuation
    lock.unlock()
    return true
  }

  func finish(request: Request, result: Result<Value, Error>) {
    lock.lock()
    guard activeRequest === request else {
      lock.unlock()
      return
    }
    activeRequest = nil
    let continuation = continuation
    self.continuation = nil
    lock.unlock()
    continuation?.resume(with: result)
  }

  func cancelWait(request: Request) {
    lock.lock()
    guard activeRequest === request else {
      lock.unlock()
      return
    }
    let continuation = continuation
    self.continuation = nil
    lock.unlock()
    continuation?.resume(throwing: CancellationError())
  }

  /// Completes only the caller's wait while retaining the operating-system
  /// request identity until its terminal delegate callback arrives.
  func completeWaitKeepingRequest(request: Request, value: Value) {
    lock.lock()
    guard activeRequest === request else {
      lock.unlock()
      return
    }
    let continuation = continuation
    self.continuation = nil
    lock.unlock()
    continuation?.resume(returning: value)
  }

  func cancelActiveWait() {
    lock.lock()
    let continuation = continuation
    self.continuation = nil
    lock.unlock()
    continuation?.resume(throwing: CancellationError())
  }

  func isAwaited(request: Request) -> Bool {
    lock.lock()
    let result = activeRequest === request && continuation != nil
    lock.unlock()
    return result
  }
}

public enum SystemExtensionInstallResult: Equatable, Sendable {
  case completed
  case awaitingApproval
  case requiresRestart
}

public enum AppleNetworkError: Error, Equatable, Sendable {
  case installationAlreadyInProgress
  case unknownSystemExtensionResult(Int)
  case systemExtensionInstallationFailed(code: Int, message: String)
  case preferenceLoadFailed(String)
  case preferenceSaveFailed(String)
  case duplicateTunnelManagers(Int)
  case invalidConfigurationSlot
  case systemExtensionStateTransportFailed(String)
  case systemExtensionStateTransportTimedOut
  case tunnelStartFailed(String)
  case tunnelStartCleanupFailed(start: String, cleanup: String)
  case tunnelStopTimedOut
  case staleStopRequest
  case providerDidNotRespond
  case providerMessageTimedOut
  case providerMessageFailed(String)
  case providerResponseMismatch
  case providerFailure(EngineFailure)
}

public protocol SystemExtensionInstalling: Sendable {
  func install() async throws -> SystemExtensionInstallResult
  /// Cancels only the caller's local wait. Public SystemExtensions API does
  /// not provide a way to withdraw a submitted activation request.
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
  private let continuationGate =
    IdentityBoundContinuation<OSSystemExtensionRequest, SystemExtensionInstallResult>()

  public init(
    extensionIdentifier: String,
    approvalHandler: @escaping ApprovalHandler
  ) {
    self.extensionIdentifier = extensionIdentifier
    self.approvalHandler = approvalHandler
  }

  public func install() async throws -> SystemExtensionInstallResult {
    try Task.checkCancellation()
    let request = OSSystemExtensionRequest.activationRequest(
      forExtensionWithIdentifier: extensionIdentifier,
      queue: .main
    )
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        guard !Task.isCancelled else {
          continuation.resume(throwing: CancellationError())
          return
        }
        guard continuationGate.install(request: request, continuation: continuation) else {
          continuation.resume(throwing: AppleNetworkError.installationAlreadyInProgress)
          return
        }
        if Task.isCancelled {
          continuationGate.finish(request: request, result: .failure(CancellationError()))
          return
        }

        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
      }
    } onCancel: {
      cancelWaitingTask(request)
    }
  }

  public func cancelInstallationWait() {
    continuationGate.cancelActiveWait()
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
    let nsError = error as NSError
    finish(
      request,
      .failure(
        AppleNetworkError.systemExtensionInstallationFailed(
          code: nsError.code,
          message: nsError.localizedDescription
        )
      )
    )
  }

  public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
    if continuationGate.isAwaited(request: request) {
      approvalHandler()
      continuationGate.completeWaitKeepingRequest(
        request: request,
        value: .awaitingApproval
      )
    }
  }

  public func request(
    _ request: OSSystemExtensionRequest,
    actionForReplacingExtension existing: OSSystemExtensionProperties,
    withExtension extension: OSSystemExtensionProperties
  ) -> OSSystemExtensionRequest.ReplacementAction {
    let versionOrder = `extension`.bundleVersion.compare(
      existing.bundleVersion,
      options: .numeric
    )
    return versionOrder == .orderedAscending ? .cancel : .replace
  }

  private func finish(
    _ request: OSSystemExtensionRequest,
    _ result: Result<SystemExtensionInstallResult, Error>
  ) {
    continuationGate.finish(request: request, result: result)
  }

  private func cancelWaitingTask(_ request: OSSystemExtensionRequest) {
    continuationGate.cancelWait(request: request)
  }
}

public protocol TunnelHostBridging: Sendable {
  func installTunnel() async throws -> SystemExtensionInstallResult
  func cancelTunnelInstallationWait() async
  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) async throws
  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) async throws
  func snapshot() async throws -> EngineSnapshot
  func hasManagedTunnelConfiguration() async throws -> Bool
  func managedTunnelConfiguration() async throws -> ConfigurationDescriptor?
}

/// Serializes all NETunnelProviderManager mutations in one actor. It never
/// reports TunnelActive from NEVPNStatus alone: the connected provider must
/// return a typed snapshot whose configuration digest matches preferences.
public actor NetworkExtensionHostBridge: TunnelHostBridging {
  private let providerBundleIdentifier: String
  private let installer: any SystemExtensionInstalling

  public init(
    providerBundleIdentifier: String,
    installer: any SystemExtensionInstalling
  ) {
    self.providerBundleIdentifier = providerBundleIdentifier
    self.installer = installer
  }

  public func installTunnel() async throws -> SystemExtensionInstallResult {
    try await installer.install()
  }

  public func cancelTunnelInstallationWait() async {
    // This intentionally does not call stopTunnel. Approval/activation is a
    // SystemExtensions control-plane operation, not a running VPN session,
    // and Apple exposes no public cancellation API once a request is submitted.
    installer.cancelInstallationWait()
  }

  public func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) async throws {
    try Task.checkCancellation()
    guard descriptor.slot == .tunnel else {
      throw AppleNetworkError.invalidConfigurationSlot
    }
    let manager = try await loadOrCreateManager()
    try Task.checkCancellation()
    let tunnelProtocol = NETunnelProviderProtocol()
    tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
    tunnelProtocol.serverAddress = "Clash for Mac"
    tunnelProtocol.providerConfiguration = try descriptor.providerConfiguration()
    manager.protocolConfiguration = tunnelProtocol
    manager.localizedDescription = "Clash for Mac Tunnel"
    manager.isEnabled = true
    try await save(manager)
    // Saving preferences is a committed external mutation and cannot be
    // canceled through NetworkExtension. Honor cancellation before reloading
    // and, critically, before starting the data plane.
    try Task.checkCancellation()
    try await reload(manager)
    try Task.checkCancellation()

    do {
      try Task.checkCancellation()
      var payload = try TunnelStartPayloadCodec.encode(
        descriptor: descriptor,
        configuration: configuration,
        credentialPayload: credentialPayload
      )
      defer {
        payload.resetBytes(in: payload.startIndex..<payload.endIndex)
        payload.removeAll(keepingCapacity: false)
      }
      try manager.connection.startVPNTunnel(
        options: [NativeProtocolConstants.tunnelStartPayloadOptionKey: payload as NSData]
      )
    } catch let startError {
      if startError is CancellationError {
        throw startError
      }
      throw AppleNetworkError.tunnelStartFailed(startError.localizedDescription)
    }
  }

  public func stopTunnel(expectedConfiguration: ConfigurationDescriptor) async throws {
    guard let manager = try await matchingManager() else {
      throw AppleNetworkError.staleStopRequest
    }
    guard try manager.configurationDescriptor() == expectedConfiguration else {
      throw AppleNetworkError.staleStopRequest
    }
    manager.connection.stopVPNTunnel()

    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(5))
    while clock.now < deadline {
      switch manager.connection.status {
      case .disconnected, .invalid:
        return
      default:
        try await Task.sleep(for: .milliseconds(100))
      }
    }
    throw AppleNetworkError.tunnelStopTimedOut
  }

  public func snapshot() async throws -> EngineSnapshot {
    try Task.checkCancellation()
    guard let manager = try await matchingManager() else {
      return .off
    }
    try Task.checkCancellation()
    switch manager.connection.status {
    case .invalid, .disconnected:
      return .off
    case .connecting, .reasserting:
      return .tunnelStarting(
        configuration: try manager.configurationDescriptor(),
        sequence: 0
      )
    case .disconnecting:
      return .tunnelStopping(
        configuration: try manager.configurationDescriptor(),
        sequence: 0
      )
    case .connected:
      return try await providerSnapshot(manager)
    @unknown default:
      return .tunnelFailed(
        EngineFailure(
          code: "unknown-nevpn-status",
          message: "NetworkExtension returned an unknown VPN status.",
          isRetryable: false
        ),
        configuration: try manager.configurationDescriptor(),
        sequence: 0
      )
    }
  }

  public func hasManagedTunnelConfiguration() async throws -> Bool {
    try await matchingManager() != nil
  }

  public func managedTunnelConfiguration() async throws -> ConfigurationDescriptor? {
    guard let manager = try await matchingManager() else {
      return nil
    }
    return try manager.configurationDescriptor()
  }

  private func providerSnapshot(_ manager: NETunnelProviderManager) async throws -> EngineSnapshot {
    guard let session = manager.connection as? NETunnelProviderSession else {
      throw AppleNetworkError.providerDidNotRespond
    }
    let command = try NativeCommand(kind: .snapshot)
    let request = RequestEnvelope(command: command)
    let requestData = try ProtocolCodec.encode(request)
    let gate = ProviderResponseGate()
    let responseData: Data = try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        gate.install(continuation)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
          gate.finish(.failure(AppleNetworkError.providerMessageTimedOut))
        }
        do {
          try session.sendProviderMessage(requestData) { data in
            guard let data else {
              gate.finish(.failure(AppleNetworkError.providerDidNotRespond))
              return
            }
            gate.finish(.success(data))
          }
        } catch {
          gate.finish(
            .failure(
              AppleNetworkError.providerMessageFailed(error.localizedDescription)
            )
          )
        }
      }
    } onCancel: {
      gate.finish(.failure(CancellationError()))
    }
    let response = try ProtocolCodec.decodeResponse(responseData)
    guard response.requestID == request.requestID else {
      throw AppleNetworkError.providerResponseMismatch
    }
    if let failure = response.failure {
      throw AppleNetworkError.providerFailure(failure)
    }
    guard let providerSnapshot = response.result?.snapshot,
      providerSnapshot.state.kind == .tunnelActive,
      providerSnapshot.configuration == (try manager.configurationDescriptor())
    else {
      throw AppleNetworkError.providerResponseMismatch
    }
    return providerSnapshot
  }

  private func loadOrCreateManager() async throws -> NETunnelProviderManager {
    if let manager = try await matchingManager() {
      return manager
    }
    return NETunnelProviderManager()
  }

  private func matchingManager() async throws -> NETunnelProviderManager? {
    let managerList: TunnelManagerList = try await withCheckedThrowingContinuation {
      continuation in
      NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if let error {
          continuation.resume(
            throwing: AppleNetworkError.preferenceLoadFailed(error.localizedDescription)
          )
        } else {
          continuation.resume(returning: TunnelManagerList(values: managers ?? []))
        }
      }
    }
    let matches = managerList.values.filter { manager in
      (manager.protocolConfiguration as? NETunnelProviderProtocol)?
        .providerBundleIdentifier == providerBundleIdentifier
    }
    guard matches.count <= 1 else {
      throw AppleNetworkError.duplicateTunnelManagers(matches.count)
    }
    return matches.first
  }

  private func save(_ manager: NETunnelProviderManager) async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      manager.saveToPreferences { error in
        if let error {
          continuation.resume(
            throwing: AppleNetworkError.preferenceSaveFailed(error.localizedDescription)
          )
        } else {
          continuation.resume(returning: ())
        }
      }
    }
  }

  private func reload(_ manager: NETunnelProviderManager) async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      manager.loadFromPreferences { error in
        if let error {
          continuation.resume(
            throwing: AppleNetworkError.preferenceLoadFailed(error.localizedDescription)
          )
        } else {
          continuation.resume(returning: ())
        }
      }
    }
  }
}

extension ConfigurationDescriptor {
  fileprivate func providerConfiguration() throws -> [String: Any] {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let credentialSlotsData = try encoder.encode(credentialSlots)
    return [
      "schemaVersion": String(NativeProtocolConstants.schemaVersion),
      "slot": slot.rawValue,
      "installationID": installationID.uuidString,
      "epoch": String(epoch),
      "generation": String(generation),
      "byteCount": String(byteCount),
      "sha256": sha256.hex,
      "identitySha256": identitySHA256.hex,
      "credentialSlots": credentialSlotsData,
    ].merging(tunnelProviderConfiguration) { _, new in new }
  }

  private var tunnelProviderConfiguration: [String: Any] {
    guard let tunnelOptions else {
      return [:]
    }
    return [
      "ipv6Enabled": tunnelOptions.ipv6Enabled ? "true" : "false",
      "bypassPrivateNetworks": tunnelOptions.bypassPrivateNetworks ? "true" : "false",
      "mtu": String(tunnelOptions.mtu),
    ]
  }
}

extension NETunnelProviderManager {
  fileprivate func configurationDescriptor() throws -> ConfigurationDescriptor {
    guard
      let configuration = (protocolConfiguration as? NETunnelProviderProtocol)?
        .providerConfiguration,
      let schemaVersionValue = configuration["schemaVersion"] as? String,
      let schemaVersion = UInt16(schemaVersionValue),
      schemaVersion == NativeProtocolConstants.schemaVersion,
      let slotRawValue = configuration["slot"] as? String,
      let slot = ConfigurationSlot(rawValue: slotRawValue),
      let tunnelOptions = try Self.decodeTunnelOptions(
        configuration,
        slot: slot
      ),
      let installationIDValue = configuration["installationID"] as? String,
      let installationID = UUID(uuidString: installationIDValue),
      let epochValue = configuration["epoch"] as? String,
      let epoch = UInt64(epochValue),
      let generationValue = configuration["generation"] as? String,
      let generation = UInt64(generationValue),
      let byteCountValue = configuration["byteCount"] as? String,
      let byteCount = UInt64(byteCountValue),
      let digest = configuration["sha256"] as? String,
      let identityDigest = configuration["identitySha256"] as? String,
      let credentialSlotsData = configuration["credentialSlots"] as? Data,
      let credentialSlots = try? JSONDecoder().decode(
        [CredentialSlot].self,
        from: credentialSlotsData
      )
    else {
      throw AppleNetworkError.providerResponseMismatch
    }
    return try ConfigurationDescriptor(
      slot: slot,
      tunnelOptions: tunnelOptions,
      installationID: installationID,
      epoch: epoch,
      generation: generation,
      byteCount: byteCount,
      sha256: SHA256Digest(hex: digest),
      identitySHA256: SHA256Digest(hex: identityDigest),
      credentialSlots: credentialSlots
    )
  }

  private static func decodeTunnelOptions(
    _ configuration: [String: Any],
    slot: ConfigurationSlot
  ) throws -> TunnelNetworkOptions? {
    guard slot == .tunnel else {
      return nil
    }
    guard let ipv6Value = configuration["ipv6Enabled"] as? String,
      let bypassPrivateNetworksValue = configuration["bypassPrivateNetworks"] as? String,
      let mtuValue = configuration["mtu"] as? String,
      let mtu = UInt16(mtuValue)
    else {
      throw AppleNetworkError.providerResponseMismatch
    }
    let ipv6Enabled: Bool
    switch ipv6Value {
    case "true":
      ipv6Enabled = true
    case "false":
      ipv6Enabled = false
    default:
      throw AppleNetworkError.providerResponseMismatch
    }
    let bypassPrivateNetworks: Bool
    switch bypassPrivateNetworksValue {
    case "true":
      bypassPrivateNetworks = true
    case "false":
      bypassPrivateNetworks = false
    default:
      throw AppleNetworkError.providerResponseMismatch
    }
    return try TunnelNetworkOptions(
      ipv6Enabled: ipv6Enabled,
      bypassPrivateNetworks: bypassPrivateNetworks,
      mtu: mtu
    )
  }
}

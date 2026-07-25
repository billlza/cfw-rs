import CFWAppleNetwork
import CFWCredentialTransport
import CFWSharedProtocol
import Foundation

extension NativeBridgeCoordinator {
  func startSystemProxy(_ request: EngineStartRequest) async throws
    -> NativeRuntimeIdentity
  {
    do {
      try GlobalAuthorityReleaseGate.requireStartAuthorization()
    } catch {
      throw Self.map(error)
    }
    try beginMutation()
    defer { endMutation() }
    guard request.tunnelOptions == nil else {
      throw NativeBridgeExecutionError.failure(
        .configurationRejected,
        "System Proxy start contains Tunnel network options."
      )
    }
    try preflightCredentials(request)
    do {
      try await proxy.ensureRegistered()
    } catch {
      throw Self.map(error)
    }
    let descriptor = try request.descriptor(slot: .systemProxy)
    var configuration = Data(request.configJSON.utf8)
    defer {
      configuration.resetBytes(in: configuration.startIndex..<configuration.endIndex)
      configuration.removeAll(keepingCapacity: false)
    }
    do {
      try configurationStore.persist(configuration, descriptor: descriptor)
    } catch {
      throw Self.map(error)
    }
    do {
      try await proxy.start(configuration: descriptor)
    } catch {
      throw Self.map(error)
    }
    let status = try await queryStatus()
    guard case .systemProxy(let runtime) = status,
      runtime.context == request.context,
      runtime.configDigest == request.configDigest.hex,
      runtime.ready
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "ProxyAgent did not return readiness for the exact start request."
      )
    }
    return runtime
  }

  func stopSystemProxy(_ context: EngineCommandContext) async throws {
    try beginMutation()
    defer { endMutation() }
    let snapshot: EngineSnapshot
    do {
      snapshot = try await proxy.snapshot()
    } catch {
      throw Self.map(error)
    }
    guard let descriptor = try Self.activeDescriptor(snapshot, expectedMode: .systemProxy),
      Self.matches(descriptor, context: context)
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "ProxyAgent stop does not match the active generation."
      )
    }
    do {
      try await proxy.stop(configuration: descriptor)
    } catch {
      throw Self.map(error)
    }
    guard case .off = try await queryStatus() else {
      throw NativeBridgeExecutionError.failure(
        .unavailable,
        "ProxyAgent stop did not reach the global Off barrier."
      )
    }
  }

  func installTunnel(_ context: EngineCommandContext) async throws
    -> NativeTunnelInstallOutcome
  {
    try beginMutation()
    defer { endMutation() }
    guard pendingInstallationContext == nil else {
      throw NativeBridgeExecutionError.failure(
        .busy,
        "A prior System Extension installation request is still pending."
      )
    }
    let result: SystemExtensionInstallResult
    do {
      result = try await tunnel.installTunnel()
    } catch {
      throw Self.map(error)
    }
    switch result {
    case .completed:
      return .ready
    case .awaitingApproval:
      pendingInstallationContext = context
      return .awaitingApproval
    case .requiresRestart:
      throw NativeBridgeExecutionError.failure(
        .unavailable,
        "System Extension activation requires a restart before Tunnel can start."
      )
    }
  }

  func cancelTunnelInstall(_ context: EngineCommandContext) async throws {
    try beginMutation()
    defer { endMutation() }
    guard pendingInstallationContext == context else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "Tunnel installation cancellation does not match the pending generation."
      )
    }
    await tunnel.cancelTunnelInstallationWait()
    pendingInstallationContext = nil
  }

  func startTunnel(_ request: EngineStartRequest) async throws -> NativeRuntimeIdentity {
    do {
      try GlobalAuthorityReleaseGate.requireStartAuthorization()
    } catch {
      throw Self.map(error)
    }
    try beginMutation()
    defer { endMutation() }
    guard request.tunnelOptions != nil else {
      throw NativeBridgeExecutionError.failure(
        .configurationRejected,
        "Tunnel start omits required network options."
      )
    }
    var credentialMaterial: CredentialMaterial
    do {
      credentialMaterial = try credentialVault.resolve(slots: request.credentialSlots)
    } catch {
      throw Self.map(error)
    }
    defer { credentialMaterial.erase() }
    var credentialPayload: Data?
    if !request.credentialSlots.isEmpty {
      do {
        credentialPayload = try EphemeralCredentialCodec.encode(credentialMaterial)
      } catch {
        throw Self.map(error)
      }
    }
    defer {
      if var payload = credentialPayload {
        credentialPayload = nil
        payload.resetBytes(in: payload.startIndex..<payload.endIndex)
        payload.removeAll(keepingCapacity: false)
      }
    }
    let descriptor = try request.descriptor(slot: .tunnel)
    do {
      try await tunnel.startTunnel(
        configuration: Data(request.configJSON.utf8),
        descriptor: descriptor,
        credentialPayload: credentialPayload
      )
    } catch {
      throw Self.map(error)
    }
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(10))
    while clock.now < deadline {
      let providerSnapshot: EngineSnapshot
      do {
        providerSnapshot = try await tunnel.snapshot()
      } catch {
        throw Self.map(error)
      }
      if providerSnapshot.state.kind == .tunnelActive {
        let status = try await queryStatus()
        guard case .tunnel(let runtime) = status else {
          throw NativeBridgeExecutionError.failure(
            .identityRejected,
            "Packet Tunnel provider was ready without matching global ownership."
          )
        }
        guard runtime.context == request.context,
          runtime.configDigest == request.configDigest.hex,
          runtime.ready
        else {
          throw NativeBridgeExecutionError.failure(
            .identityRejected,
            "Packet Tunnel readiness does not match the exact start request."
          )
        }
        return runtime
      }
      if providerSnapshot.state.kind == .failed {
        throw NativeBridgeExecutionError.failure(
          .unavailable,
          "Packet Tunnel entered a failed state before readiness attestation."
        )
      }
      try await Task.sleep(for: .milliseconds(100))
    }
    throw NativeBridgeExecutionError.failure(
      .timeout,
      "Packet Tunnel did not provide bounded ready attestation."
    )
  }

  func stopTunnel(_ context: EngineCommandContext) async throws {
    try beginMutation()
    defer { endMutation() }
    let snapshot: EngineSnapshot
    do {
      snapshot = try await tunnel.snapshot()
    } catch {
      throw Self.map(error)
    }
    guard let descriptor = try Self.activeDescriptor(snapshot, expectedMode: .tunnel),
      Self.matches(descriptor, context: context)
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "Packet Tunnel stop does not match the active generation."
      )
    }
    do {
      try await tunnel.stopTunnel(expectedConfiguration: descriptor)
    } catch {
      throw Self.map(error)
    }
    guard case .off = try await queryStatus() else {
      throw NativeBridgeExecutionError.failure(
        .unavailable,
        "Packet Tunnel stop did not reach the global Off barrier."
      )
    }
  }
}

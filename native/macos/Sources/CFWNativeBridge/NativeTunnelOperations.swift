import CFWAppleNetwork
import CFWCredentialTransport
import CFWSharedProtocol
import Foundation

extension NativeBridgeCoordinator {
  func installTunnel(_ context: EngineCommandContext) async throws
    -> NativeTunnelInstallOutcome
  {
    let mutationID = try await beginMutation()
    defer { endMutation(mutationID) }
    try Task.checkCancellation()
    let result: SystemExtensionInstallResult
    do {
      result = try await awaitTunnelInstallation(context: context)
      try Task.checkCancellation()
    } catch {
      throw Self.map(error)
    }
    switch result {
    case .completed:
      return .ready
    case .awaitingApproval:
      return .awaitingApproval
    case .requiresRestart:
      throw NativeBridgeExecutionError.failure(
        .unavailable,
        "System Extension activation requires a restart before Tunnel can start."
      )
    }
  }

  /// Waits for the answer to the approval that the exact pending installation
  /// asked for. It takes no mutation, so a stop or the installation's own
  /// retry proceeds meanwhile, and the answer stays with the request for that
  /// retry to read.
  func awaitTunnelApproval(_ context: EngineCommandContext) async throws
    -> NativeTunnelApprovalWait
  {
    try Task.checkCancellation()
    guard let pending = pendingTunnelInstallation, pending.context == context,
      pending.state == .retryable
    else {
      return .noPendingRequest
    }
    let wait: SystemExtensionApprovalWait
    do {
      wait = try await tunnel.awaitTunnelInstallationApproval()
      try Task.checkCancellation()
    } catch {
      throw Self.map(error)
    }
    switch wait {
    case .resolved: return .resolved
    case .stillAwaiting: return .stillAwaiting
    case .noPendingRequest: return .noPendingRequest
    }
  }

  func cancelTunnelInstall(_ context: EngineCommandContext) async throws {
    let mutationID = try await beginMutation()
    defer { endMutation(mutationID) }
    guard pendingTunnelInstallation?.context == context else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "Tunnel installation cancellation does not match the pending generation."
      )
    }
    await tunnel.cancelTunnelInstallationWait()
    pendingTunnelInstallation = nil
  }

  func authorizeTunnelConfiguration(_ request: EngineStartRequest) async throws {
    let mutationID = try await beginMutation()
    defer { endMutation(mutationID) }
    try requireNoPendingStopBeforeStart()
    let descriptor = try request.descriptor(slot: .tunnel)
    do {
      try await proxy.ensureRegistered()
      let ownership = try await engineLease.authorityOwnership()
      guard ownership.state == .off, ownership.lease == nil,
        try await proxy.snapshot().state.kind == .off
      else {
        throw NativeBridgeExecutionError.failure(.busy, "VPN authorization requires global Off.")
      }
    } catch {
      throw Self.map(error)
    }
    do {
      try await tunnel.authorizeTunnelConfiguration(descriptor)
      try Task.checkCancellation()
    } catch {
      let original = error
      pendingStartCleanup = NativeStopTransaction(
        owner: .tunnel, commandContext: request.context, descriptor: descriptor)
      do {
        try await reconcilePendingTunnelStartCleanup(recordCompletion: false)
        try await proveFailedStartOff(
          NativeStopTransaction(
            owner: .tunnel, commandContext: request.context, descriptor: descriptor))
      } catch {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "VPN configuration authorization failed and its preference cleanup is unproven.")
      }
      throw Self.map(original)
    }
  }

  func startTunnel(_ request: EngineStartRequest) async throws -> NativeRuntimeIdentity {
    let mutationID = try await beginMutation()
    defer { endMutation(mutationID) }
    try Task.checkCancellation()
    try requireNoPendingStopBeforeStart()
    guard request.tunnelOptions != nil else {
      throw NativeBridgeExecutionError.failure(
        .configurationRejected,
        "Tunnel start omits required network options."
      )
    }
    // Exact global ownership requires the signed ProxyAgent to be observable even
    // for Tunnel mode; an unregistered Agent cannot prove that no persisted System
    // Proxy ownership remains. Approval errors are surfaced before Tunnel mutation.
    do {
      try await proxy.ensureRegistered()
    } catch {
      throw Self.map(error)
    }
    try Task.checkCancellation()
    var credentialMaterial: CredentialMaterial
    do {
      credentialMaterial = try credentialVault.resolve(
        audience: request.credentialAudience,
        slots: request.credentialSlots
      )
    } catch {
      throw Self.map(error)
    }
    defer { credentialMaterial.erase() }
    var credentialPayload: Data?
    do {
      let encoded = try credentialMaterial.authorityPayload(for: request.credentialSlots)
      defer { encoded?.erase() }
      credentialPayload = try encoded?.withUnsafeBytes { Data($0) }
    } catch {
      throw Self.map(error)
    }
    defer {
      if var payload = credentialPayload {
        credentialPayload = nil
        payload.resetBytes(in: payload.startIndex..<payload.endIndex)
        payload.removeAll(keepingCapacity: false)
      }
    }
    let descriptor = try request.descriptor(slot: .tunnel)
    try Task.checkCancellation()
    do {
      try await tunnel.startTunnel(
        configuration: Data(request.configJSON.utf8),
        descriptor: descriptor,
        credentialPayload: credentialPayload
      )
    } catch {
      let originalError = error
      pendingStartCleanup = NativeStopTransaction(
        owner: .tunnel,
        commandContext: request.context,
        descriptor: descriptor)
      do {
        try await reconcilePendingTunnelStartCleanup(recordCompletion: false)
      } catch {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Tunnel start failed and exact preparation cleanup remains unproven: \(Self.map(error).responseFailure.message)"
        )
      }
      let transaction = NativeStopTransaction(
        owner: .tunnel,
        commandContext: request.context,
        descriptor: descriptor)
      try await proveFailedStartOff(transaction)
      throw Self.map(originalError)
    }
    do {
      try Task.checkCancellation()
      // Ticket validity remains ten seconds. Observing the OS's asynchronous
      // disconnect error needs a separate, longer bound so a cold launch that
      // expires its ticket reports that exact cause before cleanup and retry.
      // The bound also outlasts the provider's interruptible libbox start.
      let deadline = armTunnelReadinessDeadline(EngineStartBudget.tunnelReadiness)
      while !deadline.hasPassed() {
        let providerSnapshot: EngineSnapshot
        do {
          providerSnapshot = try await tunnel.snapshot()
        } catch {
          throw Self.map(error)
        }
        if providerSnapshot.state.kind == .tunnelActive {
          let status = try await queryStatus(enforcePreferenceBarrier: false)
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
          do {
            try await tunnel.completePreferenceMutation(
              expectedConfiguration: descriptor)
          } catch {
            throw Self.map(error)
          }
          try Task.checkCancellation()
          return runtime
        }
        if providerSnapshot.state.kind == .failed {
          guard let failure = providerSnapshot.state.failure else {
            throw NativeBridgeExecutionError.failure(
              .identityRejected,
              "Packet Tunnel returned a failed state without a typed failure."
            )
          }
          throw Self.map(AppleNetworkError.providerFailure(failure))
        }
        try await Task.sleep(for: .milliseconds(100))
      }
      throw NativeBridgeExecutionError.failure(
        .timeout,
        "Packet Tunnel did not provide bounded ready attestation."
      )
    } catch {
      try await rollbackStartedOwner(
        .tunnel,
        descriptor: descriptor,
        commandContext: request.context,
        after: error)
    }
  }

  func stopTunnel(_ context: EngineCommandContext) async throws {
    let mutationID = try await beginMutation()
    defer { endMutation(mutationID) }
    if try await acknowledgeCompletedStartCleanup(.tunnel, context: context) {
      return
    }
    if try await resumePendingFailedStartOff(.tunnel, context: context) {
      return
    }
    if let pendingStartCleanup {
      guard pendingStartCleanup.owner == .tunnel,
        pendingStartCleanup.commandContext == context
      else {
        throw NativeBridgeExecutionError.failure(
          .identityRejected,
          "Tunnel cleanup retry does not match the failed start generation."
        )
      }
      do {
        try await reconcilePendingTunnelStartCleanup(recordCompletion: false)
      } catch {
        throw Self.map(error)
      }
      try await proveFailedStartOff(pendingStartCleanup)
      guard try await acknowledgeCompletedStartCleanup(.tunnel, context: context) else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Tunnel failed-start cleanup completed without an exact receipt."
        )
      }
      return
    }
    if try await prepareExplicitStop(.tunnel, context: context) {
      try await drivePendingStop(restoringSettingsFirst: false)
    }
  }
}

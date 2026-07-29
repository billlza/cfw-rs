import CFWAppleNetwork
import CFWCredentialTransport
import CFWSharedProtocol
import Foundation

extension NativeBridgeCoordinator {
  func startSystemProxy(_ request: EngineStartRequest) async throws
    -> NativeRuntimeIdentity
  {
    try beginMutation()
    defer { endMutation() }
    try requireNoPendingStopBeforeStart()
    guard request.tunnelOptions == nil else {
      throw NativeBridgeExecutionError.failure(
        .configurationRejected,
        "System Proxy start contains Tunnel network options."
      )
    }
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
    let prepared: HostPreparedSystemProxyStart
    do {
      prepared = try await systemProxyPreparer.prepareSystemProxyStart(
        configuration: configuration,
        descriptor: descriptor)
    } catch {
      throw Self.map(error)
    }
    do {
      try preflightCredentials(request)
    } catch {
      try await cancelSystemProxyPreparation(
        prepared,
        after: error,
        context: "credential preflight failed",
        descriptor: descriptor,
        commandContext: request.context)
    }
    do {
      try await proxy.start(
        configuration: configuration,
        descriptor: descriptor,
        authorization: prepared)
    } catch {
      let originalError = error
      do {
        try await systemProxyPreparer.cancelSystemProxyStart(prepared)
      } catch {
        try await rollbackStartedOwner(
          .systemProxy,
          descriptor: descriptor,
          commandContext: request.context,
          after: originalError,
          cancellationFailure: error)
      }
      rememberCompletedStartCleanup(
        owner: .systemProxy,
        commandContext: request.context,
        descriptor: descriptor)
      throw Self.map(originalError)
    }
    do {
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
    } catch {
      try await rollbackStartedOwner(
        .systemProxy,
        descriptor: descriptor,
        commandContext: request.context,
        after: error)
    }
  }

  private func cancelSystemProxyPreparation(
    _ prepared: HostPreparedSystemProxyStart,
    after originalError: Error,
    context: String,
    descriptor: ConfigurationDescriptor,
    commandContext: EngineCommandContext
  ) async throws -> Never {
    do {
      try await systemProxyPreparer.cancelSystemProxyStart(prepared)
    } catch {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "System Proxy \(context) and Authority cancellation is unproven: \(Self.map(error).responseFailure.message)"
      )
    }
    rememberCompletedStartCleanup(
      owner: .systemProxy,
      commandContext: commandContext,
      descriptor: descriptor)
    throw Self.map(originalError)
  }

  func stopSystemProxy(_ context: EngineCommandContext) async throws {
    try beginMutation()
    defer { endMutation() }
    if try acknowledgeCompletedStartCleanup(.systemProxy, context: context) {
      return
    }
    try await prepareExplicitStop(.systemProxy, context: context)
    try await drivePendingStop()
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
    // Register the exact local wait ownership before submitting the public
    // System Extension request. A synchronous error, timeout, cancellation, or
    // restart-required terminal result can then be acknowledged by Rust's
    // exact cancel command without inventing that the OS request was revoked.
    pendingInstallationContext = context
    let result: SystemExtensionInstallResult
    do {
      result = try await tunnel.installTunnel()
    } catch {
      throw Self.map(error)
    }
    switch result {
    case .completed:
      pendingInstallationContext = nil
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
    try beginMutation()
    defer { endMutation() }
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
      let originalError = error
      pendingStartCleanup = NativeStopTransaction(
        owner: .tunnel,
        commandContext: request.context,
        descriptor: descriptor)
      do {
        try await reconcilePendingTunnelStartCleanup()
      } catch {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Tunnel start failed and exact preparation cleanup remains unproven: \(Self.map(error).responseFailure.message)"
        )
      }
      throw Self.map(originalError)
    }
    do {
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
    } catch {
      try await rollbackStartedOwner(
        .tunnel,
        descriptor: descriptor,
        commandContext: request.context,
        after: error)
    }
  }

  func stopTunnel(_ context: EngineCommandContext) async throws {
    try beginMutation()
    defer { endMutation() }
    if try acknowledgeCompletedStartCleanup(.tunnel, context: context) {
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
        try await reconcilePendingTunnelStartCleanup()
      } catch {
        throw Self.map(error)
      }
      guard try acknowledgeCompletedStartCleanup(.tunnel, context: context) else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Tunnel failed-start cleanup completed without an exact receipt."
        )
      }
      return
    }
    try await prepareExplicitStop(.tunnel, context: context)
    try await drivePendingStop()
  }

  private func requireNoPendingStopBeforeStart() throws {
    guard pendingStop == nil,
      pendingStartCleanup == nil,
      completedStartCleanup == nil
    else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "A prior native stop transaction has not reached the global Off barrier."
      )
    }
  }

  private func prepareExplicitStop(
    _ owner: NativeStopOwner,
    context: EngineCommandContext
  ) async throws {
    if let pendingStop {
      guard pendingStop.owner == owner,
        pendingStop.commandContext == context
      else {
        throw NativeBridgeExecutionError.failure(
          .identityRejected,
          "The stop retry does not match the pending native stop transaction."
        )
      }
      return
    }

    let snapshot: EngineSnapshot
    do {
      snapshot = try await ownerSnapshot(owner)
    } catch {
      throw Self.map(error)
    }
    let expectedMode: EngineMode = owner == .systemProxy ? .systemProxy : .tunnel
    guard let descriptor = try Self.activeDescriptor(snapshot, expectedMode: expectedMode),
      Self.matches(descriptor, context: context)
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "The native owner stop does not match the active generation."
      )
    }
    pendingStop = NativeStopTransaction(
      owner: owner,
      commandContext: context,
      descriptor: descriptor)
  }

  private func rollbackStartedOwner(
    _ owner: NativeStopOwner,
    descriptor: ConfigurationDescriptor,
    commandContext: EngineCommandContext,
    after originalError: Error,
    cancellationFailure: Error? = nil
  ) async throws -> Never {
    if let pendingStop {
      guard pendingStop.owner == owner,
        pendingStop.commandContext == commandContext,
        pendingStop.descriptor == descriptor
      else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Start verification failed while another native stop transaction remained pending."
        )
      }
    } else {
      pendingStop = NativeStopTransaction(
        owner: owner,
        commandContext: commandContext,
        descriptor: descriptor)
    }

    do {
      try await drivePendingStop()
    } catch let error as NativeBridgeExecutionError {
      let localCleanup = await attemptLocalStopAfterOrderingFailure()
      let original = Self.map(originalError).responseFailure.message
      let cancellation =
        cancellationFailure.map {
          " Preparation cancellation also failed: \(Self.map($0).responseFailure.message)"
        } ?? ""
      let cleanup = error.responseFailure.message
      let local = localCleanup.map { " Local stop also failed: \($0)" } ?? ""
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "Native start failed: \(original)\(cancellation) Cleanup remains unproven: \(cleanup).\(local)"
      )
    } catch {
      let localCleanup = await attemptLocalStopAfterOrderingFailure()
      let local = localCleanup.map { " Local stop also failed: \($0)" } ?? ""
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "Native start cleanup failed at an untyped boundary.\(local)"
      )
    }
    rememberCompletedStartCleanup(
      owner: owner,
      commandContext: commandContext,
      descriptor: descriptor)
    throw Self.map(originalError)
  }

  private func reconcilePendingTunnelStartCleanup() async throws {
    guard let transaction = pendingStartCleanup,
      transaction.owner == .tunnel
    else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "No exact Tunnel preparation cleanup is pending."
      )
    }

    if try await engineLease.cancelPreparedStart(for: transaction.descriptor) {
      pendingStartCleanup = nil
      rememberCompletedStartCleanup(
        owner: transaction.owner,
        commandContext: transaction.commandContext,
        descriptor: transaction.descriptor)
      return
    }

    pendingStartCleanup = nil
    pendingStop = transaction
    try await drivePendingStop()
    rememberCompletedStartCleanup(
      owner: transaction.owner,
      commandContext: transaction.commandContext,
      descriptor: transaction.descriptor)
  }

  private func rememberCompletedStartCleanup(
    owner: NativeStopOwner,
    commandContext: EngineCommandContext,
    descriptor: ConfigurationDescriptor
  ) {
    completedStartCleanup = NativeStartCleanupReceipt(
      owner: owner,
      commandContext: commandContext,
      descriptor: descriptor)
  }

  private func acknowledgeCompletedStartCleanup(
    _ owner: NativeStopOwner,
    context: EngineCommandContext
  ) throws -> Bool {
    guard let receipt = completedStartCleanup else { return false }
    guard receipt.owner == owner,
      receipt.commandContext == context
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "The cleanup acknowledgement does not match the failed start generation."
      )
    }
    completedStartCleanup = nil
    return true
  }

  private func drivePendingStop() async throws {
    guard var transaction = pendingStop else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "No native stop transaction is available to continue."
      )
    }

    if transaction.authorityContext == nil {
      do {
        transaction.authorityContext = try await engineLease.beginStop(
          for: transaction.descriptor)
      } catch {
        throw Self.map(error)
      }
      pendingStop = transaction
    }

    if !transaction.ownerStopped {
      do {
        try await stopOwner(transaction)
      } catch {
        throw Self.map(error)
      }
      transaction.ownerStopped = true
      pendingStop = transaction
    }

    if !transaction.authorityCompleted {
      guard let authorityContext = transaction.authorityContext else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "The Authority stop context was lost before completion."
        )
      }
      do {
        try await engineLease.completeStop(authorityContext)
      } catch {
        throw Self.map(error)
      }
      transaction.authorityCompleted = true
      pendingStop = transaction
    }

    guard case .off = try await queryStatus() else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "The native stop transaction did not reach the global Off barrier."
      )
    }
    pendingStop = nil
  }

  private func ownerSnapshot(_ owner: NativeStopOwner) async throws -> EngineSnapshot {
    switch owner {
    case .systemProxy: try await proxy.snapshot()
    case .tunnel: try await tunnel.snapshot()
    }
  }

  private func stopOwner(_ transaction: NativeStopTransaction) async throws {
    switch transaction.owner {
    case .systemProxy:
      try await proxy.stop(configuration: transaction.descriptor)
    case .tunnel:
      try await tunnel.stopTunnel(expectedConfiguration: transaction.descriptor)
    }
  }

  /// If Authority ordering itself becomes unavailable during a failed start, the
  /// already-started owner must still be asked to tear down. The transaction remains
  /// pending so a later retry can complete the missing Authority barrier exactly.
  private func attemptLocalStopAfterOrderingFailure() async -> String? {
    guard var transaction = pendingStop, !transaction.ownerStopped else { return nil }
    do {
      try await stopOwner(transaction)
      transaction.ownerStopped = true
      pendingStop = transaction
      return nil
    } catch {
      return Self.map(error).responseFailure.message
    }
  }
}

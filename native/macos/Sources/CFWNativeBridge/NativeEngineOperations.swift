import CFWAppleNetwork
import CFWCredentialTransport
import CFWSharedProtocol
import Foundation

extension NativeBridgeCoordinator {
  func startSystemProxy(_ request: EngineStartRequest) async throws
    -> NativeRuntimeIdentity
  {
    let mutationID = try await beginMutation()
    defer { endMutation(mutationID) }
    try Task.checkCancellation()
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
    try Task.checkCancellation()
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
      try Task.checkCancellation()
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
      let transaction = NativeStopTransaction(
        owner: .systemProxy,
        commandContext: request.context,
        descriptor: descriptor)
      try await proveFailedStartOff(transaction)
      throw Self.map(originalError)
    }
    do {
      try Task.checkCancellation()
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
      try Task.checkCancellation()
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
    try await proveFailedStartOff(
      NativeStopTransaction(
        owner: .systemProxy,
        commandContext: commandContext,
        descriptor: descriptor)
    )
    throw Self.map(originalError)
  }

  func stopSystemProxy(_ context: EngineCommandContext) async throws {
    let mutationID = try await beginMutation()
    defer { endMutation(mutationID) }
    if try await acknowledgeCompletedStartCleanup(.systemProxy, context: context) {
      return
    }
    if try await resumePendingFailedStartOff(.systemProxy, context: context) {
      return
    }
    try await prepareExplicitStop(.systemProxy, context: context)
    try await drivePendingStop()
  }

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
    try await prepareExplicitStop(.tunnel, context: context)
    try await drivePendingStop()
  }

  private func requireNoPendingStopBeforeStart() throws {
    guard pendingStop == nil,
      pendingStartCleanup == nil,
      pendingFailedStartOff == nil,
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
    if owner == .tunnel {
      if let pendingStartCleanup {
        guard pendingStartCleanup.owner == owner,
          pendingStartCleanup.commandContext == commandContext,
          pendingStartCleanup.descriptor == descriptor
        else {
          throw NativeBridgeExecutionError.failure(
            .cleanupUnproven,
            "Tunnel start verification conflicts with another cleanup transaction."
          )
        }
      } else {
        pendingStartCleanup = NativeStopTransaction(
          owner: owner,
          commandContext: commandContext,
          descriptor: descriptor)
      }
      do {
        try await reconcilePendingTunnelStartCleanup(recordCompletion: false)
      } catch let error as NativeBridgeExecutionError {
        let localCleanup = await attemptLocalStopAfterOrderingFailure()
        let local = localCleanup.map { " Local stop also failed: \($0)" } ?? ""
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Tunnel start failed and durable preference cleanup remains unproven: \(error.responseFailure.message).\(local)"
        )
      } catch {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Tunnel start cleanup failed at an untyped boundary."
        )
      }
      let transaction = NativeStopTransaction(
        owner: owner,
        commandContext: commandContext,
        descriptor: descriptor)
      try await proveFailedStartOff(transaction)
      throw Self.map(originalError)
    }

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

  func reconcilePendingTunnelStartCleanup(
    recordCompletion: Bool = true
  ) async throws {
    guard let transaction = pendingStartCleanup,
      transaction.owner == .tunnel
    else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "No exact Tunnel preparation cleanup is pending."
      )
    }

    var ownerControlled = false
    if let pendingStop {
      guard pendingStop.owner == transaction.owner,
        pendingStop.commandContext == transaction.commandContext,
        pendingStop.descriptor == transaction.descriptor
      else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Tunnel preference cleanup conflicts with another stop transaction."
        )
      }
      ownerControlled = true
    } else {
      ownerControlled =
        !(try await engineLease.cancelPreparedStart(
          for: transaction.descriptor))
      if ownerControlled {
        pendingStop = transaction
      }
    }

    if ownerControlled {
      try await beginPendingStopAtAuthority()
    }

    let preferenceCompensated: Bool
    if pendingStop?.preferenceCompensated == true {
      // A prior attempt already restored the exact preference state and proved
      // OS Off, but Authority completion or the final global query failed. Do
      // not replay beginStop after a lost complete reply may have committed Off.
      // The final fresh verification below still guards journal removal.
      preferenceCompensated = true
    } else {
      let authorityContext = pendingStop?.authorityContext
      let engineLease = self.engineLease
      do {
        preferenceCompensated = try await tunnel.compensatePendingPreferenceMutation(
          expectedConfiguration: transaction.descriptor,
          revokePreparation: {
            if let authorityContext {
              let observed = try await engineLease.beginStop(
                for: transaction.descriptor)
              guard observed == authorityContext else {
                throw NativeBridgeExecutionError.failure(
                  .cleanupUnproven,
                  "Authority stop identity changed during preference compensation."
                )
              }
            } else {
              guard try await engineLease.cancelPreparedStart(for: transaction.descriptor) else {
                throw NativeBridgeExecutionError.failure(
                  .cleanupUnproven,
                  "Authority retained owner control during preference compensation."
                )
              }
            }
          }
        )
      } catch {
        throw Self.map(error)
      }
    }

    if ownerControlled {
      if preferenceCompensated {
        guard var stoppedTransaction = pendingStop else {
          throw NativeBridgeExecutionError.failure(
            .cleanupUnproven,
            "Tunnel preference compensation lost its Authority stop transaction."
          )
        }
        // Compensation has independently stopped the exact written manager and
        // proved NetworkExtension Off. Authority completion remains the final,
        // independent durable owner-stopped check.
        stoppedTransaction.preferenceCompensated = true
        stoppedTransaction.ownerStopped = true
        pendingStop = stoppedTransaction
      } else {
        try await drivePendingStopToOwnerStopped()
      }
      try await completePendingStopAfterOwnerStopped()
    }

    do {
      try await tunnel.finishPreferenceCompensation(
        expectedConfiguration: transaction.descriptor)
    } catch {
      throw Self.map(error)
    }

    pendingStartCleanup = nil
    if recordCompletion {
      rememberCompletedStartCleanup(
        owner: transaction.owner,
        commandContext: transaction.commandContext,
        descriptor: transaction.descriptor)
    }
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
  ) async throws -> Bool {
    guard let receipt = completedStartCleanup else { return false }
    guard receipt.owner == owner,
      receipt.commandContext == context
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "The cleanup acknowledgement does not match the failed start generation."
      )
    }
    try await requireFailedStartGlobalOff(
      "The failed-start cleanup receipt no longer has a fresh global Off proof.")
    completedStartCleanup = nil
    return true
  }

  private func resumePendingFailedStartOff(
    _ owner: NativeStopOwner,
    context: EngineCommandContext
  ) async throws -> Bool {
    guard let transaction = pendingFailedStartOff else { return false }
    guard transaction.owner == owner,
      transaction.commandContext == context
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "The failed-start Off retry does not match the pending generation."
      )
    }
    try await proveFailedStartOff(transaction)
    guard try await acknowledgeCompletedStartCleanup(owner, context: context) else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "The failed-start Off proof completed without an exact receipt."
      )
    }
    return true
  }

  private func retainPendingFailedStartOff(
    _ transaction: NativeStopTransaction
  ) throws {
    if let pendingFailedStartOff {
      guard pendingFailedStartOff.owner == transaction.owner,
        pendingFailedStartOff.commandContext == transaction.commandContext,
        pendingFailedStartOff.descriptor == transaction.descriptor
      else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Failed-start Off proof conflicts with another cleanup transaction."
        )
      }
      return
    }
    guard completedStartCleanup == nil else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "Failed-start Off proof conflicts with an unacknowledged cleanup receipt."
      )
    }
    pendingFailedStartOff = transaction
  }

  private func proveFailedStartOff(
    _ transaction: NativeStopTransaction
  ) async throws {
    try retainPendingFailedStartOff(transaction)
    guard pendingStartCleanup == nil, pendingStop == nil else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "Failed-start Off proof began before its earlier cleanup phase completed."
      )
    }
    let initial: EngineSnapshot
    do {
      initial = try await ownerSnapshot(transaction.owner)
    } catch {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "Failed-start owner state could not be observed: \(Self.map(error).responseFailure.message)"
      )
    }
    if !Self.isStableOff(initial) {
      guard initial.state.kind == .failed,
        initial.configuration == transaction.descriptor
      else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Failed-start owner state does not match the exact failed generation."
        )
      }
      do {
        try await stopOwner(transaction)
      } catch {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Failed-start owner could not advance to Off: \(Self.map(error).responseFailure.message)"
        )
      }
      let stopped: EngineSnapshot
      do {
        stopped = try await ownerSnapshot(transaction.owner)
      } catch {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Stopped failed-start owner could not be observed: \(Self.map(error).responseFailure.message)"
        )
      }
      guard Self.isStableOff(stopped) else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "The exact failed-start owner did not attest Off after cleanup."
        )
      }
    }
    try await requireFailedStartGlobalOff(
      "Failed-start cleanup did not reach the independent global Off barrier.")
    pendingFailedStartOff = nil
    rememberCompletedStartCleanup(
      owner: transaction.owner,
      commandContext: transaction.commandContext,
      descriptor: transaction.descriptor)
  }

  private func requireFailedStartGlobalOff(_ context: String) async throws {
    let status: NativeEngineStatus
    do {
      status = try await queryStatus(enforcePreferenceBarrier: false)
    } catch {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "\(context) Observation failed: \(Self.map(error).responseFailure.message)"
      )
    }
    guard case .off = status else {
      throw NativeBridgeExecutionError.failure(.cleanupUnproven, context)
    }
  }

  private func drivePendingStop() async throws {
    try await drivePendingStopToOwnerStopped()
    try await completePendingStopAfterOwnerStopped()
  }

  private func beginPendingStopAtAuthority() async throws {
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
  }

  private func drivePendingStopToOwnerStopped() async throws {
    try await beginPendingStopAtAuthority()
    guard var transaction = pendingStop else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "The native stop transaction disappeared after Authority ordering."
      )
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
  }

  private func completePendingStopAfterOwnerStopped() async throws {
    guard var transaction = pendingStop, transaction.ownerStopped else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "The owner is not proven stopped before Authority completion."
      )
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

    guard case .off = try await queryStatus(enforcePreferenceBarrier: false) else {
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

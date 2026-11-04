import CFWAppleNetwork
import CFWSharedProtocol
import Foundation

extension NativeBridgeCoordinator {
  func startSystemProxy(_ request: EngineStartRequest) async throws
    -> NativeRuntimeIdentity
  {
    try await startProxy(request, expectedMode: .systemProxy)
  }

  func startLocalProxy(_ request: EngineStartRequest) async throws -> NativeRuntimeIdentity {
    try await startProxy(request, expectedMode: .localProxy)
  }

  private func startProxy(_ request: EngineStartRequest, expectedMode: NativeStartMode) async throws
    -> NativeRuntimeIdentity
  {
    let mutationID = try await beginMutation()
    defer { endMutation(mutationID) }
    try Task.checkCancellation()
    try requireNoPendingStopBeforeStart()
    guard request.mode == expectedMode, expectedMode.slot.isProxyAgent,
      request.tunnelOptions == nil
    else {
      throw NativeBridgeExecutionError.failure(
        .configurationRejected,
        "Proxy start mode does not match the requested entry point."
      )
    }
    do {
      try await proxy.ensureRegistered()
    } catch {
      throw Self.map(error)
    }
    try Task.checkCancellation()
    let descriptor = try request.descriptor(slot: expectedMode.slot)
    let owner = NativeStopOwner(mode: descriptor.slot.authorityMode)
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
      let failure = Self.map(error)
      // Preparation can fail after Authority has recorded the attempt but before
      // its authorization reply reaches us. Keep the exact failed generation
      // until both the owner and independent Authority observation prove Off.
      try await proveFailedStartOff(
        NativeStopTransaction(
          owner: owner, commandContext: request.context, descriptor: descriptor))
      throw failure
    }
    do {
      try Task.checkCancellation()
      try preflightCredentials(request)
    } catch {
      try await cancelSystemProxyPreparation(
        prepared,
        after: error,
        context: "credential preflight failed",
        owner: owner,
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
          owner,
          descriptor: descriptor,
          commandContext: request.context,
          after: originalError,
          cancellationFailure: error)
      }
      let transaction = NativeStopTransaction(
        owner: owner,
        commandContext: request.context,
        descriptor: descriptor)
      try await proveFailedStartOff(transaction)
      throw Self.map(originalError)
    }
    do {
      try Task.checkCancellation()
      let status = try await queryStatus()
      let runtime: NativeRuntimeIdentity
      switch (expectedMode, status) {
      case (.localProxy, .localProxy(let identity)), (.systemProxy, .systemProxy(let identity)):
        runtime = identity
      default:
        throw NativeBridgeExecutionError.failure(
          .identityRejected, "ProxyAgent reported the wrong mode.")
      }
      guard runtime.context == request.context,
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
        owner,
        descriptor: descriptor,
        commandContext: request.context,
        after: error)
    }
  }

  private func cancelSystemProxyPreparation(
    _ prepared: HostPreparedSystemProxyStart,
    after originalError: Error,
    context: String,
    owner: NativeStopOwner,
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
        owner: owner,
        commandContext: commandContext,
        descriptor: descriptor)
    )
    throw Self.map(originalError)
  }

  func stopSystemProxy(_ context: EngineCommandContext) async throws {
    try await stopProxy(context, owner: .systemProxy)
  }

  func stopLocalProxy(_ context: EngineCommandContext) async throws {
    try await stopProxy(context, owner: .localProxy)
  }

  private func stopProxy(_ context: EngineCommandContext, owner: NativeStopOwner) async throws {
    let mutationID = try await beginMutation()
    defer { endMutation(mutationID) }
    if try await acknowledgeCompletedStartCleanup(owner, context: context) {
      return
    }
    if try await resumePendingFailedStartOff(owner, context: context) {
      return
    }
    if try await prepareExplicitStop(owner, context: context) {
      try await drivePendingStop(restoringSettingsFirst: owner == .systemProxy)
    }
  }
}

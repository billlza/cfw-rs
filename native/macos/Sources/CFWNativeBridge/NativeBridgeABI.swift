import CFWAppleNetwork
import CFWCredentialVault
import CFWSharedProtocol
import Foundation
@preconcurrency import Security

private struct HostSigningIdentity {
  let teamIdentifier: String

  static func current() throws -> HostSigningIdentity {
    guard Bundle.main.bundleIdentifier == "com.bill.clashformac" else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "Native bridge is loaded by an unexpected host bundle."
      )
    }
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "Unable to inspect the host signing identity."
      )
    }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "Unable to resolve the host static signing identity."
      )
    }
    var information: CFDictionary?
    guard
      SecCodeCopySigningInformation(
        staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
        == errSecSuccess,
      let values = information as? [CFString: Any],
      let teamIdentifier = values[kSecCodeInfoTeamIdentifier] as? String
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "The host signature does not contain a Team ID."
      )
    }
    guard teamIdentifier == GlobalAuthorityConnectionContract.teamIdentifier else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "The host signature does not match the product Team ID."
      )
    }
    _ = try CodeIdentityRequirement(
      expectedTeamIdentifier: teamIdentifier,
      expectedBundleIdentifier: "com.bill.clashformac"
    )
    return HostSigningIdentity(teamIdentifier: teamIdentifier)
  }
}

private enum ProductionNativeBridge {
  static let coordinator: Result<NativeBridgeCoordinator, NativeBridgeExecutionError> = Result {
    let signing = try HostSigningIdentity.current()
    let teamIdentifier = signing.teamIdentifier
    let installer = OSSystemExtensionInstaller(
      extensionIdentifier: "com.bill.clashformac.packet-tunnel",
      approvalHandler: {}
    )
    // One shared, typed, bounded Host Authority client backs both the machine-wide
    // lease inspector and the Tunnel-start preparer. Its connection lifecycle
    // (bounded timeouts, invalidation/interruption) fails closed.
    let authorityClient = RegistrationGatedAuthorityClient(
      authority: BoundedAuthorityXPCClient(
        remote: NSXPCGlobalAuthorityRemote(role: .host)))
    let enrollment = AuthorityInstallationEnrollment()
    let tunnel = try NetworkExtensionHostBridge(
      providerBundleIdentifier: "com.bill.clashformac.packet-tunnel",
      installer: installer,
      preparer: AuthorityBackedTunnelStartPreparer(
        authority: authorityClient,
        enrollment: enrollment),
      preferenceMutationKeychainAccessGroup:
        "\(teamIdentifier).com.bill.clashformac"
    )
    let proxy = try AuthenticatedProxyAgentTransport(
      machServiceName: "com.bill.clashformac.proxy-agent",
      teamIdentifier: teamIdentifier,
      proxyAgentBundleIdentifier: "com.bill.clashformac.proxy-agent"
    )
    let credentialVault = try CredentialVault(
      accessGroup: "\(teamIdentifier).com.bill.clashformac.credentials"
    )
    return NativeBridgeCoordinator(
      proxy: proxy,
      systemProxyPreparer: AuthorityBackedSystemProxyStartPreparer(
        authority: authorityClient,
        enrollment: enrollment),
      tunnel: tunnel,
      engineLease: GlobalAuthorityEngineLeaseInspector(authority: authorityClient),
      credentialVault: credentialVault,
      hostOperationLease: KernelNativeHostOperationLeaseAcquirer()
    )
  }.mapError { error in
    if let error = error as? NativeBridgeExecutionError {
      return error
    }
    if error is AppleNetworkError {
      return NativeBridgeCoordinator.map(error)
    }
    return .failure(
      .unavailable, "Native bridge initialization failed: \(error.localizedDescription)")
  }
}

private final class NativeBridgeABIExecutor: @unchecked Sendable {
  static let shared = NativeBridgeABIExecutor()

  func malformedRequestResponse() -> Data {
    encode(
      NativeResponseEnvelope(
        requestID: nil,
        failure: NativeBridgeFailure(
          code: .configurationRejected,
          message: "Native bridge request is malformed or exceeds its fixed bound."
        )
      )
    )
  }

  func cancellationResponse(requestID: UUID) -> Data {
    encode(
      NativeResponseEnvelope(
        requestID: requestID,
        failure: NativeBridgeFailure(
          code: .timeout,
          message: "Native operation was cancelled at its bounded wait boundary."
        )
      )
    )
  }

  func execute(_ request: NativeRequestEnvelope) async -> Data {
    do {
      try Task.checkCancellation()
      let coordinator = try ProductionNativeBridge.coordinator.get()
      let result = try await coordinator.execute(request.command)
      // Cancellation owns the terminal outcome even when it races with the
      // coordinator's final successful await boundary.
      try Task.checkCancellation()
      return encode(NativeResponseEnvelope(requestID: request.requestID, result: result))
    } catch {
      let mapped = NativeBridgeCoordinator.map(error)
      return encode(
        NativeResponseEnvelope(requestID: request.requestID, failure: mapped.responseFailure)
      )
    }
  }

  private func encode(_ response: NativeResponseEnvelope) -> Data {
    do {
      return try NativeBridgeProtocolCodec.encodeResponse(response)
    } catch {
      // This fixed response is substantially below the response bound and has
      // no user-controlled content. If encoding it fails, the C boundary still
      // invokes its callback exactly once with an empty response, which Rust
      // treats as an explicit internal error rather than success.
      return Data()
    }
  }
}

enum NativeBridgeABITiming {
  static let operationBudgetMilliseconds = 30_000
  static let operationBudget: Duration = .milliseconds(operationBudgetMilliseconds)
}

private final class NativeBridgeABIRequest: @unchecked Sendable {
  struct Terminal {
    let response: Data
    let watchdog: Task<Void, Never>?
  }

  private let lock = NSLock()
  private let cancellationResponse: Data
  private var task: Task<Void, Never>?
  private var watchdog: Task<Void, Never>?
  private var cancellationRequested = false
  private var completed = false

  init(cancellationResponse: Data) {
    self.cancellationResponse = cancellationResponse
  }

  func install(task: Task<Void, Never>) {
    let cancelImmediately = lock.withLock {
      guard !completed else { return true }
      self.task = task
      return cancellationRequested
    }
    if cancelImmediately { task.cancel() }
  }

  func install(watchdog: Task<Void, Never>) {
    let cancelImmediately = lock.withLock {
      guard !completed else { return true }
      self.watchdog = watchdog
      return false
    }
    if cancelImmediately { watchdog.cancel() }
  }

  @discardableResult
  func cancel() -> Bool {
    let outcome = lock.withLock { () -> (Bool, Task<Void, Never>?) in
      guard !completed else { return (false, nil) }
      cancellationRequested = true
      return (true, self.task)
    }
    outcome.1?.cancel()
    return outcome.0
  }

  func finish(response: Data) -> Terminal? {
    lock.withLock {
      guard !completed else { return nil }
      completed = true
      let terminalResponse = cancellationRequested ? cancellationResponse : response
      let terminalWatchdog = watchdog
      task = nil
      watchdog = nil
      return Terminal(response: terminalResponse, watchdog: terminalWatchdog)
    }
  }
}

/// Process-local ownership for accepted ABI requests. This registry is not an
/// authority or mutation lock: `NativeBridgeCoordinator` and its kernel lease
/// remain authoritative. Its sole job is to bind cancellation to the exact
/// Swift Task and preserve the callback until that Task reaches a terminal
/// cleanup result.
final class NativeBridgeABIRequestRegistry: @unchecked Sendable {
  typealias Sleep = @Sendable (Duration) async throws -> Void

  static let shared = NativeBridgeABIRequestRegistry()

  private let lock = NSLock()
  private let operationBudget: Duration
  private let sleep: Sleep
  private var requests: [UUID: NativeBridgeABIRequest] = [:]

  init(
    operationBudget: Duration = NativeBridgeABITiming.operationBudget,
    sleep: @escaping Sleep = { duration in
      try await Task<Never, Never>.sleep(for: duration)
    }
  ) {
    precondition(operationBudget > .zero, "Native ABI operation budget must be positive")
    self.operationBudget = operationBudget
    self.sleep = sleep
  }

  func submit(
    requestID: UUID,
    admittedAt: ContinuousClock.Instant = .now,
    cancellationResponse: Data,
    completion: @escaping @Sendable (Data) -> Void,
    operation: @escaping @Sendable () async -> Data
  ) -> Bool {
    let request = NativeBridgeABIRequest(cancellationResponse: cancellationResponse)
    let inserted = lock.withLock {
      guard requests[requestID] == nil else { return false }
      requests[requestID] = request
      return true
    }
    guard inserted else { return false }

    let task = Task { [self, request] in
      let response = await operation()
      finish(requestID: requestID, request: request, response: response, completion: completion)
    }
    request.install(task: task)

    let deadline = admittedAt.advanced(by: operationBudget)
    let watchdog = Task { [sleep, request] in
      do {
        let remaining = ContinuousClock.now.duration(to: deadline)
        if remaining > .zero {
          try await sleep(remaining)
        }
        request.cancel()
      } catch is CancellationError {
        // Normal terminal completion cancels the watchdog.
      } catch {
        // A production sleep has no other error. A test-injected scheduler
        // failure is fail-closed as cancellation rather than an unbounded Task.
        request.cancel()
      }
    }
    request.install(watchdog: watchdog)
    return true
  }

  @discardableResult
  func cancel(requestID: UUID) -> Bool {
    let request = lock.withLock { requests[requestID] }
    guard let request else { return false }
    return request.cancel()
  }

  var activeRequestCount: Int { lock.withLock { requests.count } }

  private func finish(
    requestID: UUID,
    request: NativeBridgeABIRequest,
    response: Data,
    completion: @escaping @Sendable (Data) -> Void
  ) {
    guard let terminal = request.finish(response: response) else { return }
    let removed = lock.withLock { () -> Bool in
      guard requests[requestID] === request else { return false }
      requests.removeValue(forKey: requestID)
      return true
    }
    guard removed else { return }
    terminal.watchdog?.cancel()
    completion(terminal.response)
  }
}

private struct NativeBridgeCallback: @unchecked Sendable {
  let function: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int) -> Void
  let context: UnsafeMutableRawPointer?

  func invoke(with data: Data) {
    data.withUnsafeBytes { bytes in
      function(context, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
    }
  }
}

private final class NativeBridgeRequestBuffer: @unchecked Sendable {
  private var data: Data

  init(bytes: UnsafePointer<UInt8>, count: Int) {
    data = Data(bytes: bytes, count: count)
  }

  deinit {
    erase()
  }

  func decodeRequest() throws -> NativeRequestEnvelope {
    try NativeBridgeProtocolCodec.decodeRequest(data)
  }

  func execute(_ request: NativeRequestEnvelope) async -> Data {
    defer { erase() }
    return await NativeBridgeABIExecutor.shared.execute(request)
  }

  private func erase() {
    data.resetBytes(in: data.startIndex..<data.endIndex)
    data.removeAll(keepingCapacity: false)
  }
}

@_cdecl("cfw_native_bridge_execute_v1")
public func cfwNativeBridgeExecuteV1(
  _ requestBytes: UnsafePointer<UInt8>?,
  _ requestLength: Int,
  _ callback: (
    @convention(c) (
      UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int
    ) -> Void
  )?,
  _ callbackContext: UnsafeMutableRawPointer?
) -> Int32 {
  let admittedAt = ContinuousClock.now
  guard let callback else {
    return 1
  }
  guard requestLength > 0,
    requestLength <= NativeBridgeProtocolConstants.maximumRequestBytes,
    let requestBytes
  else {
    return 2
  }
  let request = NativeBridgeRequestBuffer(bytes: requestBytes, count: requestLength)
  let completion = NativeBridgeCallback(function: callback, context: callbackContext)
  let envelope: NativeRequestEnvelope
  do {
    envelope = try request.decodeRequest()
  } catch {
    completion.invoke(with: NativeBridgeABIExecutor.shared.malformedRequestResponse())
    return 0
  }
  let accepted = NativeBridgeABIRequestRegistry.shared.submit(
    requestID: envelope.requestID,
    admittedAt: admittedAt,
    cancellationResponse: NativeBridgeABIExecutor.shared.cancellationResponse(
      requestID: envelope.requestID),
    completion: { data in completion.invoke(with: data) },
    operation: { await request.execute(envelope) }
  )
  return accepted ? 0 : 3
}

@_cdecl("cfw_native_bridge_cancel_v1")
public func cfwNativeBridgeCancelV1(
  _ requestIDBytes: UnsafePointer<UInt8>?,
  _ requestIDLength: Int
) -> Int32 {
  guard requestIDLength == 36, let requestIDBytes else { return 2 }
  let data = Data(bytes: requestIDBytes, count: requestIDLength)
  guard let text = String(data: data, encoding: .utf8), text == text.lowercased(),
    let requestID = UUID(uuidString: text), requestID.uuidString.lowercased() == text
  else {
    return 2
  }
  return NativeBridgeABIRequestRegistry.shared.cancel(requestID: requestID) ? 0 : 3
}

import CFWCredentialTransport
import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import OSLog
import Synchronization

/// Admits one call of a kind at a time. A call that returned frees its slot
/// before its reply, so the Host's next call, which it sends once that reply
/// arrived, finds the slot free; a call still inside libbox at its reply keeps
/// the slot until it returns.
private final class LibboxCallSlot: Sendable {
  private let holder = Mutex<UUID?>(nil)

  /// The admitted call's token, or nil while another call holds the slot.
  func admit() -> UUID? {
    holder.withLock { holder in
      guard holder == nil else { return nil }
      let token = UUID()
      holder = token
      return token
    }
  }

  /// Frees the slot if the call `token` names still holds it, and returns
  /// whether it did.
  @discardableResult
  func release(_ token: UUID) -> Bool {
    holder.withLock { holder in
      guard holder == token else { return false }
      holder = nil
      return true
    }
  }
}

final class ProxyAgentService: NSObject, CFWProxyAgentXPCProtocol, @unchecked Sendable {
  private static let authorizationLogger = Logger(
    subsystem: "com.bill.clashformac", category: "system-proxy-authorization")
  private static let validationLogger = Logger(
    subsystem: "com.bill.clashformac", category: "configuration-validation")
  private let lifecycle: any ProxySystemProxyOwning
  private let configurationChecker: any LibboxConfigurationChecking
  private let profileProbe: any LibboxProfileProbing
  private let profileProbeSlot = LibboxCallSlot()
  private let checkSlot = LibboxCallSlot()
  private let boundedCall: LibboxBoundedCall
  private let requests: ProxyAgentUnansweredRequests
  private let preferences: SCPreferencesSystemProxyPreferences
  private let journalStore: any ProxyOwnershipJournalStoring
  private let authorizationQueue = DispatchQueue(
    label: "com.bill.clashformac.proxy-authorization")
  private let authorizationLock = NSLock()
  private var authorizationPending = false

  init(
    lifecycle: any ProxySystemProxyOwning,
    configurationChecker: any LibboxConfigurationChecking,
    preferences: SCPreferencesSystemProxyPreferences,
    journalStore: any ProxyOwnershipJournalStoring,
    profileProbe: any LibboxProfileProbing = SourceBuiltLibboxProfileProbe(),
    boundedCall: LibboxBoundedCall = LibboxBoundedCall(),
    requests: ProxyAgentUnansweredRequests = ProxyAgentUnansweredRequests()
  ) {
    self.profileProbe = profileProbe
    self.boundedCall = boundedCall
    self.requests = requests
    self.lifecycle = lifecycle
    self.configurationChecker = configurationChecker
    self.preferences = preferences
    self.journalStore = journalStore
  }

  func testProfileProxies(
    _ configuration: Data, proxies: Data, timeoutMS: UInt16, targetURL: String,
    expectedStatus: String,
    withReply reply: @escaping (Data?, NSError?) -> Void
  ) {
    let response = ProxyXPCReply(reply, requests: requests)
    let names: [String]
    do {
      guard !configuration.isEmpty,
        configuration.count <= Int(NativeProtocolConstants.maximumConfigurationBytes),
        proxies.count <= 32768
      else { throw NativeBridgeProtocolError.invalidConfiguration }
      names = try JSONDecoder().decode([String].self, from: proxies)
      try ProfileDelayTestRequest.validateTargets(names, timeoutMS: timeoutMS)
      try ProfileDelayTestRequest.validateTargetURL(targetURL, expectedStatus: expectedStatus)
    } catch {
      response.finish(data: nil, error: ProfileProbeServiceFailure.invalidRequest.error)
      return
    }
    guard lifecycle.callsLibbox else {
      response.finish(data: nil, error: ProfileProbeServiceFailure.agentEnding.error)
      return
    }
    guard let slot = profileProbeSlot.admit() else {
      response.finish(data: nil, error: ProfileProbeServiceFailure.busy.error)
      return
    }
    let bytes = SensitiveDataBuffer(copying: configuration)
    let profileProbe = profileProbe
    boundedCall.run(
      replyDeadline: .milliseconds(Int64(timeoutMS))
        + ProxyAgentCallBudget.profileProbeReplyAllowance,
      qos: .utility,
      {
        try bytes.withErasingData { configuration in
          try profileProbe.test(
            configuration: configuration, proxies: names, timeoutMS: timeoutMS,
            targetURL: targetURL, expectedStatus: expectedStatus)
        }
      },
      reply: { [self] answer in
        if case .returned(let result) = answer {
          retireIfItLeftItsInstance(result)
          profileProbeSlot.release(slot)
        }
        switch answer {
        case .returned(.success(let result)):
          do {
            response.finish(data: try JSONEncoder().encode(result), error: nil)
          } catch {
            response.finish(data: nil, error: ProfileProbeServiceFailure.executionFailed.error)
          }
        case .returned(.failure):
          response.finish(data: nil, error: ProfileProbeServiceFailure.executionFailed.error)
        case .stillRunning:
          response.finish(data: nil, error: ProfileProbeServiceFailure.timedOut.error)
        }
      },
      ended: { [self] end in
        switch end {
        case .returned(let result):
          // A probe that returned before its reply decided all this there.
          if profileProbeSlot.release(slot) { retireIfItLeftItsInstance(result) }
        case .abandoned(let failure):
          retire(after: failure)
        }
      })
  }

  /// A call whose instance libbox could not close leaves in this process what
  /// only its end releases. Decided before the call's answer, so a request
  /// the Host sends on that answer finds the agent retired.
  private func retireIfItLeftItsInstance<Value>(_ result: Result<Value, any Error>) {
    guard case .failure(let error as LibboxRuntimeError) = result,
      let unclosed = error.unclosedCallInstance
    else { return }
    retire(after: unclosed)
  }

  /// A call abandoned inside libbox, or one whose instance libbox could not
  /// close, leaves in this process what only its end releases.
  private func retire(after failure: LibboxInstanceUnclosable) {
    Self.validationLogger.fault(
      "A configuration check or latency test left libbox holding what it built; the ProxyAgent retires"
    )
    lifecycle.retire(after: failure)
  }

  func authorizeSystemProxy(restorationOnly: Bool, withReply reply: @escaping (NSError?) -> Void) {
    let response = ProxyXPCReply({ _, error in reply(error) }, requests: requests)
    let admitted = authorizationLock.withLock {
      guard !authorizationPending else { return false }
      authorizationPending = true
      return true
    }
    guard admitted else {
      response.finish(
        data: nil,
        error: NSError(
          domain: SystemProxyAuthorizationFailure.domain,
          code: SystemProxyAuthorizationFailure.pending.rawValue))
      return
    }
    authorizationQueue.async { [self] in
      // The request stops counting as pending before its reply, so the Host
      // may ask again as soon as the reply arrives.
      let finish: @Sendable (NSError?) -> Void = { [self] error in
        authorizationLock.withLock { authorizationPending = false }
        response.finish(data: nil, error: error)
      }
      do {
        let needsAuthorization = try !restorationOnly || journalStore.load() != nil
        guard needsAuthorization else {
          finish(nil)
          return
        }
        try preferences.authorizeForStart()
        // Settings the agent could not restore without these rights are
        // restored with them before the reply, so the Off or quit that follows
        // it finds them restored. The reply waits behind any operation already
        // on the lifecycle's queue, an engine start included. A spent agent
        // ends only after this reply was handed to XPC.
        lifecycle.restoreSettingsAfterAuthorization { finish(nil) }
      } catch SystemProxyPreferencesError.authorizationDenied {
        finish(
          NSError(
            domain: SystemProxyAuthorizationFailure.domain,
            code: SystemProxyAuthorizationFailure.denied.rawValue))
      } catch {
        Self.authorizationLogger.error(
          "Network authorization request failed: \(String(describing: error), privacy: .public)")
        finish(
          NSError(
            domain: SystemProxyAuthorizationFailure.domain,
            code: SystemProxyAuthorizationFailure.internalFailure.rawValue))
      }
    }
  }

  func execute(
    _ requestData: Data,
    withReply reply: @escaping (Data?, NSError?) -> Void
  ) {
    let reply = ProxyXPCReply(reply, requests: requests)
    let request: RequestEnvelope
    do {
      request = try ProtocolCodec.decodeRequest(requestData)
    } catch {
      reply.finish(data: nil, error: protocolError())
      return
    }

    switch request.command.kind {
    case .snapshot:
      lifecycle.snapshot { [self] snapshot in
        respond(
          requestID: request.requestID,
          result: Result {
            try CommandResult(kind: .snapshot, snapshot: snapshot)
          },
          reply: reply
        )
      }
    case .startLocalProxy, .startSystemProxy:
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          .agent(.startRequiresOwnerAuthorization),
          message: "System proxy start requires a one-use Authority authorization."),
        reply: reply
      )
    case .stop:
      guard let configuration = request.command.configuration else {
        respond(
          requestID: request.requestID,
          failure: EngineFailure(
            .agent(.missingStopGeneration),
            message: "Stop commands must identify the exact active configuration."),
          reply: reply
        )
        return
      }
      lifecycle.stop(expectedConfiguration: configuration) { [self] result in
        respondToOperation(requestID: request.requestID, result: result, reply: reply)
      }
    case .restoreSettingsBeforeStop:
      guard let configuration = request.command.configuration else {
        respond(
          requestID: request.requestID,
          failure: EngineFailure(
            .agent(.missingStopGeneration),
            message: "Restoring settings before a stop must identify the exact configuration."),
          reply: reply
        )
        return
      }
      lifecycle.restoreSettingsBeforeStop(expectedConfiguration: configuration) {
        [self] result in
        respondToOperation(requestID: request.requestID, result: result, reply: reply)
      }
    case .installTunnel, .startTunnel, .validateConfiguration:
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          .agent(.wrongProcessBoundary),
          message: "Tunnel commands are accepted only by the host bridge/provider boundary."),
        reply: reply
      )
    }
  }

  func startSystemProxy(
    _ capabilityData: Data,
    context contextData: Data,
    configuration configurationData: Data,
    request requestData: Data,
    withReply reply: @escaping (Data?, NSError?) -> Void
  ) {
    let reply = ProxyXPCReply(reply, requests: requests)
    let request: RequestEnvelope
    let context: ProxyOwnerContext
    var capabilityBytes = capabilityData
    var configurationBytes = configurationData
    defer {
      capabilityBytes.resetBytes(
        in: capabilityBytes.startIndex..<capabilityBytes.endIndex)
      capabilityBytes.removeAll(keepingCapacity: false)
      configurationBytes.resetBytes(
        in: configurationBytes.startIndex..<configurationBytes.endIndex)
      configurationBytes.removeAll(keepingCapacity: false)
    }
    do {
      request = try ProtocolCodec.decodeRequest(requestData)
      context = try AuthorityV1Codec.decodeCanonical(
        ProxyOwnerContext.self, from: contextData)
    } catch {
      reply.finish(data: nil, error: protocolError())
      return
    }
    guard request.command.kind == .startLocalProxy || request.command.kind == .startSystemProxy,
      let descriptor = request.command.configuration,
      descriptor.slot.isProxyAgent,
      context.operation.mode == descriptor.slot.authorityMode,
      capabilityBytes.count == AuthorityV1Limits.capabilityBytes,
      context.operation.root.installationID.rawValue == descriptor.installationID,
      context.operation.root.epoch == descriptor.epoch,
      context.operation.root.generation == descriptor.generation,
      context.operation.configSHA256 == descriptor.sha256,
      context.operation.identitySHA256 == descriptor.identitySHA256
    else {
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          .agent(.invalidOwnerAuthorization),
          message: "System proxy owner authorization does not match the start request."),
        reply: reply
      )
      return
    }
    do {
      try descriptor.validateConfigurationBytes(configurationBytes)
    } catch {
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          .agent(.invalidRuntimeConfiguration),
          message: "System proxy runtime bytes do not match the authorized descriptor."),
        reply: reply
      )
      return
    }
    let capability: OwnerCapability
    do {
      capability = try OwnerCapability(copying: capabilityBytes)
    } catch {
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          .agent(.invalidOwnerAuthorization),
          message: "System proxy owner authorization is malformed."),
        reply: reply
      )
      return
    }
    let authorization = ProxyOwnerAuthorization(
      context: context, capability: capability)
    let runtimeConfiguration = SensitiveDataBuffer(copying: configurationBytes)
    lifecycle.start(
      configuration: runtimeConfiguration,
      descriptor: descriptor,
      authorization: authorization
    ) { [self] result in
      authorization.erase()
      respondToOperation(requestID: request.requestID, result: result, reply: reply)
    }
  }

  func validateConfiguration(
    _ configurationData: Data,
    request requestData: Data,
    withReply reply: @escaping (Data?, NSError?) -> Void
  ) {
    let reply = ProxyXPCReply(reply, requests: requests)
    let request: RequestEnvelope
    do {
      request = try ProtocolCodec.decodeRequest(requestData)
    } catch {
      reply.finish(data: nil, error: protocolError())
      return
    }
    guard request.command.kind == .validateConfiguration,
      request.command.configuration != nil,
      !configurationData.isEmpty,
      configurationData.count <= Int(NativeProtocolConstants.maximumConfigurationBytes)
    else {
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          .agent(.invalidValidationRequest),
          message: "Configuration validation request is malformed or exceeds its bound."),
        reply: reply
      )
      return
    }
    guard lifecycle.callsLibbox else {
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          .agent(.agentEnding),
          message: "The proxy agent is ending; the next one checks the configuration."),
        reply: reply)
      return
    }
    guard let slot = checkSlot.admit() else {
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          .agent(.configurationCheckTimedOut),
          message: "An earlier configuration check is still running. Retry shortly."),
        reply: reply)
      return
    }
    // The check leaves the connection's queue, so a check inside libbox holds
    // back no later message on that connection.
    let configuration = SensitiveDataBuffer(copying: configurationData)
    let configurationChecker = configurationChecker
    let requestID = request.requestID
    boundedCall.run(
      replyDeadline: ProxyAgentCallBudget.configurationCheckReply,
      qos: .userInitiated,
      { try configuration.withErasingData { try configurationChecker.check(configuration: $0) } },
      reply: { [self] answer in
        if case .returned(let result) = answer {
          retireIfItLeftItsInstance(result)
          checkSlot.release(slot)
        }
        switch answer {
        case .returned(.success):
          respond(
            requestID: requestID, result: Result { try CommandResult(kind: .accepted) },
            reply: reply)
        case .returned(.failure(let error)):
          respond(requestID: requestID, failure: Self.checkFailure(for: error), reply: reply)
        case .stillRunning:
          respond(
            requestID: requestID,
            failure: EngineFailure(
              .agent(.configurationCheckTimedOut),
              message: "The configuration check did not finish in time. Retry shortly."),
            reply: reply)
        }
      },
      ended: { [self] end in
        switch end {
        case .returned(let result):
          // A check that returned before its reply decided all this there.
          if checkSlot.release(slot) { retireIfItLeftItsInstance(result) }
        case .abandoned(let failure):
          retire(after: failure)
        }
      })
  }

  /// What a configuration check that returned an error tells the Host.
  static func checkFailure(for error: any Error) -> EngineFailure {
    guard let error = error as? LibboxRuntimeError else {
      return EngineFailure(
        .agent(.validatorFailed),
        message: "Configuration validation failed at an explicit internal boundary.")
    }
    if case .configurationCheckCleanupFailed = error {
      // The configuration passed; what the check built stays in this process.
      validationLogger.fault(
        "libbox could not close the instance it built to check a configuration")
    }
    return validationFailure(for: error)
  }

  /// What a configuration check that did not pass tells the Host. Only a
  /// configuration libbox read and refused is rejected. A check that could not
  /// run, or whose instance did not close, may run again; any other runtime
  /// error cannot come from a check and failed at an internal boundary.
  static func validationFailure(for error: LibboxRuntimeError) -> EngineFailure {
    switch error {
    case .invalidConfigurationSize, .invalidConfigurationEncoding, .invalidConfigurationJSON,
      .configurationCheckFailed:
      EngineFailure(
        .agent(.configurationRejected), message: "Source-built libbox rejected the configuration.")
    case .libboxUnavailable, .missingBundleSetting, .appGroupUnavailable, .unsafeRuntimeDirectory,
      .setupConflict, .setupFailed:
      EngineFailure(
        .agent(.validatorUnavailable), message: "Source-built libbox validation is unavailable.")
    case .configurationCheckCleanupFailed:
      EngineFailure(
        .agent(.configurationCheckCleanupFailed),
        message: "Source-built libbox could not close what it built to check the configuration.")
    case .configurationCheckReturnedNothing, .profileProbeCleanupFailed,
      .unexpectedPacketDescriptor, .missingPacketDescriptor,
      .packetDescriptorAlreadyTransferred, .unsupportedPlatformOperation,
      .networkMonitorAlreadyStarted, .networkMonitorUnavailable, .networkMonitorTimedOut,
      .alreadyStarted, .serverCreationFailed, .serviceStartFailed, .serviceStartTimedOut,
      .invalidRuntimeEndpoints, .invalidEndpointConflict, .endpointConflict, .serviceNotRunning:
      EngineFailure(
        .agent(.validatorFailed),
        message: "Configuration validation failed at an explicit internal boundary.")
    }
  }

  private func protocolError() -> NSError {
    NSError(
      domain: "com.bill.clashformac.proxy-agent.protocol",
      code: 1,
      userInfo: [NSLocalizedDescriptionKey: "ProxyAgent request is malformed."]
    )
  }

  private func respondToOperation(
    requestID: RequestID,
    result: Result<Void, ProxySessionLifecycleError>,
    reply: ProxyXPCReply
  ) {
    switch result {
    case .success:
      respond(
        requestID: requestID,
        result: Result { try CommandResult(kind: .accepted) },
        reply: reply
      )
    case .failure(let error):
      respond(requestID: requestID, failure: error.engineFailure, reply: reply)
    }
  }

  private func respond(
    requestID: RequestID,
    result: Result<CommandResult, Error>,
    reply: ProxyXPCReply
  ) {
    do {
      let commandResult = try result.get()
      let response = ResponseEnvelope(requestID: requestID, result: commandResult)
      reply.finish(data: try ProtocolCodec.encode(response), error: nil)
    } catch {
      reply.finish(
        data: nil,
        error: NSError(
          domain: "com.bill.clashformac.proxy-agent.encoding",
          code: 2,
          userInfo: [NSLocalizedDescriptionKey: "ProxyAgent response encoding failed."]
        )
      )
    }
  }

  private func respond(
    requestID: RequestID,
    failure: EngineFailure,
    reply: ProxyXPCReply
  ) {
    do {
      let response = ResponseEnvelope(requestID: requestID, failure: failure)
      reply.finish(data: try ProtocolCodec.encode(response), error: nil)
    } catch {
      reply.finish(
        data: nil,
        error: NSError(
          domain: "com.bill.clashformac.proxy-agent.encoding",
          code: 2,
          userInfo: [NSLocalizedDescriptionKey: "ProxyAgent response encoding failed."]
        )
      )
    }
  }
}

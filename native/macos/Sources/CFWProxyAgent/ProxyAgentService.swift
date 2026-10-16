import CFWCredentialTransport
import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import OSLog
import Synchronization

private final class ProxyXPCReply: @unchecked Sendable {
  private let lock = NSLock()
  private var handler: ((Data?, NSError?) -> Void)?

  init(_ handler: @escaping (Data?, NSError?) -> Void) {
    self.handler = handler
  }

  func finish(data: Data?, error: NSError?) {
    lock.lock()
    let handler = handler
    self.handler = nil
    lock.unlock()
    handler?(data, error)
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
  private let profileProbeLock = NSLock()
  private var profileProbePending = false
  private let profileProbeQueue = DispatchQueue(
    label: "com.bill.clashformac.profile-probe", qos: .utility)
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
    profileProbe: any LibboxProfileProbing = SourceBuiltLibboxProfileProbe()
  ) {
    self.profileProbe = profileProbe
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
    let response = ProxyXPCReply(reply)
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
    let admitted = profileProbeLock.withLock {
      guard !profileProbePending else { return false }
      profileProbePending = true
      return true
    }
    guard admitted else {
      response.finish(data: nil, error: ProfileProbeServiceFailure.busy.error)
      return
    }
    profileProbeQueue.async { [self] in
      var bytes = configuration
      defer {
        bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex)
        profileProbeLock.withLock { profileProbePending = false }
      }
      do {
        let result = try profileProbe.test(
          configuration: bytes, proxies: names, timeoutMS: timeoutMS, targetURL: targetURL,
          expectedStatus: expectedStatus)
        response.finish(data: try JSONEncoder().encode(result), error: nil)
      } catch {
        response.finish(data: nil, error: ProfileProbeServiceFailure.executionFailed.error)
      }
    }
  }

  func authorizeSystemProxy(restorationOnly: Bool, withReply reply: @escaping (NSError?) -> Void) {
    let response = ProxyXPCReply { _, error in reply(error) }
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
    let reply = ProxyXPCReply(reply)
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
    let reply = ProxyXPCReply(reply)
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
    let reply = ProxyXPCReply(reply)
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
    var configuration = configurationData
    defer {
      configuration.resetBytes(in: configuration.startIndex..<configuration.endIndex)
      configuration.removeAll(keepingCapacity: false)
    }
    do {
      try configurationChecker.check(configuration: configuration)
      respond(
        requestID: request.requestID,
        result: Result { try CommandResult(kind: .accepted) },
        reply: reply
      )
    } catch let error as LibboxRuntimeError {
      if case .configurationCheckCleanupFailed = error {
        // The configuration passed; what the check built stays in this process.
        Self.validationLogger.fault(
          "libbox could not close the instance it built to check a configuration")
      }
      respond(
        requestID: request.requestID, failure: Self.validationFailure(for: error), reply: reply)
    } catch {
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          .agent(.validatorFailed),
          message: "Configuration validation failed at an explicit internal boundary."),
        reply: reply
      )
    }
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
    case .configurationCheckReturnedNothing, .unexpectedPacketDescriptor, .missingPacketDescriptor,
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

/// A connection whose sends XPC can order a block after: the block runs once
/// every message handed to the connection before it has been sent.
protocol ProxyAgentSendBarrier: AnyObject {
  func scheduleSendBarrierBlock(_ block: @escaping @Sendable () -> Void)
}

extension NSXPCConnection: ProxyAgentSendBarrier {}

/// The ProxyAgent's accepted connections, from acceptance until invalidation.
final class ProxyAgentConnections: @unchecked Sendable {
  private let lock = NSLock()
  private var connections: [ObjectIdentifier: NSXPCConnection] = [:]

  /// Tracks `connection` until it is invalidated. Call it before resuming the
  /// connection.
  func track(_ connection: NSXPCConnection) {
    let key = ObjectIdentifier(connection)
    lock.withLock { connections[key] = connection }
    connection.invalidationHandler = { [weak self] in
      self?.forget(key)
    }
  }

  var open: [any ProxyAgentSendBarrier] {
    lock.withLock { Array(connections.values) }
  }

  private func forget(_ key: ObjectIdentifier) {
    lock.withLock { _ = connections.removeValue(forKey: key) }
  }
}

/// Ends the ProxyAgent after libbox could not close a runtime: only the process
/// ending releases the listeners, descriptors and goroutines that close left
/// open. launchd starts the agent again for the Host's next request.
struct ProxyAgentProcessExit: Sendable {
  typealias Schedule = @Sendable (DispatchTime, @escaping @Sendable () -> Void) -> Void

  /// launchd starts an on-demand agent again no sooner than this after it last
  /// started it, its default `ThrottleInterval`, which the agent's job keeps,
  /// and holds every request for the agent until then, past the Host's
  /// five-second reply wait. Measured on macOS 27.0.1 on 2026-10-16: an agent
  /// that ended right after a reply had its next request answered 10.0 seconds
  /// after its start, one that ended 11 seconds after its start within 50 ms.
  static let launchdRestartThrottle: DispatchTimeInterval = .seconds(10)
  /// The agent ends no sooner than this after it started, so launchd starts its
  /// successor at once. The extra second covers the time from launchd starting
  /// the agent to the agent reading the clock.
  static let minimumLifetime: DispatchTimeInterval = .seconds(11)
  /// How long the agent waits for its connections to send the replies it gave
  /// them. The Host waits five seconds for a reply, so one still unsent then is
  /// no longer awaited.
  static let sendBarrierLimit: DispatchTimeInterval = .seconds(5)

  private static let logger = Logger(
    subsystem: "com.bill.clashformac",
    category: "proxy-agent-exit"
  )
  private let openConnections: @Sendable () -> [any ProxyAgentSendBarrier]
  private let launchedAt: DispatchTime
  private let now: @Sendable () -> DispatchTime
  private let schedule: Schedule
  private let exit: @Sendable (Int32) -> Void

  /// `launchedAt` is when the agent's process started. Dispatch time stops
  /// while the Mac sleeps, so a wait that spans a sleep ends no earlier than
  /// launchd's. `_exit` skips atexit handlers while libbox's threads still run.
  init(connections: ProxyAgentConnections, launchedAt: DispatchTime) {
    self.init(
      openConnections: { connections.open }, launchedAt: launchedAt, now: { .now() },
      schedule: { deadline, work in
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: deadline, execute: work)
      },
      exit: { _exit($0) })
  }

  init(
    openConnections: @escaping @Sendable () -> [any ProxyAgentSendBarrier],
    launchedAt: DispatchTime,
    now: @escaping @Sendable () -> DispatchTime,
    schedule: @escaping Schedule,
    exit: @escaping @Sendable (Int32) -> Void
  ) {
    self.openConnections = openConnections
    self.launchedAt = launchedAt
    self.now = now
    self.schedule = schedule
    self.exit = exit
  }

  /// Exits once the agent has run `minimumLifetime` and a send barrier has run
  /// on every open connection then, so every reply already handed to XPC, the
  /// failure's own included, has been sent; until then the spent agent keeps
  /// answering. A connection that has not sent its replies `sendBarrierLimit`
  /// later no longer holds the exit. Only the runtime can make a
  /// `LibboxInstanceUnclosable`, so nothing else can end the agent this way.
  /// Its text is never logged.
  func end(after failure: LibboxInstanceUnclosable) {
    Self.logger.fault("libbox could not close a System Proxy runtime; ending the ProxyAgent")
    schedule(max(now(), launchedAt + Self.minimumLifetime)) { [self] in
      exitOnceRepliesAreSent()
    }
  }

  private func exitOnceRepliesAreSent() {
    let exitOnce = ProxyAgentExitOnce(exit)
    let sent = DispatchGroup()
    for connection in openConnections() {
      sent.enter()
      connection.scheduleSendBarrierBlock { sent.leave() }
    }
    sent.notify(queue: .global(qos: .userInitiated)) {
      exitOnce.exit(EX_SOFTWARE)
    }
    schedule(now() + Self.sendBarrierLimit) {
      if exitOnce.exit(EX_SOFTWARE) {
        Self.logger.fault("a connection did not send its replies in time; ending the ProxyAgent")
      }
    }
  }
}

/// Calls `exit` at most once, whichever of the agent's two exit paths comes first.
private final class ProxyAgentExitOnce: Sendable {
  private let exited = Mutex(false)
  private let exitProcess: @Sendable (Int32) -> Void

  init(_ exit: @escaping @Sendable (Int32) -> Void) {
    exitProcess = exit
  }

  /// Returns whether this call ended the process.
  @discardableResult
  func exit(_ status: Int32) -> Bool {
    let first = exited.withLock { exited -> Bool in
      defer { exited = true }
      return !exited
    }
    if first {
      exitProcess(status)
    }
    return first
  }
}

final class ProxyAgentListenerDelegate: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
  private static let logger = Logger(
    subsystem: "com.bill.clashformac",
    category: "proxy-agent-xpc"
  )
  private let identityPolicy: CodeIdentityPolicy
  private let service: ProxyAgentService
  private let connections: ProxyAgentConnections

  init(
    identityPolicy: CodeIdentityPolicy, service: ProxyAgentService,
    connections: ProxyAgentConnections
  ) {
    self.identityPolicy = identityPolicy
    self.service = service
    self.connections = connections
  }

  func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection connection: NSXPCConnection
  ) -> Bool {
    do {
      try identityPolicy.configure(connection, requiredUserIdentifier: geteuid())
    } catch {
      Self.logger.error(
        "Rejected XPC connection: \(String(describing: error), privacy: .public)"
      )
      connection.invalidate()
      return false
    }

    connection.exportedInterface = NSXPCInterface(with: CFWProxyAgentXPCProtocol.self)
    connection.exportedObject = service
    connections.track(connection)
    connection.resume()
    return true
  }
}

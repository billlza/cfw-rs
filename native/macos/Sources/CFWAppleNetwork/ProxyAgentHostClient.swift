import CFWSharedProtocol
import Darwin
import Foundation
import ServiceManagement

public enum ProxyAgentRegistrationStatus: Equatable, Sendable {
  case enabled
  case requiresApproval
  case notRegistered
  case notFound
  case unknown
}

public enum ProxyAgentHostError: Error, Equatable, Sendable {
  case registrationRequiresApproval
  case registrationUnavailable
  case registrationFailed(String)
  case transportUnavailable(String)
  case transportTimedOut
  case transportCapacityExceeded
  case authorizationDenied
  case authorizationPending
  case authorizationFailed
  case malformedResponse
  case responseMismatch
  case agentFailure(EngineFailure)
}

extension ProxyAgentHostError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .registrationRequiresApproval:
      "ProxyAgent requires approval in System Settings > Login Items."
    case .registrationUnavailable:
      "The signed ProxyAgent launch service is missing from the application bundle."
    case .registrationFailed:
      "ProxyAgent registration failed."
    case .transportUnavailable:
      "ProxyAgent XPC transport is unavailable."
    case .transportTimedOut:
      "ProxyAgent did not reply before the bounded timeout."
    case .transportCapacityExceeded:
      "ProxyAgent request capacity is exhausted."
    case .authorizationDenied:
      "macOS network authorization was not granted."
    case .authorizationPending:
      "A macOS network authorization dialog is already pending."
    case .authorizationFailed:
      "macOS network authorization could not be requested."
    case .malformedResponse:
      "ProxyAgent returned a malformed response."
    case .responseMismatch:
      "ProxyAgent response does not match the request identity."
    case .agentFailure(let failure):
      "ProxyAgent rejected the operation (\(failure.code)): \(failure.message)"
    }
  }
}

public protocol ProxyAgentServiceControlling: Sendable {
  func registrationStatus() -> ProxyAgentRegistrationStatus
  func ensureRegistered() throws
}

public protocol ProxyAgentServicing: Sendable {
  var registrationStatus: ProxyAgentRegistrationStatus { get }
  func requireRegistrationReady() throws
  func register() throws
  func unregister() async throws
}

public struct SMProxyAgentService: ProxyAgentServicing {
  public static let launchAgentPlistName = "com.bill.clashformac.proxy-agent.plist"
  private let unregistration = ServiceUnregistrationBarrier()

  public init() {}

  public var registrationStatus: ProxyAgentRegistrationStatus {
    switch SMAppService.agent(plistName: Self.launchAgentPlistName).status {
    case .enabled: .enabled
    case .requiresApproval: .requiresApproval
    case .notRegistered: .notRegistered
    case .notFound: .notFound
    @unknown default: .unknown
    }
  }

  public func requireRegistrationReady() throws {
    try unregistration.requireRegistrationReady()
  }

  public func register() throws {
    try unregistration.register {
      try SMAppService.agent(plistName: Self.launchAgentPlistName).register()
    }
  }

  public func unregister() async throws {
    try await unregistration.unregister { finish in
      SMAppService.agent(plistName: Self.launchAgentPlistName).unregister { error in
        finish(error.map { .failure($0) } ?? .success(()))
      }
    }
  }
}

public struct SMProxyAgentServiceController: ProxyAgentServiceControlling, Sendable {
  private let service: any ProxyAgentServicing

  public init(service: any ProxyAgentServicing = SMProxyAgentService()) {
    self.service = service
  }

  public func registrationStatus() -> ProxyAgentRegistrationStatus {
    service.registrationStatus
  }

  public func ensureRegistered() throws {
    do { try service.requireRegistrationReady() } catch {
      throw ProxyAgentHostError.registrationFailed("service unregistration remains pending")
    }
    switch service.registrationStatus {
    case .enabled:
      return
    case .requiresApproval:
      throw ProxyAgentHostError.registrationRequiresApproval
    case .notFound, .notRegistered:
      do {
        try service.register()
      } catch {
        switch service.registrationStatus {
        case .requiresApproval:
          throw ProxyAgentHostError.registrationRequiresApproval
        case .notFound:
          throw ProxyAgentHostError.registrationUnavailable
        case .enabled, .notRegistered, .unknown:
          throw ProxyAgentHostError.registrationFailed(error.localizedDescription)
        }
      }
      switch service.registrationStatus {
      case .enabled:
        return
      case .requiresApproval:
        throw ProxyAgentHostError.registrationRequiresApproval
      case .notRegistered, .notFound, .unknown:
        throw ProxyAgentHostError.registrationUnavailable
      }
    case .unknown:
      throw ProxyAgentHostError.registrationUnavailable
    }
  }
}

public protocol ProxyAgentTransporting: Sendable {
  func testProfileProxies(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) async throws
    -> [ProfileProxyDelay]
  func authorizeSystemProxy(restorationOnly: Bool) async throws
  func registrationStatus() async -> ProxyAgentRegistrationStatus
  func ensureRegistered() async throws
  func start(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    authorization: HostPreparedSystemProxyStart
  ) async throws
  func stop(configuration: ConfigurationDescriptor) async throws
  /// Has the ProxyAgent restore the System Proxy settings of the session the
  /// configuration names while its engine keeps running, before its stop.
  /// Only the current build understands this, so it needs that build.
  func restoreSettingsBeforeStop(configuration: ConfigurationDescriptor) async throws
  func snapshot() async throws -> EngineSnapshot
  func validateConfiguration(
    _ configuration: Data,
    descriptor: ConfigurationDescriptor
  ) async throws
}

/// The one-release, read-only compatibility boundary for the installed 40019
/// ProxyAgent. It is deliberately separate from `ProxyAgentTransporting`: the
/// current engine protocol remains strictly v6 and has no legacy fallback.
package protocol Installed40019ProxySnapshotting: Sendable {
  func snapshotInstalled40019ForMigration() async throws -> EngineSnapshot
}

private struct Installed40019ProxySnapshotRequest: Encodable, Sendable {
  let schemaVersion: UInt16 = 5
  let requestID: RequestID
  let command: NativeCommand

  init(requestID: RequestID) throws {
    self.requestID = requestID
    command = try NativeCommand(kind: .snapshot)
  }
}

private struct Installed40019ProxySnapshotResponse: Decodable, Sendable {
  let schemaVersion: UInt16
  let requestID: RequestID
  let result: CommandResult?
  let failure: EngineFailure?

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    schemaVersion = try container.decode(UInt16.self, forKey: .schemaVersion)
    guard schemaVersion == 5 else {
      throw ProtocolValidationError.unsupportedSchemaVersion(schemaVersion)
    }
    requestID = try container.decode(RequestID.self, forKey: .requestID)
    result = try container.decodeIfPresent(CommandResult.self, forKey: .result)
    failure = try container.decodeIfPresent(EngineFailure.self, forKey: .failure)
    guard (result != nil) != (failure != nil) else {
      throw ProtocolValidationError.invalidResponse
    }
  }

  private enum CodingKeys: String, CodingKey {
    case schemaVersion
    case requestID
    case result
    case failure
  }
}

enum Installed40019ProxySnapshotCodec {
  static func encodeRequest(requestID: RequestID) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(Installed40019ProxySnapshotRequest(requestID: requestID))
    guard !data.isEmpty, data.count <= NativeProtocolConstants.maximumMessageBytes else {
      throw ProtocolValidationError.messageTooLarge(
        actual: data.count, maximum: NativeProtocolConstants.maximumMessageBytes)
    }
    return data
  }

  static func decodeResponse(_ data: Data) throws -> (
    requestID: RequestID, result: CommandResult?, failure: EngineFailure?
  ) {
    guard !data.isEmpty, data.count <= NativeProtocolConstants.maximumMessageBytes else {
      throw ProtocolValidationError.messageTooLarge(
        actual: data.count, maximum: NativeProtocolConstants.maximumMessageBytes)
    }
    let response = try JSONDecoder().decode(Installed40019ProxySnapshotResponse.self, from: data)
    if let result = response.result {
      guard result.kind == .snapshot,
        let snapshot = result.snapshot,
        snapshot.mode != .tunnel
      else { throw ProtocolValidationError.invalidResponse }
    }
    return (response.requestID, response.result, response.failure)
  }
}

private enum ProxyAgentConnectionProfile: Equatable, Sendable {
  case current
  case serviceObservation
  case installed40019Migration
}

private final class ProxyAgentConnectionReference: @unchecked Sendable {
  let identifier = UUID()
  let connection: NSXPCConnection
  let lifecycle: ProxyAgentConnectionLifecycle
  let profile: ProxyAgentConnectionProfile

  init(_ connection: NSXPCConnection, profile: ProxyAgentConnectionProfile) {
    self.connection = connection
    self.profile = profile
    let box = UncheckedProxyAgentXPCConnection(connection)
    lifecycle = ProxyAgentConnectionLifecycle {
      box.value.invalidate()
    }
  }
}

private final class UncheckedProxyAgentXPCConnection: @unchecked Sendable {
  let value: NSXPCConnection

  init(_ value: NSXPCConnection) { self.value = value }
}

/// Controllable connection-generation seam. Every request registered on one XPC
/// connection receives a terminal transport failure when that exact generation is
/// retired. Late replies race through their per-request first-result gate and can
/// never complete a request on the replacement connection.
final class ProxyAgentConnectionLifecycle: @unchecked Sendable {
  let identifier = UUID()

  private let lock = NSLock()
  private let invalidate: @Sendable () -> Void
  private var retired = false
  private var pending: [UUID: @Sendable () -> Void] = [:]

  init(invalidate: @escaping @Sendable () -> Void) {
    self.invalidate = invalidate
  }

  func register(
    token: UUID,
    onRetire: @escaping @Sendable () -> Void
  ) -> Bool {
    let accepted = lock.withLock {
      guard !retired else { return false }
      pending[token] = onRetire
      return true
    }
    if !accepted { onRetire() }
    return accepted
  }

  func release(token: UUID) {
    _ = lock.withLock { pending.removeValue(forKey: token) }
  }

  func retire() {
    let outcome = lock.withLock { () -> (Bool, [@Sendable () -> Void]) in
      guard !retired else { return (false, []) }
      retired = true
      let callbacks = Array(pending.values)
      pending.removeAll(keepingCapacity: false)
      return (true, callbacks)
    }
    guard outcome.0 else { return }
    invalidate()
    for callback in outcome.1 { callback() }
  }

  var pendingCount: Int { lock.withLock { pending.count } }
  var isRetired: Bool { lock.withLock { retired } }
}

struct BoundedProxyAgentRequestRegistry: Sendable {
  static let productionMaximum = 16

  let maximum: Int
  private(set) var tokens: Set<UUID> = []

  init(maximum: Int = productionMaximum) {
    precondition(maximum > 0, "ProxyAgent request capacity must be positive")
    self.maximum = maximum
  }

  mutating func reserve() throws -> UUID {
    guard tokens.count < maximum else {
      throw ProxyAgentHostError.transportCapacityExceeded
    }
    let token = UUID()
    tokens.insert(token)
    return token
  }

  mutating func release(_ token: UUID) {
    tokens.remove(token)
  }
}

/// The byte arguments of one authorized ProxyAgent start, in XPC argument order.
struct ProxyAgentStartRequest: Sendable {
  let capability: Data
  let context: Data
  let configuration: Data
  let request: Data
}

struct ProxyAgentConnectionDependencies: @unchecked Sendable {
  typealias ConnectionFactory = @Sendable (String) -> NSXPCConnection
  typealias Execute =
    @Sendable (
      NSXPCConnection,
      Data,
      @escaping @Sendable (Result<Data, Error>) -> Void
    ) -> Void
  typealias StartSystemProxy =
    @Sendable (
      NSXPCConnection,
      ProxyAgentStartRequest,
      @escaping @Sendable (Result<Data, Error>) -> Void
    ) -> Void

  let makeConnection: ConnectionFactory
  let prepareConnection: @Sendable (NSXPCConnection, String) -> Void
  let activateConnection: @Sendable (NSXPCConnection) -> Void
  let execute: Execute
  let startSystemProxy: StartSystemProxy

  static let production = ProxyAgentConnectionDependencies(
    makeConnection: { NSXPCConnection(machServiceName: $0) },
    prepareConnection: { connection, requirement in
      connection.setCodeSigningRequirement(requirement)
      connection.remoteObjectInterface = NSXPCInterface(with: CFWProxyAgentXPCProtocol.self)
    },
    activateConnection: { $0.activate() },
    execute: { connection, request, reply in
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
          reply(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        }) as? CFWProxyAgentXPCProtocol
      else {
        reply(.failure(ProxyAgentHostError.transportUnavailable("remote interface is unavailable")))
        return
      }
      proxy.execute(request) { data, error in
        if error != nil {
          reply(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        } else if let data {
          reply(.success(data))
        } else {
          reply(.failure(ProxyAgentHostError.malformedResponse))
        }
      }
    },
    startSystemProxy: { connection, request, reply in
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
          reply(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        }) as? CFWProxyAgentXPCProtocol
      else {
        reply(.failure(ProxyAgentHostError.transportUnavailable("remote interface is unavailable")))
        return
      }
      proxy.startSystemProxy(
        request.capability,
        context: request.context,
        configuration: request.configuration,
        request: request.request
      ) { data, error in
        if error != nil {
          reply(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        } else if let data {
          reply(.success(data))
        } else {
          reply(.failure(ProxyAgentHostError.malformedResponse))
        }
      }
    }
  )
}

struct Installed40019ProxyTransportDependencies: @unchecked Sendable {
  let observeProcess: @Sendable () throws -> Installed40019ServiceProcessIdentity
  let makeConnection: ProxyAgentConnectionDependencies.ConnectionFactory
  let prepareConnection: @Sendable (NSXPCConnection, String) -> Void
  let activateConnection: @Sendable (NSXPCConnection) -> Void
  let execute:
    @Sendable (NSXPCConnection, Data, @escaping @Sendable (Data?, NSError?) -> Void) -> Void
  let peerProcessIdentifier: @Sendable (NSXPCConnection) -> pid_t
  let peerUserIdentifier: @Sendable (NSXPCConnection) -> uid_t

  static let production = Installed40019ProxyTransportDependencies(
    observeProcess: { try Installed40019ServiceProcessObserver().observe(.proxyAgent) },
    makeConnection: ProxyAgentConnectionDependencies.production.makeConnection,
    prepareConnection: ProxyAgentConnectionDependencies.production.prepareConnection,
    activateConnection: ProxyAgentConnectionDependencies.production.activateConnection,
    execute: { connection, request, reply in
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
          reply(nil, NSError(domain: NSCocoaErrorDomain, code: NSXPCConnectionInterrupted))
        }) as? CFWProxyAgentXPCProtocol
      else {
        reply(nil, NSError(domain: NSCocoaErrorDomain, code: NSXPCConnectionInvalid))
        return
      }
      proxy.execute(request, withReply: reply)
    },
    peerProcessIdentifier: { $0.processIdentifier },
    peerUserIdentifier: { $0.effectiveUserIdentifier }
  )
}

private struct ProxyAgentDecodedResponse: Sendable {
  let requestID: RequestID
  let result: CommandResult?
  let failure: EngineFailure?
}

public actor AuthenticatedProxyAgentTransport:
  ProxyAgentTransporting, Installed40019ProxySnapshotting
{
  private let machServiceName: String
  private let identity: CodeIdentityRequirement
  private let currentCodeHash: ServiceCodeHash
  private var buildConstraint = ServiceConnectionBuildConstraint()
  private let serviceController: any ProxyAgentServiceControlling
  private let replyTimeout: Duration
  private let makeReplyDeadline: @Sendable (Duration) -> CallbackDeadlineScheduler
  private let connectionDependencies: ProxyAgentConnectionDependencies
  private let installed40019Dependencies: Installed40019ProxyTransportDependencies
  private var connectionReference: ProxyAgentConnectionReference?
  private var outstandingRequests = BoundedProxyAgentRequestRegistry()

  /// The wait for every ProxyAgent reply except a start, whose Agent replies only
  /// after its libbox start (`EngineStartBudget.proxyAgentStartReply`).
  public static let defaultReplyTimeout: Duration = .seconds(5)

  /// The Host's wait for a profile probe: the probe's own timeout plus the
  /// ordinary reply wait, inside which the ProxyAgent replies by its allowance
  /// (`ProxyAgentCallBudget.profileProbeReplyAllowance`).
  public static func profileProbeReplyTimeout(timeoutMS: UInt16) -> Duration {
    .milliseconds(Int64(timeoutMS)) + defaultReplyTimeout
  }

  /// Arms one production reply deadline.
  static let productionReplyDeadline: @Sendable (Duration) -> CallbackDeadlineScheduler = {
    CallbackDeadlineScheduler(timeout: $0)
  }

  public init(
    machServiceName: String,
    teamIdentifier: String,
    proxyAgentBundleIdentifier: String,
    currentCodeHash: ServiceCodeHash,
    serviceController: any ProxyAgentServiceControlling = SMProxyAgentServiceController(),
    replyTimeout: Duration = defaultReplyTimeout
  ) throws {
    try self.init(
      machServiceName: machServiceName,
      teamIdentifier: teamIdentifier,
      proxyAgentBundleIdentifier: proxyAgentBundleIdentifier,
      currentCodeHash: currentCodeHash,
      serviceController: serviceController,
      replyTimeout: replyTimeout,
      makeReplyDeadline: Self.productionReplyDeadline)
  }

  /// `makeReplyDeadline` arms the deadline for one reply wait of the given
  /// length; each wait chooses its own length.
  init(
    machServiceName: String,
    teamIdentifier: String,
    proxyAgentBundleIdentifier: String,
    currentCodeHash: ServiceCodeHash,
    serviceController: any ProxyAgentServiceControlling,
    replyTimeout: Duration = defaultReplyTimeout,
    makeReplyDeadline: @escaping @Sendable (Duration) -> CallbackDeadlineScheduler =
      productionReplyDeadline,
    installed40019Dependencies: Installed40019ProxyTransportDependencies = .production,
    connectionDependencies: ProxyAgentConnectionDependencies = .production
  ) throws {
    guard !machServiceName.isEmpty, replyTimeout > .zero else {
      throw ProxyAgentHostError.transportUnavailable("invalid transport configuration")
    }
    self.machServiceName = machServiceName
    self.currentCodeHash = currentCodeHash
    identity = try CodeIdentityRequirement(
      expectedTeamIdentifier: teamIdentifier,
      expectedBundleIdentifier: proxyAgentBundleIdentifier
    )
    self.serviceController = serviceController
    self.replyTimeout = replyTimeout
    self.makeReplyDeadline = makeReplyDeadline
    self.installed40019Dependencies = installed40019Dependencies
    self.connectionDependencies = connectionDependencies
  }

  public func registrationStatus() -> ProxyAgentRegistrationStatus {
    serviceController.registrationStatus()
  }

  public func authorizeSystemProxy(restorationOnly: Bool) async throws {
    try serviceController.ensureRegistered()
    let token = try outstandingRequests.reserve()
    defer { outstandingRequests.release(token) }
    let reference = try connectedSession(requireCurrentBuild: !restorationOnly)
    defer { reference.lifecycle.release(token: token) }
    do {
      let _: Void = try await awaitBoundedCallback(
        deadline: CallbackDeadlineScheduler(timeout: ProxyAgentRequestBudget.authorizationReply),
        timeoutError: ProxyAgentHostError.transportTimedOut
      ) { finish in
        guard
          reference.lifecycle.register(
            token: token,
            onRetire: {
              finish(.failure(ProxyAgentHostError.transportUnavailable("connection-retired")))
            })
        else { return }
        guard
          let proxy = reference.connection.remoteObjectProxyWithErrorHandler({ _ in
            finish(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
          }) as? CFWProxyAgentXPCProtocol
        else {
          finish(.failure(ProxyAgentHostError.transportUnavailable("remote-interface")))
          return
        }
        proxy.authorizeSystemProxy(restorationOnly: restorationOnly) { error in
          reference.lifecycle.release(token: token)
          if let error {
            guard error.domain == SystemProxyAuthorizationFailure.domain,
              let failure = SystemProxyAuthorizationFailure(rawValue: error.code)
            else {
              finish(.failure(ProxyAgentHostError.malformedResponse))
              return
            }
            switch failure {
            case .denied: finish(.failure(ProxyAgentHostError.authorizationDenied))
            case .pending: finish(.failure(ProxyAgentHostError.authorizationPending))
            case .internalFailure: finish(.failure(ProxyAgentHostError.authorizationFailed))
            }
          } else {
            finish(.success(()))
          }
        }
      }
    } catch {
      if Self.shouldRetireConnection(after: error) { retireConnection(reference) }
      throw error
    }
  }

  public func ensureRegistered() throws {
    try serviceController.ensureRegistered()
  }

  public func start(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    authorization: HostPreparedSystemProxyStart
  ) async throws {
    try descriptor.validateConfigurationBytes(configuration)
    guard descriptor.slot.isProxyAgent,
      authorization.context.operation.mode == descriptor.slot.authorityMode
    else { throw ProxyAgentHostError.responseMismatch }
    let command = try NativeCommand(
      kind: descriptor.slot == .localProxy ? .startLocalProxy : .startSystemProxy,
      configuration: descriptor)
    let request = RequestEnvelope(command: command)
    let requestData = try ProtocolCodec.encode(request)
    let contextData = try AuthorityV1Codec.encodeCanonical(authorization.context)
    var capabilityData = try authorization.consumeCapabilityData()
    defer {
      capabilityData.resetBytes(
        in: capabilityData.startIndex..<capabilityData.endIndex)
      capabilityData.removeAll(keepingCapacity: false)
    }
    try await awaitAuthorizedStart(
      capabilityData: capabilityData,
      contextData: contextData,
      configurationData: configuration,
      requestData: requestData,
      requestID: request.requestID)
  }

  private func awaitAuthorizedStart(
    capabilityData: Data,
    contextData: Data,
    configurationData: Data,
    requestData: Data,
    requestID: RequestID
  ) async throws {
    let startRequest = ProxyAgentStartRequest(
      capability: capabilityData,
      context: contextData,
      configuration: configurationData,
      request: requestData)
    // The Agent replies only after its libbox start finished or was interrupted,
    // so a start waits for the start budget instead of the ordinary reply bound.
    _ = try await awaitProxyAgentResult(
      requestID: requestID,
      expectedKind: .accepted,
      deadline: makeReplyDeadline(EngineStartBudget.proxyAgentStartReply)
    ) { connection, finish in
      self.connectionDependencies.startSystemProxy(connection, startRequest, finish)
    }
  }

  public func stop(configuration: ConfigurationDescriptor) async throws {
    _ = try await execute(
      NativeCommand(kind: .stop, configuration: configuration),
      expectedKind: .accepted
    )
  }

  public func restoreSettingsBeforeStop(configuration: ConfigurationDescriptor) async throws {
    _ = try await execute(
      NativeCommand(kind: .restoreSettingsBeforeStop, configuration: configuration),
      expectedKind: .accepted
    )
  }

  public func snapshot() async throws -> EngineSnapshot {
    switch serviceController.registrationStatus() {
    case .enabled:
      break
    case .requiresApproval:
      throw ProxyAgentHostError.registrationRequiresApproval
    case .notRegistered, .notFound, .unknown:
      throw ProxyAgentHostError.registrationUnavailable
    }
    let result = try await execute(
      NativeCommand(kind: .snapshot),
      expectedKind: .snapshot)
    guard let snapshot = result.snapshot else {
      throw ProxyAgentHostError.malformedResponse
    }
    return snapshot
  }

  package func snapshotInstalled40019ForMigration() async throws -> EngineSnapshot {
    guard serviceController.registrationStatus() == .enabled else {
      throw ProxyAgentHostError.registrationUnavailable
    }
    let first = try observeInstalled40019Process()
    let second = try observeInstalled40019Process()
    guard first == second, serviceController.registrationStatus() == .enabled else {
      throw ProxyAgentHostError.responseMismatch
    }

    let requestID = RequestID()
    let requestData: Data
    do {
      requestData = try Installed40019ProxySnapshotCodec.encodeRequest(requestID: requestID)
    } catch {
      throw ProxyAgentHostError.malformedResponse
    }

    let dependencies = installed40019Dependencies
    let serviceController = serviceController
    let result = try await awaitProxyAgentResult(
      requestID: requestID,
      expectedKind: .snapshot,
      connect: {
        try connectedInstalled40019Session(
          codeSigningRequirement: second.xpcCodeSigningRequirement)
      },
      decode: { data in
        let response = try Installed40019ProxySnapshotCodec.decodeResponse(data)
        return ProxyAgentDecodedResponse(
          requestID: response.requestID,
          result: response.result,
          failure: response.failure
        )
      },
      operation: { connection, finish in
        // Foundation cannot expose an outbound Mach-service peer PID before the
        // first message. The request is therefore deliberately secret-free and
        // read-only. Its response is accepted only after the exact pre-observed
        // PID/UID and full 40019 identity have been re-established.
        let connectionBox = UncheckedProxyAgentXPCConnection(connection)
        dependencies.execute(connection, requestData) { data, error in
          let connection = connectionBox.value
          guard error == nil, let data else {
            finish(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
            return
          }
          let peerBefore = dependencies.peerProcessIdentifier(connection)
          let userBefore = dependencies.peerUserIdentifier(connection)
          guard peerBefore == second.processIdentifier,
            userBefore == second.userIdentifier
          else {
            finish(.failure(ProxyAgentHostError.responseMismatch))
            return
          }
          let after: Installed40019ServiceProcessIdentity
          do {
            after = try dependencies.observeProcess()
          } catch {
            finish(.failure(ProxyAgentHostError.responseMismatch))
            return
          }
          guard after == second,
            serviceController.registrationStatus() == .enabled,
            dependencies.peerProcessIdentifier(connection) == second.processIdentifier,
            dependencies.peerUserIdentifier(connection) == second.userIdentifier
          else {
            finish(.failure(ProxyAgentHostError.responseMismatch))
            return
          }
          finish(.success(data))
        }
      })
    guard let snapshot = result.snapshot else {
      throw ProxyAgentHostError.malformedResponse
    }
    return snapshot
  }

  private func observeInstalled40019Process() throws -> Installed40019ServiceProcessIdentity {
    do {
      return try installed40019Dependencies.observeProcess()
    } catch {
      throw ProxyAgentHostError.responseMismatch
    }
  }

  public func testProfileProxies(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) async throws -> [ProfileProxyDelay] {
    try ProfileDelayTestRequest.validateTargets(proxies, timeoutMS: timeoutMS)
    try ProfileDelayTestRequest.validateTargetURL(targetURL, expectedStatus: expectedStatus)
    guard !configuration.isEmpty,
      configuration.count <= Int(NativeProtocolConstants.maximumConfigurationBytes)
    else { throw ProxyAgentHostError.malformedResponse }
    let names = try JSONEncoder().encode(proxies)
    return try await awaitProxyAgentResponse(
      connect: { try connectedSession() },
      deadline: makeReplyDeadline(Self.profileProbeReplyTimeout(timeoutMS: timeoutMS)),
      decode: { data in
        guard data.count <= 65536 else { throw ProxyAgentHostError.malformedResponse }
        let results = try JSONDecoder().decode([ProfileProxyDelay].self, from: data)
        guard results.map(\.name) == proxies else { throw ProxyAgentHostError.responseMismatch }
        return results
      },
      operation: { connection, finish in
        guard
          let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
            finish(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
          }) as? CFWProxyAgentXPCProtocol
        else {
          finish(
            .failure(ProxyAgentHostError.transportUnavailable("remote interface is unavailable")))
          return
        }
        proxy.testProfileProxies(
          configuration, proxies: names, timeoutMS: timeoutMS, targetURL: targetURL,
          expectedStatus: expectedStatus
        ) {
          data, error in
          if let error {
            if error.domain == ProfileProbeServiceFailure.domain,
              let failure = ProfileProbeServiceFailure(rawValue: error.code)
            {
              finish(.failure(ProxyAgentHostError.agentFailure(failure.failure)))
            } else {
              finish(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
            }
          } else if let data {
            finish(.success(data))
          } else {
            finish(.failure(ProxyAgentHostError.malformedResponse))
          }
        }
      })
  }

  public func validateConfiguration(
    _ configuration: Data,
    descriptor: ConfigurationDescriptor
  ) async throws {
    guard !configuration.isEmpty,
      configuration.count <= Int(NativeProtocolConstants.maximumConfigurationBytes)
    else {
      throw ProxyAgentHostError.malformedResponse
    }
    let request = RequestEnvelope(
      command: try NativeCommand(
        kind: .validateConfiguration,
        configuration: descriptor
      )
    )
    let requestData = try ProtocolCodec.encode(request)
    _ = try await awaitProxyAgentResult(
      requestID: request.requestID,
      expectedKind: .accepted
    ) {
      connection, finish in
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
          finish(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        }) as? CFWProxyAgentXPCProtocol
      else {
        finish(
          .failure(ProxyAgentHostError.transportUnavailable("remote interface is unavailable"))
        )
        return
      }
      proxy.validateConfiguration(configuration, request: requestData) { data, error in
        if error != nil {
          finish(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        } else if let data {
          finish(.success(data))
        } else {
          finish(.failure(ProxyAgentHostError.malformedResponse))
        }
      }
    }
  }

  private func execute(
    _ command: NativeCommand,
    expectedKind: CommandResultKind
  ) async throws -> CommandResult {
    let request = RequestEnvelope(command: command)
    let requestData = try ProtocolCodec.encode(request)
    return try await awaitProxyAgentResult(
      requestID: request.requestID,
      expectedKind: expectedKind,
      requireCurrentBuild: command.kind != .snapshot && command.kind != .stop
    ) {
      connection, finish in
      self.connectionDependencies.execute(connection, requestData, finish)
    }
  }

  private func awaitProxyAgentResult(
    requestID: RequestID,
    expectedKind: CommandResultKind,
    requireCurrentBuild: Bool = true,
    deadline: CallbackDeadlineScheduler? = nil,
    _ operation:
      @escaping @Sendable (
        NSXPCConnection,
        @escaping @Sendable (Result<Data, Error>) -> Void
      ) -> Void
  ) async throws -> CommandResult {
    try await awaitProxyAgentResult(
      requestID: requestID,
      expectedKind: expectedKind,
      connect: { try connectedSession(requireCurrentBuild: requireCurrentBuild) },
      deadline: deadline,
      decode: { data in
        let response = try ProtocolCodec.decodeResponse(data)
        return ProxyAgentDecodedResponse(
          requestID: response.requestID,
          result: response.result,
          failure: response.failure
        )
      },
      operation: operation
    )
  }

  private func awaitProxyAgentResult(
    requestID: RequestID,
    expectedKind: CommandResultKind,
    connect: () throws -> ProxyAgentConnectionReference,
    deadline: CallbackDeadlineScheduler? = nil,
    decode: @escaping @Sendable (Data) throws -> ProxyAgentDecodedResponse,
    operation:
      @escaping @Sendable (
        NSXPCConnection,
        @escaping @Sendable (Result<Data, Error>) -> Void
      ) -> Void
  ) async throws -> CommandResult {
    try await awaitProxyAgentResponse(
      connect: connect,
      deadline: deadline,
      decode: { data in
        let response: ProxyAgentDecodedResponse
        do {
          response = try decode(data)
        } catch {
          throw ProxyAgentHostError.malformedResponse
        }
        guard response.requestID == requestID else {
          throw ProxyAgentHostError.responseMismatch
        }
        if let failure = response.failure {
          throw ProxyAgentHostError.agentFailure(failure)
        }
        guard let result = response.result else {
          throw ProxyAgentHostError.malformedResponse
        }
        guard result.kind == expectedKind else {
          throw ProxyAgentHostError.malformedResponse
        }
        return result
      }, operation: operation)
  }

  private func awaitProxyAgentResponse<Value: Sendable>(
    connect: () throws -> ProxyAgentConnectionReference,
    deadline: CallbackDeadlineScheduler? = nil,
    decode: @escaping @Sendable (Data) throws -> Value,
    operation:
      @escaping @Sendable (
        NSXPCConnection, @escaping @Sendable (Result<Data, Error>) -> Void
      ) -> Void
  ) async throws -> Value {
    let token = try outstandingRequests.reserve()
    defer { outstandingRequests.release(token) }
    let reference = try connect()
    defer { reference.lifecycle.release(token: token) }
    do {
      let responseData: Data = try await awaitBoundedCallback(
        deadline: deadline ?? makeReplyDeadline(replyTimeout),
        timeoutError: ProxyAgentHostError.transportTimedOut
      ) { finish in
        guard
          reference.lifecycle.register(
            token: token,
            onRetire: {
              finish(
                .failure(
                  ProxyAgentHostError.transportUnavailable("connection-retired")
                )
              )
            }
          )
        else { return }
        operation(reference.connection) { result in
          reference.lifecycle.release(token: token)
          finish(result)
        }
      }
      return try decode(responseData)
    } catch {
      if Self.shouldRetireConnection(after: error) {
        retireConnection(reference)
      }
      throw error
    }
  }

  static func shouldRetireConnection(after error: Error) -> Bool {
    if error is CancellationError { return true }
    guard let error = error as? ProxyAgentHostError else { return false }
    switch error {
    case .transportTimedOut, .transportUnavailable, .malformedResponse, .responseMismatch:
      return true
    case .registrationRequiresApproval, .registrationUnavailable,
      .registrationFailed, .transportCapacityExceeded, .authorizationDenied,
      .authorizationPending, .authorizationFailed, .agentFailure:
      return false
    }
  }

  private func retireConnection(_ reference: ProxyAgentConnectionReference) {
    guard connectionReference?.identifier == reference.identifier else { return }
    connectionReference = nil
    reference.lifecycle.retire()
  }

  private func connectedSession(requireCurrentBuild: Bool = true) throws
    -> ProxyAgentConnectionReference
  {
    let requirement = buildConstraint.requirement(
      base: identity.requirementText, currentCodeHash: currentCodeHash,
      requestingCurrentBuild: requireCurrentBuild)
    let requireCurrentBuild = buildConstraint.requiresCurrentBuild
    if let connectionReference, !connectionReference.lifecycle.isRetired,
      connectionReference.profile == .current
        || (!requireCurrentBuild && connectionReference.profile == .serviceObservation)
    {
      return connectionReference
    }
    if let connectionReference { retireConnection(connectionReference) }
    let connection = connectionDependencies.makeConnection(machServiceName)
    connectionDependencies.prepareConnection(connection, requirement)
    let reference = ProxyAgentConnectionReference(
      connection, profile: requireCurrentBuild ? .current : .serviceObservation)
    installConnectionLifecycle(reference)
    connectionDependencies.activateConnection(connection)
    connectionReference = reference
    return reference
  }

  private func connectedInstalled40019Session(
    codeSigningRequirement: String
  ) throws -> ProxyAgentConnectionReference {
    if let connectionReference { retireConnection(connectionReference) }
    let connection = installed40019Dependencies.makeConnection(machServiceName)
    installed40019Dependencies.prepareConnection(connection, codeSigningRequirement)
    let reference = ProxyAgentConnectionReference(
      connection, profile: .installed40019Migration)
    installConnectionLifecycle(reference)
    installed40019Dependencies.activateConnection(connection)
    connectionReference = reference
    return reference
  }

  private func installConnectionLifecycle(_ reference: ProxyAgentConnectionReference) {
    let identifier = reference.identifier
    // Retire on the XPC callback thread before scheduling actor cleanup. A new
    // request may otherwise reuse this generation before that Task is admitted.
    let retire: @Sendable () -> Void = { [weak self, weak lifecycle = reference.lifecycle] in
      lifecycle?.retire()
      guard let self else { return }
      Task { await self.clearConnection(identifier) }
    }
    reference.connection.interruptionHandler = retire
    reference.connection.invalidationHandler = retire
  }

  private func clearConnection(_ identifier: UUID) {
    guard connectionReference?.identifier == identifier else {
      return
    }
    connectionReference = nil
  }
}

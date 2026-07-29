import CFWSharedProtocol
import Foundation
import ServiceManagement

public enum ProxyAgentRegistrationStatus: Equatable, Sendable {
  case enabled
  case requiresApproval
  case notRegistered
  case notFound
}

public enum ProxyAgentHostError: Error, Equatable, Sendable {
  case registrationRequiresApproval
  case registrationUnavailable
  case registrationFailed(String)
  case transportUnavailable(String)
  case transportTimedOut
  case transportCapacityExceeded
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

public struct SMProxyAgentServiceController: ProxyAgentServiceControlling, Sendable {
  public static let launchAgentPlistName = "com.bill.clashformac.proxy-agent.plist"

  public init() {}

  public func registrationStatus() -> ProxyAgentRegistrationStatus {
    switch SMAppService.agent(plistName: Self.launchAgentPlistName).status {
    case .enabled: .enabled
    case .requiresApproval: .requiresApproval
    case .notRegistered: .notRegistered
    case .notFound: .notFound
    @unknown default: .notFound
    }
  }

  public func ensureRegistered() throws {
    let service = SMAppService.agent(plistName: Self.launchAgentPlistName)
    switch registrationStatus() {
    case .enabled:
      return
    case .requiresApproval:
      throw ProxyAgentHostError.registrationRequiresApproval
    case .notFound:
      throw ProxyAgentHostError.registrationUnavailable
    case .notRegistered:
      do {
        try service.register()
      } catch {
        throw ProxyAgentHostError.registrationFailed(error.localizedDescription)
      }
      switch registrationStatus() {
      case .enabled:
        return
      case .requiresApproval:
        throw ProxyAgentHostError.registrationRequiresApproval
      case .notRegistered, .notFound:
        throw ProxyAgentHostError.registrationUnavailable
      }
    }
  }
}

public protocol ProxyAgentTransporting: Sendable {
  func registrationStatus() async -> ProxyAgentRegistrationStatus
  func ensureRegistered() async throws
  func start(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    authorization: HostPreparedSystemProxyStart
  ) async throws
  func stop(configuration: ConfigurationDescriptor) async throws
  func snapshot() async throws -> EngineSnapshot
  func validateConfiguration(
    _ configuration: Data,
    descriptor: ConfigurationDescriptor
  ) async throws
}

private final class ProxyAgentConnectionReference: @unchecked Sendable {
  let identifier = UUID()
  let connection: NSXPCConnection
  let lifecycle: ProxyAgentConnectionLifecycle

  init(_ connection: NSXPCConnection) {
    self.connection = connection
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

public actor AuthenticatedProxyAgentTransport: ProxyAgentTransporting {
  private let machServiceName: String
  private let identity: CodeIdentityRequirement
  private let serviceController: any ProxyAgentServiceControlling
  private let replyDeadline: CallbackDeadlineScheduler
  private var connectionReference: ProxyAgentConnectionReference?
  private var outstandingRequests = BoundedProxyAgentRequestRegistry()

  public init(
    machServiceName: String,
    teamIdentifier: String,
    proxyAgentBundleIdentifier: String,
    serviceController: any ProxyAgentServiceControlling = SMProxyAgentServiceController(),
    replyTimeout: Duration = .seconds(5)
  ) throws {
    guard !machServiceName.isEmpty, replyTimeout > .zero else {
      throw ProxyAgentHostError.transportUnavailable("invalid transport configuration")
    }
    self.machServiceName = machServiceName
    identity = try CodeIdentityRequirement(
      expectedTeamIdentifier: teamIdentifier,
      expectedBundleIdentifier: proxyAgentBundleIdentifier
    )
    self.serviceController = serviceController
    replyDeadline = CallbackDeadlineScheduler(timeout: replyTimeout)
  }

  public func registrationStatus() -> ProxyAgentRegistrationStatus {
    serviceController.registrationStatus()
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
    let command = try NativeCommand(kind: .startSystemProxy, configuration: descriptor)
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
    _ = try await awaitProxyAgentResult(requestID: requestID, expectedKind: .accepted) {
      connection, finish in
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
          finish(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        }) as? CFWProxyAgentXPCProtocol
      else {
        finish(
          .failure(ProxyAgentHostError.transportUnavailable("remote interface is unavailable")))
        return
      }
      proxy.startSystemProxy(
        capabilityData,
        context: contextData,
        configuration: configurationData,
        request: requestData
      ) { data, error in
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

  public func stop(configuration: ConfigurationDescriptor) async throws {
    _ = try await execute(
      NativeCommand(kind: .stop, configuration: configuration),
      expectedKind: .accepted
    )
  }

  public func snapshot() async throws -> EngineSnapshot {
    switch serviceController.registrationStatus() {
    case .enabled:
      break
    case .requiresApproval:
      throw ProxyAgentHostError.registrationRequiresApproval
    case .notRegistered, .notFound:
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
      expectedKind: expectedKind
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
      proxy.execute(requestData) { data, error in
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

  private func awaitProxyAgentResult(
    requestID: RequestID,
    expectedKind: CommandResultKind,
    _ operation:
      @escaping @Sendable (
        NSXPCConnection,
        @escaping @Sendable (Result<Data, Error>) -> Void
      ) -> Void
  ) async throws -> CommandResult {
    let token = try outstandingRequests.reserve()
    defer { outstandingRequests.release(token) }
    let reference = try connectedSession()
    defer { reference.lifecycle.release(token: token) }
    do {
      let responseData: Data = try await awaitBoundedCallback(
        deadline: replyDeadline,
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
      let response: ResponseEnvelope
      do {
        response = try ProtocolCodec.decodeResponse(responseData)
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
      .registrationFailed, .transportCapacityExceeded, .agentFailure:
      return false
    }
  }

  private func retireConnection(_ reference: ProxyAgentConnectionReference) {
    guard connectionReference?.identifier == reference.identifier else { return }
    connectionReference = nil
    reference.lifecycle.retire()
  }

  private func connectedSession() throws -> ProxyAgentConnectionReference {
    if let connectionReference {
      return connectionReference
    }
    let connection = NSXPCConnection(machServiceName: machServiceName)
    try identity.configure(connection)
    connection.remoteObjectInterface = NSXPCInterface(with: CFWProxyAgentXPCProtocol.self)
    let reference = ProxyAgentConnectionReference(connection)
    let owner = self
    connection.invalidationHandler = {
      Task {
        await owner.clearConnection(reference.identifier)
      }
    }
    connection.activate()
    connectionReference = reference
    return reference
  }

  private func clearConnection(_ identifier: UUID) {
    guard connectionReference?.identifier == identifier else {
      return
    }
    connectionReference = nil
  }
}

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
  func start(configuration: ConfigurationDescriptor) async throws
  func stop(configuration: ConfigurationDescriptor) async throws
  func snapshot() async throws -> EngineSnapshot
  func validateConfiguration(
    _ configuration: Data,
    descriptor: ConfigurationDescriptor
  ) async throws
}

private final class ProxyAgentReplyGate: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Data, Error>?

  init(_ continuation: CheckedContinuation<Data, Error>) {
    self.continuation = continuation
  }

  func finish(_ result: Result<Data, Error>) {
    let continuation = lock.withLock { () -> CheckedContinuation<Data, Error>? in
      let continuation = self.continuation
      self.continuation = nil
      return continuation
    }
    continuation?.resume(with: result)
  }
}

private final class ProxyAgentConnectionReference: @unchecked Sendable {
  let identifier = UUID()
  let connection: NSXPCConnection

  init(_ connection: NSXPCConnection) {
    self.connection = connection
  }
}

public actor AuthenticatedProxyAgentTransport: ProxyAgentTransporting {
  private let machServiceName: String
  private let identity: CodeIdentityRequirement
  private let serviceController: any ProxyAgentServiceControlling
  private let replyTimeout: Duration
  private var connectionReference: ProxyAgentConnectionReference?

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
    self.replyTimeout = replyTimeout
  }

  public func registrationStatus() -> ProxyAgentRegistrationStatus {
    serviceController.registrationStatus()
  }

  public func ensureRegistered() throws {
    try serviceController.ensureRegistered()
  }

  public func start(configuration: ConfigurationDescriptor) async throws {
    let command = try NativeCommand(kind: .startSystemProxy, configuration: configuration)
    let result = try await execute(command)
    guard result.kind == .accepted, result.snapshot == nil else {
      throw ProxyAgentHostError.malformedResponse
    }
  }

  public func stop(configuration: ConfigurationDescriptor) async throws {
    let result = try await execute(
      NativeCommand(kind: .stop, configuration: configuration)
    )
    guard result.kind == .accepted, result.snapshot == nil else {
      throw ProxyAgentHostError.malformedResponse
    }
  }

  public func snapshot() async throws -> EngineSnapshot {
    guard serviceController.registrationStatus() == .enabled else {
      return .off
    }
    let result = try await execute(NativeCommand(kind: .snapshot))
    guard result.kind == .snapshot, let snapshot = result.snapshot else {
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
    let connection = try connectedSession().connection
    let responseData: Data = try await withCheckedThrowingContinuation { continuation in
      let gate = ProxyAgentReplyGate(continuation)
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
          gate.finish(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        }) as? CFWProxyAgentXPCProtocol
      else {
        gate.finish(
          .failure(ProxyAgentHostError.transportUnavailable("remote interface is unavailable"))
        )
        return
      }
      proxy.validateConfiguration(configuration, request: requestData) { data, error in
        if error != nil {
          gate.finish(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        } else if let data {
          gate.finish(.success(data))
        } else {
          gate.finish(.failure(ProxyAgentHostError.malformedResponse))
        }
      }
      let timeout = replyTimeout
      Task {
        do {
          try await Task.sleep(for: timeout)
          gate.finish(.failure(ProxyAgentHostError.transportTimedOut))
        } catch is CancellationError {
          return
        } catch {
          gate.finish(.failure(ProxyAgentHostError.transportUnavailable("sleep-error")))
        }
      }
    }
    let response = try ProtocolCodec.decodeResponse(responseData)
    guard response.requestID == request.requestID else {
      throw ProxyAgentHostError.responseMismatch
    }
    if let failure = response.failure {
      throw ProxyAgentHostError.agentFailure(failure)
    }
    guard response.result?.kind == .accepted, response.result?.snapshot == nil else {
      throw ProxyAgentHostError.malformedResponse
    }
  }

  private func execute(_ command: NativeCommand) async throws -> CommandResult {
    let request = RequestEnvelope(command: command)
    let requestData = try ProtocolCodec.encode(request)
    let connection = try connectedSession().connection
    let responseData: Data = try await withCheckedThrowingContinuation { continuation in
      let gate = ProxyAgentReplyGate(continuation)
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
          gate.finish(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        }) as? CFWProxyAgentXPCProtocol
      else {
        gate.finish(
          .failure(ProxyAgentHostError.transportUnavailable("remote interface is unavailable"))
        )
        return
      }
      proxy.execute(requestData) { data, error in
        if error != nil {
          gate.finish(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        } else if let data {
          gate.finish(.success(data))
        } else {
          gate.finish(.failure(ProxyAgentHostError.malformedResponse))
        }
      }
      let timeout = replyTimeout
      Task {
        do {
          try await Task.sleep(for: timeout)
          gate.finish(.failure(ProxyAgentHostError.transportTimedOut))
        } catch is CancellationError {
          return
        } catch {
          gate.finish(.failure(ProxyAgentHostError.transportUnavailable("sleep-error")))
        }
      }
    }
    let response = try ProtocolCodec.decodeResponse(responseData)
    guard response.requestID == request.requestID else {
      throw ProxyAgentHostError.responseMismatch
    }
    if let failure = response.failure {
      throw ProxyAgentHostError.agentFailure(failure)
    }
    guard let result = response.result else {
      throw ProxyAgentHostError.malformedResponse
    }
    return result
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

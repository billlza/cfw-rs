import CFWCredentialTransport
import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import OSLog

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
  private let lifecycle: any ProxySystemProxyOwning
  private let configurationChecker: any LibboxConfigurationChecking

  init(
    lifecycle: any ProxySystemProxyOwning,
    configurationChecker: any LibboxConfigurationChecking
  ) {
    self.lifecycle = lifecycle
    self.configurationChecker = configurationChecker
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
    case .startSystemProxy:
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          code: "authority-authorization-required",
          message: "System proxy start requires a one-use Authority authorization.",
          isRetryable: false
        ),
        reply: reply
      )
    case .stop:
      guard let configuration = request.command.configuration else {
        respond(
          requestID: request.requestID,
          failure: EngineFailure(
            code: "missing-stop-generation",
            message: "Stop commands must identify the exact active configuration.",
            isRetryable: false
          ),
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
          code: "wrong-process-boundary",
          message: "Tunnel commands are accepted only by the host bridge/provider boundary.",
          isRetryable: false
        ),
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
    guard request.command.kind == .startSystemProxy,
      let descriptor = request.command.configuration,
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
          code: "invalid-owner-authorization",
          message: "System proxy owner authorization does not match the start request.",
          isRetryable: false
        ),
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
          code: "invalid-runtime-configuration",
          message: "System proxy runtime bytes do not match the authorized descriptor.",
          isRetryable: false
        ),
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
          code: "invalid-owner-authorization",
          message: "System proxy owner authorization is malformed.",
          isRetryable: false
        ),
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
          code: "invalid-validation-request",
          message: "Configuration validation request is malformed or exceeds its bound.",
          isRetryable: false
        ),
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
      let retryable: Bool
      switch error {
      case .libboxUnavailable, .missingBundleSetting, .appGroupUnavailable,
        .unsafeRuntimeDirectory, .setupConflict, .setupFailed:
        retryable = true
      default:
        retryable = false
      }
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          code: retryable ? "configuration-validator-unavailable" : "configuration-rejected",
          message: retryable
            ? "Source-built libbox validation is unavailable."
            : "Source-built libbox rejected the configuration.",
          isRetryable: retryable
        ),
        reply: reply
      )
    } catch {
      respond(
        requestID: request.requestID,
        failure: EngineFailure(
          code: "configuration-validator-failed",
          message: "Configuration validation failed at an explicit internal boundary.",
          isRetryable: true
        ),
        reply: reply
      )
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

final class ProxyAgentListenerDelegate: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
  private static let logger = Logger(
    subsystem: "com.bill.clashformac",
    category: "proxy-agent-xpc"
  )
  private let identityPolicy: CodeIdentityPolicy
  private let service: ProxyAgentService

  init(identityPolicy: CodeIdentityPolicy, service: ProxyAgentService) {
    self.identityPolicy = identityPolicy
    self.service = service
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
    connection.resume()
    return true
  }
}

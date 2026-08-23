import CFWAppleNetwork
import CFWSharedProtocol
import Foundation

protocol Installed40019AuthoritySession: Sendable {
  var processIdentifier: pid_t { get }
  var effectiveUserIdentifier: uid_t { get }
  func handshake(
    _ request: Data,
    reply: @escaping @Sendable (Result<Data, Error>) -> Void
  )
  func snapshot(
    _ request: Data,
    reply: @escaping @Sendable (Result<Data, Error>) -> Void
  )
  func invalidate()
}

private final class Installed40019AuthorityEventRejector: NSObject,
  CFWGlobalAuthorityEventSinkProtocol, @unchecked Sendable
{
  func deliverEvent(_ event: Data, reply: @escaping (NSError?) -> Void) {
    _ = event
    reply(AuthorityXPCErrorContract.error(.invalidMessage))
  }
}

private final class NSXPCInstalled40019AuthoritySession:
  Installed40019AuthoritySession, @unchecked Sendable
{
  private let connection: NSXPCConnection
  private let eventRejector: Installed40019AuthorityEventRejector

  init(
    machServiceName: String,
    codeSigningRequirement: String
  ) {
    let connection = NSXPCConnection(
      machServiceName: machServiceName,
      options: .privileged)
    let eventRejector = Installed40019AuthorityEventRejector()
    connection.setCodeSigningRequirement(codeSigningRequirement)
    connection.remoteObjectInterface = NSXPCInterface(
      with: CFWGlobalAuthorityXPCProtocol.self)
    connection.exportedInterface = NSXPCInterface(
      with: CFWGlobalAuthorityEventSinkProtocol.self)
    connection.exportedObject = eventRejector
    connection.activate()
    self.connection = connection
    self.eventRejector = eventRejector
  }

  var processIdentifier: pid_t { connection.processIdentifier }
  var effectiveUserIdentifier: uid_t { connection.effectiveUserIdentifier }

  func handshake(
    _ request: Data,
    reply: @escaping @Sendable (Result<Data, Error>) -> Void
  ) {
    guard
      let remote = connection.remoteObjectProxyWithErrorHandler({ error in
        reply(.failure(AuthorityXPCErrorContract.domainError(error)))
      }) as? CFWGlobalAuthorityXPCProtocol
    else {
      reply(.failure(AuthorityDomainError(code: .globalAuthorityUnavailable)))
      return
    }
    remote.handshake(request) { data, error in
      Self.finish(data: data, error: error, reply: reply)
    }
  }

  func snapshot(
    _ request: Data,
    reply: @escaping @Sendable (Result<Data, Error>) -> Void
  ) {
    guard
      let remote = connection.remoteObjectProxyWithErrorHandler({ error in
        reply(.failure(AuthorityXPCErrorContract.domainError(error)))
      }) as? CFWGlobalAuthorityXPCProtocol
    else {
      reply(.failure(AuthorityDomainError(code: .globalAuthorityUnavailable)))
      return
    }
    remote.snapshot(request) { data, error in
      Self.finish(data: data, error: error, reply: reply)
    }
  }

  func invalidate() { connection.invalidate() }

  private static func finish(
    data: Data?,
    error: NSError?,
    reply: @escaping @Sendable (Result<Data, Error>) -> Void
  ) {
    if let error {
      reply(.failure(AuthorityXPCErrorContract.domainError(error)))
    } else if let data {
      reply(.success(data))
    } else {
      reply(.failure(AuthorityDomainError(code: .invalidMessage)))
    }
  }
}

struct Installed40019AuthorityOffProofDependencies: @unchecked Sendable {
  let observeProcess: @Sendable () throws -> Installed40019ServiceProcessIdentity
  let makeSession:
    @Sendable (Installed40019ServiceProcessIdentity) ->
      any Installed40019AuthoritySession

  static let production = Installed40019AuthorityOffProofDependencies(
    observeProcess: {
      try Installed40019ServiceProcessObserver().observe(.globalAuthority)
    },
    makeSession: { identity in
      NSXPCInstalled40019AuthoritySession(
        machServiceName: "com.bill.clashformac.global-authority",
        codeSigningRequirement: identity.xpcCodeSigningRequirement)
    }
  )
}

struct Installed40019AuthorityOffProver: Installed40019AuthorityOffProving {
  private let dependencies: Installed40019AuthorityOffProofDependencies
  private let deadline: CallbackDeadlineScheduler

  init(
    dependencies: Installed40019AuthorityOffProofDependencies = .production,
    timeout: Duration = .seconds(5)
  ) {
    self.dependencies = dependencies
    deadline = CallbackDeadlineScheduler(timeout: timeout)
  }

  func proveOff() async throws {
    let first = try observe()
    let second = try observe()
    guard first == second, second.service == .globalAuthority else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }

    let session = dependencies.makeSession(second)
    defer { session.invalidate() }

    let handshakeID = AuthorityIdentifier(UUID())
    let handshake = try Installed40019AuthorityOffCodec.handshakeRequest(
      requestID: handshakeID)
    let handshakeResponse = try await call(session.handshake, request: handshake)
    try validateResponse {
      try Installed40019AuthorityOffCodec.validateHandshakeResponse(
        handshakeResponse, requestID: handshakeID)
    }
    try requireSamePeer(session, identity: second)

    let snapshotID = AuthorityIdentifier(UUID())
    let snapshot = try Installed40019AuthorityOffCodec.snapshotRequest(
      requestID: snapshotID)
    let snapshotResponse = try await call(session.snapshot, request: snapshot)
    try validateResponse {
      try Installed40019AuthorityOffCodec.validateOffSnapshotResponse(
        snapshotResponse, requestID: snapshotID)
    }
    try requireSamePeer(session, identity: second)
  }

  private func validateResponse(_ validation: () throws -> Void) throws {
    do {
      try validation()
    } catch is Installed40019AuthorityOffValidationError {
      throw AuthorityDomainError(code: .busy)
    } catch is AuthorityV1ValidationError {
      throw AuthorityDomainError(code: .globalAuthorityProtocolMismatch)
    } catch {
      throw AuthorityDomainError(code: .invalidMessage)
    }
  }

  private func call(
    _ operation:
      @escaping @Sendable (
        Data, @escaping @Sendable (Result<Data, Error>) -> Void
      ) -> Void,
    request: Data
  ) async throws -> Data {
    try await awaitBoundedCallback(
      deadline: deadline,
      timeoutError: AuthorityDomainError(code: .globalAuthorityTimeout)
    ) { finish in
      operation(request, finish)
    }
  }

  private func requireSamePeer(
    _ session: any Installed40019AuthoritySession,
    identity: Installed40019ServiceProcessIdentity
  ) throws {
    guard session.processIdentifier == identity.processIdentifier,
      session.effectiveUserIdentifier == identity.userIdentifier,
      try observe() == identity
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
  }

  private func observe() throws -> Installed40019ServiceProcessIdentity {
    do {
      return try dependencies.observeProcess()
    } catch {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
  }
}

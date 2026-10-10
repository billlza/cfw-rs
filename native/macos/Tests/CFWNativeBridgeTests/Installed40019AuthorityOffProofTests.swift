import Foundation
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

private enum AuthoritySessionFixtureError: Error { case rejected }

private final class LockedCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var storage = 0

  func increment() { lock.withLock { storage += 1 } }
  var value: Int { lock.withLock { storage } }
}

private final class StubInstalled40019AuthoritySession:
  Installed40019AuthoritySession, @unchecked Sendable
{
  let processIdentifier: pid_t
  let effectiveUserIdentifier: uid_t
  private let lock = NSLock()
  private let handshakeFailure: (any Error)?
  private let repliesToHandshake: Bool
  private let snapshotState: String
  private(set) var calls: [String] = []
  private(set) var invalidated = false

  init(
    processIdentifier: pid_t = 6806,
    effectiveUserIdentifier: uid_t = 0,
    snapshotState: String = "off",
    handshakeFailure: (any Error)? = nil,
    repliesToHandshake: Bool = true
  ) {
    self.processIdentifier = processIdentifier
    self.effectiveUserIdentifier = effectiveUserIdentifier
    self.snapshotState = snapshotState
    self.handshakeFailure = handshakeFailure
    self.repliesToHandshake = repliesToHandshake
  }

  func handshake(
    _ request: Data,
    reply: @escaping @Sendable (Result<Data, Error>) -> Void
  ) {
    record("handshake")
    guard repliesToHandshake else { return }
    if let handshakeFailure {
      reply(.failure(handshakeFailure))
      return
    }
    do {
      let requestID = try Self.requestID(request)
      reply(.success(Data(Self.handshakeResponse(requestID: requestID).utf8)))
    } catch {
      reply(.failure(error))
    }
  }

  func snapshot(
    _ request: Data,
    reply: @escaping @Sendable (Result<Data, Error>) -> Void
  ) {
    record("snapshot")
    do {
      let requestID = try Self.requestID(request)
      reply(
        .success(
          Data(
            Self.snapshotResponse(
              requestID: requestID,
              state: snapshotState
            ).utf8)))
    } catch {
      reply(.failure(error))
    }
  }

  func invalidate() {
    lock.withLock { invalidated = true }
  }

  private func record(_ value: String) {
    lock.withLock { calls.append(value) }
  }

  private static func requestID(_ data: Data) throws -> String {
    guard
      let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      let requestID = value["request_id"] as? String
    else { throw AuthoritySessionFixtureError.rejected }
    return requestID
  }

  private static func handshakeResponse(requestID: String) -> String {
    """
    {"major":1,"minor":0,"request_id":"\(requestID)","result":{"command_timeout_ms":5000,"maximum_configuration_bytes":786432,"maximum_credential_slots":256,"maximum_individual_secret_bytes":16384,"maximum_mutating_transactions":1,"maximum_queued_events_per_peer":32,"maximum_read_only_requests":64,"maximum_total_secret_bytes":262144,"preparation_lifetime_ms":10000,"stop_attestation_timeout_ms":5000,"version":{"feature_bits":0,"major":1,"max_message_bytes":1048576,"minimum_minor":0,"minor":0}}}
    """
  }

  private static func snapshotResponse(requestID: String, state: String) -> String {
    """
    {"major":1,"minor":0,"request_id":"\(requestID)","result":{"console_uid":501,"protocol_version":{"feature_bits":0,"major":1,"max_message_bytes":1048576,"minimum_minor":0,"minor":0},"revision":1,"state":"\(state)"}}
    """
  }
}

private final class IdentitySequence: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [Installed40019ServiceProcessIdentity]

  init(_ values: [Installed40019ServiceProcessIdentity]) {
    self.values = values
  }

  func next() throws -> Installed40019ServiceProcessIdentity {
    try lock.withLock {
      guard !values.isEmpty else { throw AuthoritySessionFixtureError.rejected }
      return values.removeFirst()
    }
  }
}

private func authorityIdentity(
  processIdentifier: pid_t = 6806
) -> Installed40019ServiceProcessIdentity {
  Installed40019ServiceProcessIdentity(
    service: .globalAuthority,
    processIdentifier: processIdentifier,
    userIdentifier: 0,
    startSeconds: 1_777_777_777,
    startMicroseconds: 123_456,
    xpcCodeSigningRequirement: "fixed-authority-requirement"
  )
}

@Test func installed40019AuthorityUsesTheRoleScopedHostMachService() {
  #expect(
    Installed40019AuthorityOffProver.hostMachServiceName
      == GlobalAuthorityConnectionContract.machServiceName(for: .host)
  )
  #expect(
    Installed40019AuthorityOffProver.hostMachServiceName
      == "YKUPL7Z869.group.com.bill.clashformac.global-authority.host"
  )
}

@Test func installed40019AuthorityProofUsesOneExactReadOnlySession() async throws {
  let identity = authorityIdentity()
  let session = StubInstalled40019AuthoritySession()
  let prover = Installed40019AuthorityOffProver(
    dependencies: Installed40019AuthorityOffProofDependencies(
      observeProcess: { identity },
      makeSession: { observed in
        #expect(observed == identity)
        return session
      }
    ))

  try await prover.proveOff()

  #expect(session.calls == ["handshake", "snapshot"])
  #expect(session.invalidated)
}

@Test func installed40019AuthorityAbsenceNeverCreatesAnXPCSession() async {
  let sessionCount = LockedCounter()
  let prover = Installed40019AuthorityOffProver(
    dependencies: Installed40019AuthorityOffProofDependencies(
      observeProcess: { throw AuthoritySessionFixtureError.rejected },
      makeSession: { _ in
        sessionCount.increment()
        return StubInstalled40019AuthoritySession()
      }
    ))

  await #expect(throws: (any Error).self) { try await prover.proveOff() }
  #expect(sessionCount.value == 0)
}

@Test func installed40019AuthorityPeerPIDMismatchStopsBeforeSnapshot() async {
  let identity = authorityIdentity()
  let session = StubInstalled40019AuthoritySession(processIdentifier: 9999)
  let prover = Installed40019AuthorityOffProver(
    dependencies: Installed40019AuthorityOffProofDependencies(
      observeProcess: { identity },
      makeSession: { _ in session }
    ))

  await #expect(throws: (any Error).self) { try await prover.proveOff() }
  #expect(session.calls == ["handshake"])
  #expect(session.invalidated)
}

@Test func installed40019AuthorityNonOffSnapshotIsRejected() async {
  let identity = authorityIdentity()
  let session = StubInstalled40019AuthoritySession(snapshotState: "active")
  let prover = Installed40019AuthorityOffProver(
    dependencies: Installed40019AuthorityOffProofDependencies(
      observeProcess: { identity },
      makeSession: { _ in session }
    ))

  do {
    try await prover.proveOff()
    Issue.record("non-Off installed Authority snapshot was accepted")
  } catch let error as AuthorityDomainError {
    #expect(error.code == .busy)
  } catch {
    Issue.record("non-Off installed Authority returned an unstable error type")
  }
  #expect(session.calls == ["handshake", "snapshot"])
  #expect(session.invalidated)
}

@Test func installed40019AuthorityHandshakeTimeoutIsTypedAndInvalidatesSession() async {
  let identity = authorityIdentity()
  let session = StubInstalled40019AuthoritySession(repliesToHandshake: false)
  let prover = Installed40019AuthorityOffProver(
    dependencies: Installed40019AuthorityOffProofDependencies(
      observeProcess: { identity },
      makeSession: { _ in session }
    ),
    timeout: .milliseconds(5)
  )

  do {
    try await prover.proveOff()
    Issue.record("installed Authority handshake timeout was accepted")
  } catch let error as AuthorityDomainError {
    #expect(error.code == .globalAuthorityTimeout)
  } catch {
    Issue.record("installed Authority timeout returned an unstable error type")
  }
  #expect(session.calls == ["handshake"])
  #expect(session.invalidated)
}

@Test func installed40019AuthorityTransportFailureStopsBeforeSnapshot() async {
  let identity = authorityIdentity()
  let session = StubInstalled40019AuthoritySession(
    handshakeFailure: AuthorityDomainError(code: .globalAuthorityInterrupted))
  let prover = Installed40019AuthorityOffProver(
    dependencies: Installed40019AuthorityOffProofDependencies(
      observeProcess: { identity },
      makeSession: { _ in session }
    ))

  do {
    try await prover.proveOff()
    Issue.record("installed Authority transport failure was accepted")
  } catch let error as AuthorityDomainError {
    #expect(error.code == .globalAuthorityInterrupted)
  } catch {
    Issue.record("installed Authority transport failure changed error type")
  }
  #expect(session.calls == ["handshake"])
  #expect(session.invalidated)
}

@Test func installed40019AuthorityPeerUIDMismatchStopsBeforeSnapshot() async {
  let identity = authorityIdentity()
  let session = StubInstalled40019AuthoritySession(effectiveUserIdentifier: 501)
  let prover = Installed40019AuthorityOffProver(
    dependencies: Installed40019AuthorityOffProofDependencies(
      observeProcess: { identity },
      makeSession: { _ in session }
    ))

  do {
    try await prover.proveOff()
    Issue.record("installed Authority peer UID mismatch was accepted")
  } catch let error as AuthorityDomainError {
    #expect(error.code == .globalAuthorityIdentityRejected)
  } catch {
    Issue.record("installed Authority UID mismatch changed error type")
  }
  #expect(session.calls == ["handshake"])
  #expect(session.invalidated)
}

@Test func installed40019AuthorityObserverDriftStopsBeforeSnapshot() async {
  let identity = authorityIdentity()
  let sequence = IdentitySequence([
    identity,
    identity,
    authorityIdentity(processIdentifier: 7000),
  ])
  let session = StubInstalled40019AuthoritySession()
  let prover = Installed40019AuthorityOffProver(
    dependencies: Installed40019AuthorityOffProofDependencies(
      observeProcess: sequence.next,
      makeSession: { _ in session }
    ))

  do {
    try await prover.proveOff()
    Issue.record("installed Authority process drift was accepted")
  } catch let error as AuthorityDomainError {
    #expect(error.code == .globalAuthorityIdentityRejected)
  } catch {
    Issue.record("installed Authority drift changed error type")
  }
  #expect(session.calls == ["handshake"])
  #expect(session.invalidated)
}

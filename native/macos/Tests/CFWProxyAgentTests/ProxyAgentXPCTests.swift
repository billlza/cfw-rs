import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// The agent's XPC connections: tracked connections, failure codes on the
// wire, and libbox calls that hold back no other message.
@objc private protocol ConnectionProbe {
  func ping(withReply reply: @escaping @Sendable () -> Void)
}

private final class ConnectionProbeService: NSObject, ConnectionProbe {
  func ping(withReply reply: @escaping @Sendable () -> Void) { reply() }
}

private final class TrackingListenerDelegate: NSObject, NSXPCListenerDelegate {
  private let connections: ProxyAgentConnections
  private let service = ConnectionProbeService()

  init(connections: ProxyAgentConnections) {
    self.connections = connections
  }

  func listener(
    _ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection
  ) -> Bool {
    connection.exportedInterface = NSXPCInterface(with: ConnectionProbe.self)
    connection.exportedObject = service
    connections.track(connection)
    connection.resume()
    return true
  }
}

/// Ending the ProxyAgent waits for a send barrier on every connection it
/// tracks. A tracked connection runs one while open and leaves once
/// invalidated, and libxpc runs a barrier issued on a cancelled connection at
/// once, so a connection that ends while the agent ends cannot hold it back.
@Test(.timeLimit(.minutes(1)))
func trackedConnectionRunsSendBarriersAndLeavesWhenInvalidated() async throws {
  let connections = ProxyAgentConnections()
  let delegate = TrackingListenerDelegate(connections: connections)
  let listener = NSXPCListener.anonymous()
  listener.delegate = delegate
  listener.resume()
  defer { listener.invalidate() }
  let client = NSXPCConnection(listenerEndpoint: listener.endpoint)
  client.remoteObjectInterface = NSXPCInterface(with: ConnectionProbe.self)
  client.resume()
  let probe = try #require(
    client.remoteObjectProxyWithErrorHandler { _ in } as? any ConnectionProbe)
  await withCheckedContinuation { (replied: CheckedContinuation<Void, Never>) in
    probe.ping { replied.resume() }
  }
  let open = connections.open
  #expect(open.count == 1)
  let accepted = try #require(open.first)
  await withCheckedContinuation { (sent: CheckedContinuation<Void, Never>) in
    accepted.scheduleSendBarrierBlock { sent.resume() }
  }

  client.invalidate()
  let deadline = ContinuousClock.now.advanced(by: .seconds(2))
  while !connections.open.isEmpty, ContinuousClock.now < deadline {
    try await Task.sleep(for: .milliseconds(10))
  }
  #expect(connections.open.isEmpty)
  await withCheckedContinuation { (ran: CheckedContinuation<Void, Never>) in
    accepted.scheduleSendBarrierBlock { ran.resume() }
  }
  withExtendedLifetime(delegate) {}
}

/// Every failure the ProxyAgent reports, with the code and retry flag it
/// crosses XPC with. The Host decides by these alone, for example that a stop
/// without a session found an owner that ended while a stale stop did not.
private let lifecycleFailureWire: [(failure: ProxySessionLifecycleError, code: String)] = [
  (.invalidConfigurationSlot, "invalid-configuration-slot"),
  (.lifecycleConflict, "proxy-lifecycle-conflict"),
  (.startupCancelled, "proxy-startup-cancelled"),
  (.staleStopRequest, "stale-stop-request"),
  (.stopWithoutSession, "proxy-stop-without-session"),
  (.recoveryBlocked("detail"), "proxy-recovery-blocked"),
  (.authorizationRequired, "system-proxy-authorization-required"),
  (.engineLease("detail"), "proxy-engine-lease-failed"),
  (.configuration("detail"), "proxy-configuration-failed"),
  (.engineCreation("detail"), "proxy-engine-creation-failed"),
  (.engineStart("detail"), "proxy-engine-start-failed"),
  (.engineStartTimedOut, "proxy-engine-start-timed-out"),
  (.endpointConflict(role: .mixed, port: 7890), "mixed-endpoint-in-use"),
  (.endpointConflict(role: .controller, port: 9090), "controller-endpoint-in-use"),
  (.listenerReadinessTimedOut, "proxy-listener-readiness-timeout"),
  (.engineUnclosable(LibboxInstanceUnclosable(closeFailure: "detail")), "proxy-engine-unclosable"),
  (.engineFailed(ProxyEngineFailure(code: "detail", message: "detail")), "proxy-engine-crashed"),
  (.preferences("detail"), "system-proxy-preferences-failed"),
  (.existingSystemProxy, "existing-system-proxy"),
  (.ownershipJournal("detail"), "proxy-ownership-journal-failed"),
  (.ownershipConflict([]), "system-proxy-ownership-conflict"),
  (.cleanupFailed(original: "detail", cleanup: ["detail"]), "proxy-cleanup-failed"),
  (.agentEnding, "proxy-agent-ending"),
]

/// The engine protocol admits only lowercase letters, digits and hyphens in a
/// code, and a reply it cannot encode reaches the Host as a broken connection.
/// Only an ending agent's refusal says a retry may succeed, which the agent
/// macOS starts next takes; every other lifecycle failure needs a new start or
/// the user's action.
@Test func everyLifecycleFailureCrossesXPCUnderItsOwnCode() throws {
  let failures =
    lifecycleFailureWire
    + AuthorityErrorCode.allCases.map { code in
      (
        failure: ProxySessionLifecycleError.authority(code),
        code: "authority-" + code.rawValue.replacingOccurrences(of: "_", with: "-")
      )
    }
  for (failure, code) in failures {
    let envelope = ResponseEnvelope(requestID: RequestID(), failure: failure.engineFailure)
    let encoded: Data
    do {
      encoded = try ProtocolCodec.encode(envelope)
    } catch {
      Issue.record("\(failure) cannot be sent to the Host: \(error)")
      continue
    }
    let received = try #require(try ProtocolCodec.decodeResponse(encoded).failure)
    #expect(received == failure.engineFailure)
    #expect(received.code == code, "\(failure)")
    #expect(received.isRetryable == (failure == .agentEnding), "\(failure)")
  }
}

/// A stop reaching an agent with no session and no record of the stop's
/// generation, as after its predecessor ended, is answered under the code the
/// Host takes for an ended owner.
@Test func aStopWithoutASessionCrossesXPCAsSuch() throws {
  let service = ProxyAgentService(
    lifecycle: ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle),
    configurationChecker: SourceBuiltLibboxConfigurationChecker(),
    preferences: SCPreferencesSystemProxyPreferences(),
    journalStore: FakeLifecycleJournalStore()
  )
  let request = RequestEnvelope(
    command: try NativeCommand(kind: .stop, configuration: descriptor()))
  let replied = DispatchSemaphore(value: 0)
  let reply = Mutex<(Data?, NSError?)>((nil, nil))
  service.execute(try ProtocolCodec.encode(request)) { data, error in
    reply.withLock { $0 = (data, error) }
    replied.signal()
  }
  #expect(replied.wait(timeout: .now() + 5) == .success)
  let (data, error) = reply.withLock { $0 }
  #expect(error == nil)
  let response = try ProtocolCodec.decodeResponse(try #require(data))
  #expect(response.requestID == request.requestID)
  let failure = try #require(response.failure)
  #expect(failure.code == "proxy-stop-without-session")
  #expect(!failure.isRetryable)
}

private final class ExportingListenerDelegate: NSObject, NSXPCListenerDelegate {
  private let service: ProxyAgentService

  init(service: ProxyAgentService) { self.service = service }

  func listener(
    _ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection
  ) -> Bool {
    connection.exportedInterface = NSXPCInterface(with: CFWProxyAgentXPCProtocol.self)
    connection.exportedObject = service
    connection.resume()
    return true
  }
}

/// NSXPCConnection hands one connection's messages to its exported object one
/// at a time. A check inside libbox leaves the connection's queue for its own
/// thread, so a snapshot sent after it on the same connection still answers.
@Test func aCheckInsideLibboxHoldsBackNoOtherMessageOnItsConnection() throws {
  let checker = FirstCheckGate()
  defer { checker.open() }
  let service = ProxyAgentService(
    lifecycle: ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle),
    configurationChecker: checker,
    preferences: SCPreferencesSystemProxyPreferences(),
    journalStore: FakeLifecycleJournalStore()
  )
  let delegate = ExportingListenerDelegate(service: service)
  let listener = NSXPCListener.anonymous()
  listener.delegate = delegate
  listener.resume()
  defer { listener.invalidate() }
  let client = NSXPCConnection(listenerEndpoint: listener.endpoint)
  client.remoteObjectInterface = NSXPCInterface(with: CFWProxyAgentXPCProtocol.self)
  client.resume()
  defer { client.invalidate() }
  let agent = try #require(
    client.remoteObjectProxyWithErrorHandler { _ in } as? any CFWProxyAgentXPCProtocol)

  let checked = DispatchSemaphore(value: 0)
  agent.validateConfiguration(
    Data("{}".utf8),
    request: try ProtocolCodec.encode(
      RequestEnvelope(
        command: try NativeCommand(kind: .validateConfiguration, configuration: descriptor())))
  ) { _, _ in checked.signal() }
  #expect(checker.awaitEntry())
  let snapshotted = DispatchSemaphore(value: 0)
  agent.execute(
    try ProtocolCodec.encode(RequestEnvelope(command: try NativeCommand(kind: .snapshot)))
  ) { _, _ in snapshotted.signal() }
  #expect(snapshotted.wait(timeout: .now() + 2) == .success)
  checker.open()
  #expect(checked.wait(timeout: .now() + 5) == .success)
  withExtendedLifetime(delegate) {}
}

/// A restore before a stop crosses XPC as an accepted command, which an
/// agent without a session answers at once.
@Test func aRestoreBeforeAStopCrossesXPCAsAnAcceptedCommand() throws {
  let service = ProxyAgentService(
    lifecycle: ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle),
    configurationChecker: SourceBuiltLibboxConfigurationChecker(),
    preferences: SCPreferencesSystemProxyPreferences(),
    journalStore: FakeLifecycleJournalStore()
  )
  let request = RequestEnvelope(
    command: try NativeCommand(kind: .restoreSettingsBeforeStop, configuration: descriptor()))
  let replied = DispatchSemaphore(value: 0)
  let reply = Mutex<(Data?, NSError?)>((nil, nil))
  service.execute(try ProtocolCodec.encode(request)) { data, error in
    reply.withLock { $0 = (data, error) }
    replied.signal()
  }
  #expect(replied.wait(timeout: .now() + 5) == .success)
  let (data, error) = reply.withLock { $0 }
  #expect(error == nil)
  let response = try ProtocolCodec.decodeResponse(try #require(data))
  #expect(response.requestID == request.requestID)
  #expect(response.result == (try CommandResult(kind: .accepted)))
}

/// libbox's close text can name servers and paths. However an error that
/// carries it is printed, described or sent, the text stays inside libbox's
/// own type.
@Test func libboxCloseTextNeverReachesTheAgentsErrorsOrReplies() throws {
  let canary = "close outbound proxy-canary.example:443 at /Users/someone/cache.db"
  let unclosable = LibboxInstanceUnclosable(closeFailure: canary)
  let failures: [ProxySessionLifecycleError] = [
    .engineUnclosable(unclosable),
    .cleanupFailed(
      original: String(describing: ProxySessionLifecycleError.engineUnclosable(unclosable)),
      cleanup: [String(reflecting: ProxySessionLifecycleError.engineUnclosable(unclosable))]),
  ]
  for failure in failures {
    var dumped = ""
    dump(failure, to: &dumped)
    for rendering in [
      String(describing: failure), String(reflecting: failure), "\(failure)", dumped,
      failure.localizedDescription, (failure as NSError).description,
      String(describing: (failure as NSError).userInfo),
      String(
        decoding: try ProtocolCodec.encode(
          ResponseEnvelope(requestID: RequestID(), failure: failure.engineFailure)), as: UTF8.self),
    ] {
      #expect(!rendering.contains("proxy-canary"), "\(rendering)")
    }
  }
  #expect(!unclosable.localizedDescription.contains("proxy-canary"))
  #expect(!String(describing: unclosable).contains("proxy-canary"))
}

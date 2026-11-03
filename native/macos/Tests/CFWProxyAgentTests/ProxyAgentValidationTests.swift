import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Checks and probes: runtime bytes before owner binding, retirement after a
// call that left its instance open, the call slots, and replies that never
// echo a secret.
private struct SecretEchoFailure: LocalizedError {
  let secret: String
  var errorDescription: String? { "libbox echoed secret: \(secret)" }
}

private struct SecretEchoConfigurationChecker: LibboxConfigurationChecking {
  let secret: String

  func check(configuration: Data) throws {
    _ = configuration
    throw SecretEchoFailure(secret: secret)
  }
}

@Test func proxyStartRejectsMismatchedRuntimeBytesBeforeOwnerBinding() throws {
  let owner = ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle)
  let service = ProxyAgentService(
    lifecycle: owner,
    configurationChecker: SecretEchoConfigurationChecker(secret: "unused"),
    preferences: SCPreferencesSystemProxyPreferences(),
    journalStore: FakeLifecycleJournalStore()
  )
  let configurationDescriptor = try descriptor()
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(configurationDescriptor.installationID),
      epoch: configurationDescriptor.epoch,
      generation: configurationDescriptor.generation),
    mode: .systemProxy,
    configSHA256: configurationDescriptor.sha256,
    identitySHA256: configurationDescriptor.identitySHA256,
    ownerUID: 501,
    authorityRevision: 1)
  let context = try ProxyOwnerContext(
    operation: operation,
    leaseID: AuthorityIdentifier(UUID()))
  let request = RequestEnvelope(
    command: try NativeCommand(
      kind: .startSystemProxy,
      configuration: configurationDescriptor))
  var responseData: Data?
  var responseError: NSError?

  service.startSystemProxy(
    Data(repeating: 0x5, count: AuthorityV1Limits.capabilityBytes),
    context: try AuthorityV1Codec.encodeCanonical(context),
    configuration: Data("{}".utf8),
    request: try ProtocolCodec.encode(request)
  ) { data, error in
    responseData = data
    responseError = error
  }

  #expect(responseError == nil)
  let response = try ProtocolCodec.decodeResponse(try #require(responseData))
  #expect(response.failure?.code == "invalid-runtime-configuration")
  #expect(owner.startCount == 0)
}

private struct CleanupFailingConfigurationChecker: LibboxConfigurationChecking {
  func check(configuration: Data) throws {
    throw LibboxRuntimeError.configurationCheckCleanupFailed(
      LibboxDiagnostic("close network: close interface monitor: proxy-canary"))
  }
}

/// libbox accepted the configuration but could not close the instance it built
/// to check it. That is no rejection of the profile, so the Host may ask again,
/// and since what the check built stays in this process, the agent retires and
/// the agent macOS starts next answers.
@Test func validationWhoseCheckCouldNotCloseIsRetryableAndNoRejection() throws {
  let owner = ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle)
  let service = ProxyAgentService(
    lifecycle: owner,
    configurationChecker: CleanupFailingConfigurationChecker(),
    preferences: SCPreferencesSystemProxyPreferences(),
    journalStore: FakeLifecycleJournalStore()
  )
  let request = RequestEnvelope(
    command: try NativeCommand(kind: .validateConfiguration, configuration: descriptor()))
  let (data, error) = try validationReply(service, Data("{}".utf8), request)
  #expect(error == nil)
  #expect(!String(decoding: data, as: UTF8.self).contains("proxy-canary"))
  let failure = try #require(try ProtocolCodec.decodeResponse(data).failure)
  #expect(failure.code == "configuration-check-cleanup-failed")
  #expect(failure.isRetryable)
  #expect(owner.waitUntilRetired())
}

/// Runs each bounded call to its end on the caller's thread, with no timer, so
/// the call's reply and end have both run once the request returns.
private let inlineBoundedCall = LibboxBoundedCall(
  afterAwake: { _, _ in {} }, startCall: { _, work in work() })

private struct RefusingChecker: LibboxConfigurationChecking {
  func check(configuration: Data) throws {
    throw LibboxRuntimeError.configurationCheckFailed(LibboxDiagnostic("unknown outbound type"))
  }
}

private struct AcceptingChecker: LibboxConfigurationChecking {
  func check(configuration: Data) throws {}
}

/// A probe that answers each target with a delay, or fails as `failure`.
private struct AnsweringProbe: LibboxProfileProbing {
  var failure: LibboxRuntimeError?

  func test(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) throws -> [ProfileProxyDelay] {
    if let failure { throw failure }
    return try proxies.map { try ProfileProxyDelay(name: $0, delay: 10, errorKind: nil) }
  }
}

private func probeRequest(
  _ service: ProxyAgentService, reply: @escaping (Data?, NSError?) -> Void
) {
  service.testProfileProxies(
    Data("{}".utf8), proxies: Data(#"["p"]"#.utf8), timeoutMS: 500, targetURL: "",
    expectedStatus: "", withReply: reply)
}

/// A check libbox refused, or a probe libbox failed, is an ordinary answer: the
/// agent keeps calling libbox and retires nothing. Only an instance libbox
/// could not close, or a call it never returned from, retires it.
@Test func anOrdinaryCheckOrProbeFailureRetiresNothing() throws {
  let owner = ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle)
  let service = ProxyAgentService(
    lifecycle: owner, configurationChecker: RefusingChecker(),
    preferences: SCPreferencesSystemProxyPreferences(), journalStore: FakeLifecycleJournalStore(),
    profileProbe: AnsweringProbe(
      failure: .serviceStartFailed(LibboxDiagnostic("dial tcp: i/o timeout"))),
    boundedCall: inlineBoundedCall)
  let request = RequestEnvelope(
    command: try NativeCommand(kind: .validateConfiguration, configuration: descriptor()))
  let (data, error) = try validationReply(service, Data("{}".utf8), request)
  #expect(error == nil)
  #expect(try ProtocolCodec.decodeResponse(data).failure?.code == "configuration-rejected")
  let probeError = Mutex<NSError?>(nil)
  probeRequest(service) { _, error in probeError.withLock { $0 = error } }
  #expect(probeError.withLock { $0?.code } == ProfileProbeServiceFailure.executionFailed.rawValue)
  #expect(owner.retirements.isEmpty)
  #expect(owner.callsLibbox)
}

/// A check or probe whose instance libbox could not close retires the agent
/// before its answer goes out, so a request the Host sends on that answer is
/// refused already.
@Test func aCallThatLeftItsInstanceOpenRetiresTheAgentBeforeItsAnswer() throws {
  let owner = ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle)
  let service = ProxyAgentService(
    lifecycle: owner, configurationChecker: CleanupFailingConfigurationChecker(),
    preferences: SCPreferencesSystemProxyPreferences(), journalStore: FakeLifecycleJournalStore(),
    profileProbe: AnsweringProbe(
      failure: .profileProbeCleanupFailed(LibboxDiagnostic("close: outbound"))),
    boundedCall: inlineBoundedCall)
  let atCheckAnswer = Mutex<(callsLibbox: Bool, retirements: Int)?>(nil)
  service.validateConfiguration(
    Data("{}".utf8),
    request: try ProtocolCodec.encode(
      RequestEnvelope(
        command: try NativeCommand(kind: .validateConfiguration, configuration: descriptor())))
  ) { _, _ in
    atCheckAnswer.withLock { $0 = (owner.callsLibbox, owner.retirements.count) }
  }
  let check = try #require(atCheckAnswer.withLock { $0 })
  #expect(!check.callsLibbox)
  #expect(check.retirements == 1)

  let probeOwner = ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle)
  let probeService = ProxyAgentService(
    lifecycle: probeOwner, configurationChecker: AcceptingChecker(),
    preferences: SCPreferencesSystemProxyPreferences(), journalStore: FakeLifecycleJournalStore(),
    profileProbe: AnsweringProbe(
      failure: .profileProbeCleanupFailed(LibboxDiagnostic("close: outbound"))),
    boundedCall: inlineBoundedCall)
  let atProbeAnswer = Mutex<(callsLibbox: Bool, retirements: Int)?>(nil)
  probeRequest(probeService) { _, _ in
    atProbeAnswer.withLock { $0 = (probeOwner.callsLibbox, probeOwner.retirements.count) }
  }
  let probe = try #require(atProbeAnswer.withLock { $0 })
  #expect(!probe.callsLibbox)
  #expect(probe.retirements == 1)
}

/// A call that returned frees its slot before its reply, so the next one the
/// Host sends once that reply arrived is admitted at once, for checks and
/// probes alike.
@Test func aCallThatReturnedAdmitsTheNextOneBeforeItsReplyIsOver() throws {
  let service = ProxyAgentService(
    lifecycle: ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle),
    configurationChecker: AcceptingChecker(),
    preferences: SCPreferencesSystemProxyPreferences(), journalStore: FakeLifecycleJournalStore(),
    profileProbe: AnsweringProbe(), boundedCall: inlineBoundedCall)
  let check = try ProtocolCodec.encode(
    RequestEnvelope(
      command: try NativeCommand(kind: .validateConfiguration, configuration: descriptor())))
  let nextCheck = Mutex<Data?>(nil)
  service.validateConfiguration(Data("{}".utf8), request: check) { _, _ in
    service.validateConfiguration(Data("{}".utf8), request: check) { data, _ in
      nextCheck.withLock { $0 = data }
    }
  }
  let nextCheckData = try #require(nextCheck.withLock { $0 })
  #expect(try ProtocolCodec.decodeResponse(nextCheckData).failure == nil)

  let nextProbe = Mutex<(Data?, NSError?)>((nil, nil))
  probeRequest(service) { _, _ in
    probeRequest(service) { data, error in nextProbe.withLock { $0 = (data, error) } }
  }
  let (probeData, probeError) = nextProbe.withLock { $0 }
  #expect(probeError == nil)
  #expect(probeData != nil)
}

/// Runs the first bounded call on the caller's thread and every later one on
/// a queue of its own.
private final class FirstCallInline: @unchecked Sendable {
  private let lock = NSLock()
  private var started = 0

  var start: LibboxBoundedCall.StartCall {
    { qos, work in
      let first = self.lock.withLock { () -> Bool in
        self.started += 1
        return self.started == 1
      }
      if first {
        work()
      } else {
        LibboxBoundedCall.onItsOwnQueue(qos, work)
      }
    }
  }
}

/// Lets the first check return at once and holds the second inside "libbox"
/// until the test opens it.
private final class SecondCheckGate: LibboxConfigurationChecking, @unchecked Sendable {
  private let lock = NSLock()
  private var calls = 0
  private let entered = DispatchSemaphore(value: 0)
  private let opened = DispatchSemaphore(value: 0)

  func check(configuration: Data) throws {
    let second = lock.withLock { () -> Bool in
      calls += 1
      return calls == 2
    }
    guard second else { return }
    entered.signal()
    _ = opened.wait(timeout: .now() + .seconds(30))
  }

  func awaitEntry() -> Bool { entered.wait(timeout: .now() + .seconds(5)) == .success }
  func open() { opened.signal() }
}

/// A call that returned ends after its reply. By then the next call may hold
/// the slot, and the late end frees only the slot of its own call, so a third
/// call still finds the second inside libbox.
@Test func aReturnedCallsLateEndFreesNoNewerCallsSlot() throws {
  let checker = SecondCheckGate()
  defer { checker.open() }
  let service = ProxyAgentService(
    lifecycle: ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle),
    configurationChecker: checker,
    preferences: SCPreferencesSystemProxyPreferences(), journalStore: FakeLifecycleJournalStore(),
    boundedCall: LibboxBoundedCall(
      afterAwake: { _, _ in {} }, startCall: FirstCallInline().start))
  let check = try ProtocolCodec.encode(
    RequestEnvelope(
      command: try NativeCommand(kind: .validateConfiguration, configuration: descriptor())))
  service.validateConfiguration(Data("{}".utf8), request: check) { _, _ in
    service.validateConfiguration(Data("{}".utf8), request: check) { _, _ in }
  }
  #expect(checker.awaitEntry())
  let third = Mutex<Data?>(nil)
  service.validateConfiguration(Data("{}".utf8), request: check) { data, _ in
    third.withLock { $0 = data }
  }
  let thirdData = try #require(third.withLock { $0 }, "the third check was admitted")
  #expect(
    try ProtocolCodec.decodeResponse(thirdData).failure?.code
      == "configuration-check-timed-out")
}

/// Every request counts as unanswered until its reply is handed to XPC, a
/// check still inside libbox included, and none is once all are answered.
@Test func everyRequestCountsAsUnansweredUntilItsReply() throws {
  let checker = FirstCheckGate()
  defer { checker.open() }
  let requests = ProxyAgentUnansweredRequests()
  let service = ProxyAgentService(
    lifecycle: ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle),
    configurationChecker: checker,
    preferences: SCPreferencesSystemProxyPreferences(), journalStore: FakeLifecycleJournalStore(),
    requests: requests)
  let checked = DispatchSemaphore(value: 0)
  service.validateConfiguration(
    Data("{}".utf8),
    request: try ProtocolCodec.encode(
      RequestEnvelope(
        command: try NativeCommand(kind: .validateConfiguration, configuration: descriptor())))
  ) { _, _ in checked.signal() }
  #expect(checker.awaitEntry())
  let none = DispatchSemaphore(value: 0)
  requests.whenNone { none.signal() }
  #expect(none.wait(timeout: .now() + .milliseconds(200)) == .timedOut)
  checker.open()
  #expect(checked.wait(timeout: .now() + 5) == .success)
  #expect(none.wait(timeout: .now() + 5) == .success)

  let snapshotted = DispatchSemaphore(value: 0)
  service.execute(
    try ProtocolCodec.encode(RequestEnvelope(command: try NativeCommand(kind: .snapshot)))
  ) { _, _ in snapshotted.signal() }
  #expect(snapshotted.wait(timeout: .now() + 5) == .success)
  let noneAgain = DispatchSemaphore(value: 0)
  requests.whenNone { noneAgain.signal() }
  #expect(noneAgain.wait(timeout: .now() + 5) == .success)
}

/// Only a configuration libbox read and refused is a rejected profile. A check
/// libbox could not answer, including one that broke libbox's own API by
/// returning nothing, is no verdict on the profile.
@Test func everyCheckFailureTellsTheHostWhetherTheProfileWasRejected() {
  let diagnostic = LibboxDiagnostic("detail")
  let expected: [(LibboxRuntimeError, ProxyAgentFailureCode)] = [
    (.invalidConfigurationSize(0), .configurationRejected),
    (.invalidConfigurationEncoding, .configurationRejected),
    (.invalidConfigurationJSON, .configurationRejected),
    (.configurationCheckFailed(diagnostic), .configurationRejected),
    (.libboxUnavailable, .validatorUnavailable),
    (.missingBundleSetting("key"), .validatorUnavailable),
    (.appGroupUnavailable("group"), .validatorUnavailable),
    (.unsafeRuntimeDirectory("path"), .validatorUnavailable),
    (.setupConflict, .validatorUnavailable),
    (.setupFailed(diagnostic), .validatorUnavailable),
    (.configurationCheckCleanupFailed(diagnostic), .configurationCheckCleanupFailed),
    (.configurationCheckReturnedNothing, .validatorFailed),
    (.profileProbeCleanupFailed(diagnostic), .validatorFailed),
    (.unexpectedPacketDescriptor, .validatorFailed),
    (.missingPacketDescriptor, .validatorFailed),
    (.packetDescriptorAlreadyTransferred, .validatorFailed),
    (.unsupportedPlatformOperation("operation"), .validatorFailed),
    (.networkMonitorAlreadyStarted, .validatorFailed),
    (.networkMonitorUnavailable, .validatorFailed),
    (.networkMonitorTimedOut, .validatorFailed),
    (.alreadyStarted, .validatorFailed),
    (.serverCreationFailed(diagnostic), .validatorFailed),
    (.serviceStartFailed(diagnostic), .validatorFailed),
    (.serviceStartTimedOut, .validatorFailed),
    (.invalidRuntimeEndpoints, .validatorFailed),
    (.invalidEndpointConflict(kind: 0, port: 0), .validatorFailed),
    (.endpointConflict(role: .mixed, port: 7890), .validatorFailed),
    (.serviceNotRunning(state: 0, message: diagnostic), .validatorFailed),
  ]
  for (error, code) in expected {
    let failure = ProxyAgentService.validationFailure(for: error)
    #expect(failure.code == code.rawValue, "\(error)")
    #expect(failure.isRetryable == (code != .configurationRejected), "\(error)")
  }
}

@Test func proxyValidationResponseNeverEchoesUnderlyingSecretError() throws {
  let secret = "credential-that-must-never-leave-agent"
  let service = ProxyAgentService(
    lifecycle: ValidationOnlyProxyOwner(lifecycle: makeLifecycleFixture().lifecycle),
    configurationChecker: SecretEchoConfigurationChecker(secret: secret),
    preferences: SCPreferencesSystemProxyPreferences(),
    journalStore: FakeLifecycleJournalStore()
  )
  let request = RequestEnvelope(
    command: try NativeCommand(
      kind: .validateConfiguration,
      configuration: descriptor()
    )
  )
  let (data, responseError) = try validationReply(
    service, Data("{\"password\":\"\(secret)\"}".utf8), request)

  #expect(responseError == nil)
  #expect(!String(decoding: data, as: UTF8.self).contains(secret))
  let response = try ProtocolCodec.decodeResponse(data)
  #expect(response.failure?.code == "configuration-validator-failed")
  #expect(
    response.failure?.message
      == "Configuration validation failed at an explicit internal boundary."
  )
}

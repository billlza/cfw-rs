import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// The session lifecycle fixture: a descriptor-only start, operation, event and
// exit recorders, libbox runtimes that time out or cannot close, and the
// builders of descriptors, fixtures and recovery lifecycles.
/// Test-only adapter that always supplies a fresh one-use in-memory template.
/// Production has no descriptor-only start overload and cannot read a template
/// back from disk.
extension ProxySessionLifecycle {
  func start(
    configuration descriptor: ConfigurationDescriptor,
    completionHandler:
      @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    start(
      configuration: SensitiveDataBuffer(copying: Data("{}".utf8)),
      descriptor: descriptor,
      deadline: EngineStartDeadline(receivedAt: .now),
      completionHandler: completionHandler)
  }
}

enum OperationOutcome: Equatable {
  case success
  case failure(ProxySessionLifecycleError)
}

final class OperationRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let completed = DispatchSemaphore(value: 0)
  private var outcomes: [OperationOutcome] = []

  func record(_ result: Result<Void, ProxySessionLifecycleError>) {
    lock.withLock {
      switch result {
      case .success: outcomes.append(.success)
      case .failure(let error): outcomes.append(.failure(error))
      }
    }
    completed.signal()
  }

  func wait() -> Bool {
    completed.wait(timeout: .now() + 1) == .success
  }

  var values: [OperationOutcome] {
    lock.withLock { outcomes }
  }
}

/// What happened, in order: completions the test records and ended processes.
final class EventLog: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []

  func record(_ event: String) {
    lock.withLock { events.append(event) }
  }

  var values: [String] {
    lock.withLock { events }
  }
}

final class EndProcessRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let ended = DispatchSemaphore(value: 0)
  private var failures: [ProxyAgentEndReason] = []

  func record(_ failure: ProxyAgentEndReason) {
    lock.withLock { failures.append(failure) }
    ended.signal()
  }

  func wait() -> Bool {
    ended.wait(timeout: .now() + 1) == .success
  }

  var values: [ProxyAgentEndReason] {
    lock.withLock { failures }
  }
}

struct ProxyFixture {
  let lifecycle: ProxySessionLifecycle
  let engine: FakeLifecycleEngine
  let lease: FakeLease
  let preferences: FakeLifecyclePreferences
  let journalStore: FakeLifecycleJournalStore
  let endRecorder: EndProcessRecorder
  let events: EventLog
}

/// A runtime whose start ran past its deadline and was interrupted.
final class TimedOutLibboxRuntime: LibboxServiceRuntime, @unchecked Sendable {
  private let lock = NSLock()
  private var stopCountValue = 0
  private var startDeadlines: [EngineStartDeadline] = []

  var stopCount: Int { lock.withLock { stopCountValue } }
  var deadlines: [EngineStartDeadline] { lock.withLock { startDeadlines } }

  func start(configuration: Data, packetFileDescriptor: Int32?, deadline: EngineStartDeadline)
    throws
  {
    lock.withLock { startDeadlines.append(deadline) }
    throw LibboxRuntimeError.serviceStartTimedOut
  }

  func stop() throws(LibboxInstanceUnclosable) { lock.withLock { stopCountValue += 1 } }
  func healthCheck() throws {}
  func resetNetwork() {}
}

/// A runtime whose failed start libbox could not close: the start throws the
/// close failure, and so does every stop.
final class UnclosableLibboxRuntime: LibboxServiceRuntime, @unchecked Sendable {
  private let lock = NSLock()
  private let closeFailure: LibboxInstanceUnclosable
  private var startCountValue = 0
  private var stopCountValue = 0

  init(closeFailure: LibboxInstanceUnclosable) {
    self.closeFailure = closeFailure
  }

  var startCount: Int { lock.withLock { startCountValue } }
  var stopCount: Int { lock.withLock { stopCountValue } }

  func start(configuration: Data, packetFileDescriptor: Int32?, deadline: EngineStartDeadline)
    throws
  {
    lock.withLock { startCountValue += 1 }
    throw closeFailure
  }

  func stop() throws(LibboxInstanceUnclosable) {
    lock.withLock { stopCountValue += 1 }
    throw closeFailure
  }

  func healthCheck() throws {}
  func resetNetwork() {}
}

struct StubLibboxRuntimeFactory: LibboxServiceRuntimeFactory {
  let runtime: any LibboxServiceRuntime & Sendable

  func makeRuntime(role: LibboxRuntimeRole) throws -> any LibboxServiceRuntime { runtime }
}

/// The smallest configuration the real engine admits: an app-owned controller
/// and the System Proxy mixed listener.
func receiptConfiguration() -> Data {
  Data(
    #"{"experimental":{"clash_api":{"external_controller":"127.0.0.1:9091","secret":"s"}},"inbounds":[{"type":"mixed","tag":"cfw-system-proxy","listen":"127.0.0.1","listen_port":7891}]}"#
      .utf8)
}

func descriptor(generation: UInt64 = 1, slot: ConfigurationSlot = .systemProxy) throws
  -> ConfigurationDescriptor
{
  guard
    let installationID = UUID(
      uuidString: "11111111-1111-1111-1111-111111111111"
    )
  else {
    throw ForcedProxyFailure.requested
  }
  return try ConfigurationDescriptor(
    slot: slot,
    tunnelOptions: nil,
    credentialAudience: CredentialAudience(
      profileID: installationID,
      profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
    installationID: installationID,
    epoch: 1,
    generation: generation,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )
}

func makeLifecycleFixture(
  creationFails: Bool = false,
  preferences: FakeLifecyclePreferences = FakeLifecyclePreferences(),
  journalStore: FakeLifecycleJournalStore = FakeLifecycleJournalStore(),
  readinessTimeout: TimeInterval = 60
) -> ProxyFixture {
  let engine = FakeLifecycleEngine()
  let lease = FakeLease()
  let endRecorder = EndProcessRecorder()
  let events = EventLog()
  let lifecycle = ProxySessionLifecycle(
    dependencies: ProxySessionDependencies(
      prepareOwnership: { _ in
        PreparedProxyOwnership(lease: lease)
      },
      recoverCleanupLease: { _ in lease },
      engineFactory: FakeLifecycleEngineFactory(
        engine: engine,
        creationFails: creationFails
      ),
      preferences: preferences,
      journalStore: journalStore,
      readinessTimeout: readinessTimeout,
      endProcess: { failure in
        events.record("end")
        endRecorder.record(failure)
      }
    )
  )
  return ProxyFixture(
    lifecycle: lifecycle,
    engine: engine,
    lease: lease,
    preferences: preferences,
    journalStore: journalStore,
    endRecorder: endRecorder,
    events: events
  )
}

/// Runs the restore that follows granted rights and waits until it finished.
func restoreAfterAuthorization(_ lifecycle: ProxySessionLifecycle) -> Bool {
  let finished = DispatchSemaphore(value: 0)
  lifecycle.restoreSettingsAfterAuthorization { finished.signal() }
  return finished.wait(timeout: .now() + 1) == .success
}

func keychainRecoveryStore(
  dataStore: any JournalDataStoring
) -> KeychainProxyOwnershipJournalStore {
  KeychainProxyOwnershipJournalStore(testingDataStore: dataStore)
}

func recoveryLifecycle(
  preferences: FakeLifecyclePreferences,
  journalStore: any ProxyOwnershipJournalStoring
) -> ProxySessionLifecycle {
  let engine = FakeLifecycleEngine()
  let lease = FakeLease()
  return ProxySessionLifecycle(
    dependencies: ProxySessionDependencies(
      prepareOwnership: { _ in
        PreparedProxyOwnership(lease: lease)
      },
      recoverCleanupLease: { _ in lease },
      engineFactory: FakeLifecycleEngineFactory(engine: engine, creationFails: false),
      preferences: preferences,
      journalStore: journalStore,
      readinessTimeout: 60,
      endProcess: { _ in Issue.record("every engine in this test closes") }
    )
  )
}

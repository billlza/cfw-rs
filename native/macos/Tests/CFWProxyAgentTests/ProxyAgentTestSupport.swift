import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Fixtures shared by the ProxyAgent test files: an owner that only validates,
// an unclosable libbox instance, a check held until released, a validation
// reply and a ready listener endpoint.
/// Keeps this validation-only service test behind the same Authority-owned
/// surface as production. An accidental start fails explicitly instead of
/// bypassing the one-use owner authorization contract.
final class ValidationOnlyProxyOwner: ProxySystemProxyOwning, @unchecked Sendable {
  private let lifecycle: ProxySessionLifecycle
  private let lock = NSLock()
  private var startCountValue = 0

  init(lifecycle: ProxySessionLifecycle) {
    self.lifecycle = lifecycle
  }

  func start(
    configuration: SensitiveDataBuffer,
    descriptor: ConfigurationDescriptor,
    authorization: ProxyOwnerAuthorization,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    lock.withLock { startCountValue += 1 }
    configuration.erase()
    _ = descriptor
    authorization.erase()
    completionHandler(
      .failure(.engineLease("Validation-only owner cannot authorize a start.")))
  }

  var startCount: Int { lock.withLock { startCountValue } }

  func stop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    lifecycle.stop(
      expectedConfiguration: expectedConfiguration,
      completionHandler: completionHandler)
  }

  func snapshot(
    completionHandler: @escaping @Sendable (EngineSnapshot) -> Void
  ) {
    lifecycle.snapshot(completionHandler: completionHandler)
  }

  func restoreSettingsAfterAuthorization(completionHandler: @escaping @Sendable () -> Void) {
    lifecycle.restoreSettingsAfterAuthorization(completionHandler: completionHandler)
  }

  func restoreSettingsBeforeStop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    lifecycle.restoreSettingsBeforeStop(
      expectedConfiguration: expectedConfiguration, completionHandler: completionHandler)
  }

  var callsLibbox: Bool { lifecycle.callsLibbox }

  private let retired = DispatchSemaphore(value: 0)
  private var retirementsValue: [LibboxInstanceUnclosable] = []
  var retirements: [LibboxInstanceUnclosable] { lock.withLock { retirementsValue } }

  func retire(after failure: LibboxInstanceUnclosable) {
    lock.withLock { retirementsValue.append(failure) }
    lifecycle.retire(after: failure)
    retired.signal()
  }

  func waitUntilRetired() -> Bool { retired.wait(timeout: .now() + 2) == .success }
}

let unclosable = LibboxInstanceUnclosable(closeFailure: "close network: monitor")

/// Holds the first configuration check inside "libbox" until the test opens
/// it; later checks return at once.
final class FirstCheckGate: LibboxConfigurationChecking, @unchecked Sendable {
  private let lock = NSLock()
  private var calls = 0
  private let entered = DispatchSemaphore(value: 0)
  private let opened = DispatchSemaphore(value: 0)

  func check(configuration: Data) throws {
    let first = lock.withLock { () -> Bool in
      calls += 1
      return calls == 1
    }
    guard first else { return }
    entered.signal()
    _ = opened.wait(timeout: .now() + .seconds(30))
  }

  func awaitEntry() -> Bool { entered.wait(timeout: .now() + .seconds(5)) == .success }
  func open() { opened.signal() }
}

/// Sends one validation request and waits for its reply, which arrives from
/// the check's own thread.
func validationReply(
  _ service: ProxyAgentService, _ configuration: Data, _ request: RequestEnvelope
) throws -> (Data, NSError?) {
  let replied = DispatchSemaphore(value: 0)
  let reply = Mutex<(Data?, NSError?)>((nil, nil))
  service.validateConfiguration(configuration, request: try ProtocolCodec.encode(request)) {
    data, error in
    reply.withLock { $0 = (data, error) }
    replied.signal()
  }
  #expect(replied.wait(timeout: .now() + 5) == .success)
  let (data, error) = reply.withLock { $0 }
  return (try #require(data), error)
}

func readyEndpoint() throws -> MixedListenerEndpoint {
  try MixedListenerEndpoint(host: "127.0.0.1", port: 7_890)
}

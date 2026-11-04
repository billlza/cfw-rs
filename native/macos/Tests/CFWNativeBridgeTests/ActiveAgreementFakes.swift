import CFWCredentialTransport
import CFWCredentialVault
import Foundation
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// The active agreement fakes: leases, the ProxyAgent, the installed 40019
// Authority and transport, the tunnel host, credential vault and service
// maintainer, and the observers and sentinels around them.
struct StubLease: NativeEngineLeaseInspecting {
  let observation: AuthorityOwnershipObservation
  let onObservation: @Sendable () -> Void

  init(
    observation: AuthorityOwnershipObservation,
    onObservation: @escaping @Sendable () -> Void = {}
  ) {
    self.observation = observation
    self.onObservation = onObservation
  }

  func isAvailable() async throws -> Bool { observation.state == .off }
  func authorityOwnership() async throws -> AuthorityOwnershipObservation {
    onObservation()
    return observation
  }
  func beginStop(
    for descriptor: ConfigurationDescriptor
  ) async throws -> NativeAuthorityStopContext {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop boundary")
  }
  func completeStop(_ context: NativeAuthorityStopContext) async throws {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop boundary")
  }
}

actor StubProxyAgent: ProxyAgentTransporting, Installed40019ProxySnapshotting {
  func testProfileProxies(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) async throws
    -> [ProfileProxyDelay]
  {
    throw ProxyAgentHostError.malformedResponse
  }

  var authorizationCount = 0
  var authorizationRestorationOnly: [Bool] = []
  func authorizeSystemProxy(restorationOnly: Bool) async throws {
    authorizationCount += 1
    authorizationRestorationOnly.append(restorationOnly)
  }
  let observed: EngineSnapshot
  init(_ observed: EngineSnapshot) { self.observed = observed }
  func registrationStatus() -> ProxyAgentRegistrationStatus { .notRegistered }
  func ensureRegistered() throws {}
  func start(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    authorization: HostPreparedSystemProxyStart
  ) throws {
    _ = configuration
    _ = descriptor
    authorization.erase()
    throw UnusedSystemProxyStartPreparerError.unexpectedInvocation
  }
  func stop(configuration: ConfigurationDescriptor) throws {}
  func restoreSettingsBeforeStop(configuration: ConfigurationDescriptor) throws {}
  func snapshot() -> EngineSnapshot { observed }
  func snapshotInstalled40019ForMigration() -> EngineSnapshot { observed }
  func validateConfiguration(_ configuration: Data, descriptor: ConfigurationDescriptor) throws {}
}

struct StubInstalled40019Authority: Installed40019AuthorityOffProving {
  let observation: AuthorityOwnershipObservation
  let onObservation: @Sendable () -> Void

  func proveOff() async throws {
    onObservation()
    guard observation.state == .off, observation.lease == nil else {
      throw AuthorityDomainError(code: .cleanupUnproven)
    }
  }
}

private struct FixedInstalled40019ProxyServiceController: ProxyAgentServiceControlling {
  func registrationStatus() -> ProxyAgentRegistrationStatus { .enabled }
  func ensureRegistered() throws {}
}

private struct Installed40019ProxyRequestIdentity: Decodable {
  let schemaVersion: UInt16
  let requestID: RequestID
  let command: NativeCommand
}

private struct Installed40019ProxyResponseEnvelope: Encodable {
  let schemaVersion: UInt16 = 5
  let requestID: RequestID
  let result: CommandResult
}

func realInstalled40019ProxyTransport(
  snapshot: EngineSnapshot
) throws -> AuthenticatedProxyAgentTransport {
  let uid: uid_t = 501
  let identity = Installed40019ServiceProcessIdentity(
    service: .proxyAgent,
    processIdentifier: 4_242,
    userIdentifier: uid,
    startSeconds: 1_700_000_000,
    startMicroseconds: 123_456,
    xpcCodeSigningRequirement: Installed40019ServiceProcessObserver.codeSigningRequirement(
      for: .proxyAgent,
      invokingUserIdentifier: uid
    )
  )
  let dependencies = Installed40019ProxyTransportDependencies(
    observeProcess: { identity },
    makeConnection: { _ in
      NSXPCConnection(machServiceName: "com.bill.clashformac.tests.never-activated")
    },
    prepareConnection: { _, _ in },
    activateConnection: { _ in },
    execute: { _, data, reply in
      do {
        let request = try JSONDecoder().decode(
          Installed40019ProxyRequestIdentity.self,
          from: data
        )
        guard request.schemaVersion == 5, request.command.kind == .snapshot else {
          throw ProtocolValidationError.invalidCommand
        }
        let response = Installed40019ProxyResponseEnvelope(
          requestID: request.requestID,
          result: try CommandResult(kind: .snapshot, snapshot: snapshot)
        )
        reply(try JSONEncoder().encode(response), nil)
      } catch {
        reply(nil, error as NSError)
      }
    },
    peerProcessIdentifier: { _ in identity.processIdentifier },
    peerUserIdentifier: { _ in identity.userIdentifier }
  )
  return try AuthenticatedProxyAgentTransport(
    machServiceName: "com.bill.clashformac.proxy-agent",
    teamIdentifier: "YKUPL7Z869",
    proxyAgentBundleIdentifier: "com.bill.clashformac.proxy-agent",
    currentCodeHash: try ServiceCodeHash(Data(repeating: 0x42, count: 20)),
    serviceController: FixedInstalled40019ProxyServiceController(),
    installed40019Dependencies: dependencies
  )
}

actor StubTunnelHost: TunnelHostBridging {
  let observed: EngineSnapshot
  let pendingPreference: ConfigurationDescriptor?
  let recoveryStatus: RecoveryManagedTunnelStatus
  init(
    _ observed: EngineSnapshot,
    pendingPreference: ConfigurationDescriptor? = nil,
    recoveryStatus: RecoveryManagedTunnelStatus = .unknown
  ) {
    self.observed = observed
    self.pendingPreference = pendingPreference
    self.recoveryStatus = recoveryStatus
  }
  func installTunnel() throws -> SystemExtensionInstallResult { .completed }
  func awaitTunnelInstallationApproval() -> SystemExtensionApprovalWait {
    Issue.record("this fixture never awaits an approval")
    return .noPendingRequest
  }
  func cancelTunnelInstallationWait() {}
  func authorizeTunnelConfiguration(_ descriptor: ConfigurationDescriptor) throws {
    throw AppleNetworkError.providerDidNotRespond
  }

  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) {}
  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) {}
  func snapshot() -> EngineSnapshot { observed }
  func recoveryManagedTunnelStatus() -> RecoveryManagedTunnelStatus { recoveryStatus }
  func hasManagedTunnelConfiguration() -> Bool { false }
  func managedTunnelConfiguration() -> ConfigurationDescriptor? { nil }
  func pendingPreferenceMutationConfiguration() -> ConfigurationDescriptor? {
    pendingPreference
  }
  func compensatePendingPreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor,
    revokePreparation: @escaping @Sendable () async throws -> Void
  ) async throws -> Bool { false }
  func finishPreferenceCompensation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws {}
  func completePreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor
  ) {}
}

final class StubCredentialVault: NativeCredentialVaulting, @unchecked Sendable {
  func provision(
    audience: CredentialAudience,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CFWCredentialVault.CredentialVaultReceipt {
    throw CredentialVaultError.missingVault
  }
  func presence(
    audience: CredentialAudience,
    of references: [CredentialReference]
  ) throws -> [CFWCredentialVault.CredentialPresence] { [] }
  func resolve(
    audience: CredentialAudience,
    slots: [CredentialSlot]
  ) throws -> CredentialMaterial { .empty }
  func previewGarbageCollection(
    _ request: CredentialGarbageCollectionRequest
  ) throws -> CredentialGarbageCollectionPreview {
    throw CredentialVaultError.missingVault
  }
  func commitGarbageCollection(
    _ request: CredentialGarbageCollectionCommitRequest
  ) throws -> CredentialGarbageCollectionReceipt {
    throw CredentialVaultError.missingVault
  }
}

final class StubServiceMaintainer: CurrentAppServiceMaintaining,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var proxy: CurrentAppServiceStatus
  private var authority: CurrentAppServiceStatus
  private let onPerform:
    @Sendable (
      CurrentAppServiceMutation, CurrentAppService
    ) throws -> Void
  private(set) var registerCalls = 0
  private(set) var unregisterCalls = 0

  init(
    proxy: CurrentAppServiceStatus = .enabled,
    authority: CurrentAppServiceStatus = .enabled,
    onPerform:
      @escaping @Sendable (
        CurrentAppServiceMutation, CurrentAppService
      ) throws -> Void = { _, _ in }
  ) {
    self.proxy = proxy
    self.authority = authority
    self.onPerform = onPerform
  }

  func status(of service: CurrentAppService) -> CurrentAppServiceStatus {
    lock.withLock { service == .proxyAgent ? proxy : authority }
  }

  func perform(
    _ mutation: CurrentAppServiceMutation,
    on service: CurrentAppService
  ) throws -> CurrentAppServiceStatus {
    let result = lock.withLock {
      switch mutation {
      case .observe:
        return service == .proxyAgent ? proxy : authority
      case .register:
        registerCalls += 1
        if service == .proxyAgent { proxy = .enabled } else { authority = .enabled }
        return .enabled
      case .unregister:
        unregisterCalls += 1
        if service == .proxyAgent {
          proxy = .notRegistered
        } else {
          authority = .notRegistered
        }
        return .notRegistered
      }
    }
    try onPerform(mutation, service)
    return result
  }
}

private enum SimulatedServiceMutationInterruption: Error { case afterRegister }

struct StubSystemProxySwitchObserver: CurrentSystemProxySwitchObserving {
  let observed: CurrentSystemProxySwitchStatus
  func status() -> CurrentSystemProxySwitchStatus { observed }
}

final class SequencedSystemProxySwitchObserver: CurrentSystemProxySwitchObserving,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var observations: [CurrentSystemProxySwitchStatus]
  init(_ observations: [CurrentSystemProxySwitchStatus]) { self.observations = observations }
  func status() -> CurrentSystemProxySwitchStatus {
    lock.withLock {
      guard !observations.isEmpty else { return .unobservable }
      return observations.removeFirst()
    }
  }
}

final class FailAfterFirstAuthorityRegister: @unchecked Sendable {
  private let lock = NSLock()
  private var armed = true

  func check(
    _ mutation: CurrentAppServiceMutation,
    _ service: CurrentAppService
  ) throws {
    let shouldFail = lock.withLock { () -> Bool in
      guard armed, mutation == .register, service == .globalAuthority else {
        return false
      }
      armed = false
      return true
    }
    if shouldFail { throw SimulatedServiceMutationInterruption.afterRegister }
  }
}

final class SequencedServiceRuntimeObserver: CurrentAppServiceRuntimeObserving,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var proxyStatuses: [CurrentAppServiceRuntimeStatus]
  private var authorityStatuses: [CurrentAppServiceRuntimeStatus]

  init(
    proxyStatuses: [CurrentAppServiceRuntimeStatus] = [.absent],
    authorityStatuses: [CurrentAppServiceRuntimeStatus] = [.absent]
  ) {
    self.proxyStatuses = proxyStatuses
    self.authorityStatuses = authorityStatuses
  }

  func status(of service: CurrentAppService) -> CurrentAppServiceRuntimeStatus {
    lock.withLock {
      switch service {
      case .proxyAgent:
        guard proxyStatuses.count > 1 else {
          return proxyStatuses.first ?? .unobservable
        }
        return proxyStatuses.removeFirst()
      case .globalAuthority:
        guard authorityStatuses.count > 1 else {
          return authorityStatuses.first ?? .unobservable
        }
        return authorityStatuses.removeFirst()
      }
    }
  }
}

final class EventLedger: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []

  func append(_ event: String) {
    lock.withLock { events.append(event) }
  }

  var snapshot: [String] { lock.withLock { events } }
}

final class LeaseSentinel: @unchecked Sendable {
  private let lock = NSLock()
  private var held = false

  func acquire() throws {
    try lock.withLock {
      guard !held else { throw CrossProcessEngineLeaseError.alreadyHeld }
      held = true
    }
  }

  func release() {
    lock.withLock { held = false }
  }

  var isHeld: Bool { lock.withLock { held } }
}

private final class SentinelLeaseHolder: NativeHostOperationLeaseHolding,
  @unchecked Sendable
{
  private let sentinel: LeaseSentinel
  init(_ sentinel: LeaseSentinel) { self.sentinel = sentinel }
  func release() { sentinel.release() }
}

struct SentinelLeaseAcquirer: NativeHostOperationLeaseAcquiring {
  let sentinel: LeaseSentinel
  func acquire() throws -> any NativeHostOperationLeaseHolding {
    try sentinel.acquire()
    return SentinelLeaseHolder(sentinel)
  }
}

final class StubServiceRuntimeObserver: CurrentAppServiceRuntimeObserving,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var statuses: [CurrentAppService: CurrentAppServiceRuntimeStatus]
  private let onObservation: @Sendable (CurrentAppService) -> Void
  private(set) var observations: [CurrentAppService] = []

  init(
    proxy: CurrentAppServiceRuntimeStatus = .absent,
    authority: CurrentAppServiceRuntimeStatus = .absent,
    onObservation: @escaping @Sendable (CurrentAppService) -> Void = { _ in }
  ) {
    statuses = [.proxyAgent: proxy, .globalAuthority: authority]
    self.onObservation = onObservation
  }

  func status(of service: CurrentAppService) -> CurrentAppServiceRuntimeStatus {
    onObservation(service)
    return lock.withLock {
      observations.append(service)
      return statuses[service] ?? .unobservable
    }
  }
}

struct BusyNativeHostOperationLease: NativeHostOperationLeaseAcquiring {
  func acquire() throws -> any NativeHostOperationLeaseHolding {
    throw CrossProcessEngineLeaseError.alreadyHeld
  }
}

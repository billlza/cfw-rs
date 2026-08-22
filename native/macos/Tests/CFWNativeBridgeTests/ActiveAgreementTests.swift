import CFWAppleNetwork
import CFWCredentialTransport
import CFWCredentialVault
import Foundation
import Testing

@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Deterministic coverage for task 5.2: an owner is classified Active only when the
// Global_Lease, Operation_Context, owner-ready attestation, configuration digest,
// and effective OS state agree exactly. Every single mismatch must fail closed as
// Failed, Recovering, or Quarantined — never Active and never Off from ambiguity.
// All OS/XPC/Authority side effects are behind in-memory fakes: no real
// NetworkExtension, SystemConfiguration, or launchd is exercised.

private let installationID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
private let otherInstallationID = UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
private let epoch: UInt64 = 4
private let generation: UInt64 = 9

private func digest(_ byte: String) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(hex: String(repeating: byte, count: 32))
}

private func descriptor(
  slot: ConfigurationSlot,
  epoch: UInt64 = epoch,
  generation: UInt64 = generation,
  installationID: UUID = installationID,
  config: String = "ab",
  identity: String = "cd"
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: slot,
    tunnelOptions: slot == .tunnel ? TunnelNetworkOptions(ipv6Enabled: true) : nil,
    credentialAudience: CredentialAudience(
      profileID: installationID,
      profileDigest: digest("ee")),
    installationID: installationID,
    epoch: epoch,
    generation: generation,
    byteCount: 42,
    sha256: digest(config),
    identitySHA256: digest(identity)
  )
}

private func agreement(
  for descriptor: ConfigurationDescriptor,
  mode: AuthorityMode,
  leaseState: AuthorityLeaseState = .active,
  epoch: UInt64? = nil,
  generation: UInt64? = nil,
  installationID: UUID? = nil,
  configSHA256: CFWSharedProtocol.SHA256Digest? = nil,
  identitySHA256: CFWSharedProtocol.SHA256Digest? = nil
) -> AuthorityLeaseAgreement {
  AuthorityLeaseAgreement(
    installationID: installationID ?? descriptor.installationID,
    epoch: epoch ?? descriptor.epoch,
    generation: generation ?? descriptor.generation,
    ownerUID: 501,
    mode: mode,
    configSHA256: configSHA256 ?? descriptor.sha256,
    identitySHA256: identitySHA256 ?? descriptor.identitySHA256,
    leaseState: leaseState
  )
}

private struct StubLease: NativeEngineLeaseInspecting {
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

private actor StubProxyAgent: ProxyAgentTransporting {
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
  func snapshot() -> EngineSnapshot { observed }
  func validateConfiguration(_ configuration: Data, descriptor: ConfigurationDescriptor) throws {}
}

private actor StubTunnelHost: TunnelHostBridging {
  let observed: EngineSnapshot
  let pendingPreference: ConfigurationDescriptor?
  init(
    _ observed: EngineSnapshot,
    pendingPreference: ConfigurationDescriptor? = nil
  ) {
    self.observed = observed
    self.pendingPreference = pendingPreference
  }
  func installTunnel() throws -> SystemExtensionInstallResult { .completed }
  func cancelTunnelInstallationWait() {}
  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) {}
  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) {}
  func snapshot() -> EngineSnapshot { observed }
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

private final class StubCredentialVault: NativeCredentialVaulting, @unchecked Sendable {
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

private final class StubServiceMaintainer: CurrentAppServiceMaintaining,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var proxy: CurrentAppServiceStatus
  private var authority: CurrentAppServiceStatus
  private let onPerform:
    @Sendable (
      CurrentAppServiceMutation, CurrentAppService
    ) -> Void
  private(set) var registerCalls = 0
  private(set) var unregisterCalls = 0

  init(
    proxy: CurrentAppServiceStatus = .enabled,
    authority: CurrentAppServiceStatus = .enabled,
    onPerform:
      @escaping @Sendable (
        CurrentAppServiceMutation, CurrentAppService
      ) -> Void = { _, _ in }
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
    onPerform(mutation, service)
    return lock.withLock {
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
  }
}

private final class SequencedServiceRuntimeObserver: CurrentAppServiceRuntimeObserving,
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

private final class EventLedger: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []

  func append(_ event: String) {
    lock.withLock { events.append(event) }
  }

  var snapshot: [String] { lock.withLock { events } }
}

private final class LeaseSentinel: @unchecked Sendable {
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

private struct SentinelLeaseAcquirer: NativeHostOperationLeaseAcquiring {
  let sentinel: LeaseSentinel
  func acquire() throws -> any NativeHostOperationLeaseHolding {
    try sentinel.acquire()
    return SentinelLeaseHolder(sentinel)
  }
}

private final class StubServiceRuntimeObserver: CurrentAppServiceRuntimeObserving,
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

private struct BusyNativeHostOperationLease: NativeHostOperationLeaseAcquiring {
  func acquire() throws -> any NativeHostOperationLeaseHolding {
    throw CrossProcessEngineLeaseError.alreadyHeld
  }
}

private func coordinator(
  proxy: EngineSnapshot,
  tunnel: EngineSnapshot,
  observation: AuthorityOwnershipObservation,
  onAuthorityObservation: @escaping @Sendable () -> Void = {},
  pendingPreference: ConfigurationDescriptor? = nil,
  serviceMaintainer: any CurrentAppServiceMaintaining = StubServiceMaintainer(),
  serviceRuntimeObserver: any CurrentAppServiceRuntimeObserving =
    StubServiceRuntimeObserver(),
  hostOperationLease: any NativeHostOperationLeaseAcquiring =
    AvailableNativeHostOperationLease()
) -> NativeBridgeCoordinator {
  NativeBridgeCoordinator(
    proxy: StubProxyAgent(proxy),
    systemProxyPreparer: UnusedSystemProxyStartPreparer(),
    tunnel: StubTunnelHost(tunnel, pendingPreference: pendingPreference),
    engineLease: StubLease(
      observation: observation,
      onObservation: onAuthorityObservation
    ),
    credentialVault: StubCredentialVault(),
    hostOperationLease: hostOperationLease,
    serviceMaintainer: serviceMaintainer,
    serviceRuntimeObserver: serviceRuntimeObserver
  )
}

private func statusErrorCode(
  _ coordinator: NativeBridgeCoordinator
) async -> NativeBridgeErrorCode? {
  do {
    _ = try await coordinator.execute(.queryStatus)
    return nil
  } catch let error as NativeBridgeExecutionError {
    switch error {
    case .failure(let code, _): return code
    }
  } catch {
    return nil
  }
}

private func maintenanceErrorCode(
  _ coordinator: NativeBridgeCoordinator,
  action: NativeServiceMaintenanceAction
) async -> NativeBridgeErrorCode? {
  do {
    _ = try await coordinator.execute(.maintainCurrentServices(action))
    return nil
  } catch let error as NativeBridgeExecutionError {
    switch error {
    case .failure(let code, _): return code
    }
  } catch {
    return nil
  }
}

@Test func maintenanceOffAndMutationShareTheHostOperationLease() async throws {
  let sentinel = LeaseSentinel()
  let maintainer = StubServiceMaintainer { _, _ in
    #expect(sentinel.isHeld)
  }
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    onAuthorityObservation: {
      #expect(sentinel.isHeld)
    },
    serviceMaintainer: maintainer,
    hostOperationLease: SentinelLeaseAcquirer(sentinel: sentinel)
  )

  guard
    case .serviceMaintenance(let result) = try await coordinator.execute(
      .maintainCurrentServices(.unregisterProxyAgent))
  else {
    Issue.record("maintenance returned the wrong result kind")
    return
  }
  #expect(result.engineStatus == .off)
  #expect(result.proxyAgent == .notRegistered)
  #expect(result.globalAuthority == .enabled)
  #expect(maintainer.unregisterCalls == 1)
  #expect(maintainer.registerCalls == 0)
  #expect(!sentinel.isHeld)
}

@Test func fixedMaintenanceSequencePreservesOrderingAndEndsEnabledOff() async throws {
  let maintainer = StubServiceMaintainer()
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer
  )

  let actions: [NativeServiceMaintenanceAction] = [
    .unregisterProxyAgent,
    .unregisterGlobalAuthority,
    .registerGlobalAuthority,
    .registerProxyAgent,
    .proveOff,
  ]
  for action in actions {
    guard
      case .serviceMaintenance(let result) = try await coordinator.execute(
        .maintainCurrentServices(action))
    else {
      Issue.record("maintenance returned the wrong result kind")
      return
    }
    #expect(result.action == action)
    #expect(result.engineStatus == .off)
  }
  #expect(maintainer.unregisterCalls == 2)
  #expect(maintainer.registerCalls == 2)
  #expect(maintainer.status(of: .proxyAgent) == .enabled)
  #expect(maintainer.status(of: .globalAuthority) == .enabled)
}

@Test func maintenanceStatusIsPureAndDoesNotClaimEngineOff() async throws {
  let maintainer = StubServiceMaintainer(proxy: .notFound, authority: .unknown)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .active, lease: nil),
    serviceMaintainer: maintainer
  )

  guard
    case .serviceMaintenance(let result) = try await coordinator.execute(
      .maintainCurrentServices(.status))
  else {
    Issue.record("maintenance status returned the wrong result kind")
    return
  }
  #expect(result.engineStatus == nil)
  #expect(result.proxyAgent == .notFound)
  #expect(result.globalAuthority == .unknown)
  #expect(maintainer.unregisterCalls == 0)
  #expect(maintainer.registerCalls == 0)
}

@Test func everyUnprovenAuthorityStateBlocksBeforeServiceMutation() async {
  for state in [
    AuthorityState.preparing, .starting, .active, .stopping, .recovering, .quarantined,
  ] {
    let maintainer = StubServiceMaintainer()
    let coordinator = coordinator(
      proxy: .off,
      tunnel: .off,
      observation: AuthorityOwnershipObservation(state: state, lease: nil),
      serviceMaintainer: maintainer
    )
    #expect(
      await maintenanceErrorCode(
        coordinator, action: .unregisterProxyAgent) != nil)
    #expect(maintainer.unregisterCalls == 0)
    #expect(maintainer.registerCalls == 0)
  }
}

@Test func maintenanceLeaseContentionBlocksBeforeObservationOrMutation() async {
  let maintainer = StubServiceMaintainer()
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    hostOperationLease: BusyNativeHostOperationLease()
  )
  #expect(
    await maintenanceErrorCode(coordinator, action: .unregisterProxyAgent) == .busy)
  #expect(maintainer.unregisterCalls == 0)
  #expect(maintainer.registerCalls == 0)
}

@Test func pureMaintenanceProofNeverRepairsAnAbsentProxyAgent() async {
  let maintainer = StubServiceMaintainer(proxy: .notRegistered, authority: .enabled)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer
  )
  #expect(await maintenanceErrorCode(coordinator, action: .proveOff) != nil)
  #expect(maintainer.registerCalls == 0)
  #expect(maintainer.unregisterCalls == 0)
}

@Test func maintenanceRejectsEveryNonOffNativeOwnerBeforeMutation() async throws {
  let proxyDescriptor = try descriptor(slot: .systemProxy)
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let failure = EngineFailure(
    code: "fixture_failed", message: "retained owner", isRetryable: false)
  let cases: [(proxy: EngineSnapshot, tunnel: EngineSnapshot)] = [
    (
      .proxyActive(configuration: proxyDescriptor, sequence: 1),
      .off
    ),
    (
      .proxyFailed(failure, configuration: proxyDescriptor, sequence: 2),
      .off
    ),
    (
      .off,
      .tunnelActive(configuration: tunnelDescriptor, sequence: 3)
    ),
    (
      .off,
      .tunnelFailed(failure, configuration: tunnelDescriptor, sequence: 4)
    ),
  ]

  for item in cases {
    let maintainer = StubServiceMaintainer()
    let subject = coordinator(
      proxy: item.proxy,
      tunnel: item.tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceMaintainer: maintainer
    )
    #expect(
      await maintenanceErrorCode(subject, action: .unregisterProxyAgent) == .busy)
    #expect(maintainer.registerCalls == 0)
    #expect(maintainer.unregisterCalls == 0)
  }
}

@Test func pendingTunnelPreferenceBlocksMaintenanceBeforeMutation() async throws {
  let maintainer = StubServiceMaintainer()
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    pendingPreference: try descriptor(slot: .tunnel),
    serviceMaintainer: maintainer
  )
  #expect(
    await maintenanceErrorCode(subject, action: .unregisterProxyAgent)
      == .cleanupUnproven)
  #expect(maintainer.registerCalls == 0)
  #expect(maintainer.unregisterCalls == 0)
}

@Test func unregisteredProxyRequiresStableProcessAbsenceBeforeAuthorityMutation() async {
  for status in [
    CurrentAppServiceRuntimeStatus.present,
    CurrentAppServiceRuntimeStatus.unobservable,
  ] {
    let maintainer = StubServiceMaintainer(
      proxy: .notRegistered, authority: .enabled)
    let subject = coordinator(
      proxy: .off,
      tunnel: .off,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceMaintainer: maintainer,
      serviceRuntimeObserver: StubServiceRuntimeObserver(proxy: status)
    )
    #expect(
      await maintenanceErrorCode(subject, action: .unregisterGlobalAuthority)
        != nil)
    #expect(maintainer.registerCalls == 0)
    #expect(maintainer.unregisterCalls == 0)
  }
}

@Test func processAbsenceProofRejectsConcurrentRegistrationDrift() async {
  let maintainer = StubServiceMaintainer(
    proxy: .notRegistered, authority: .enabled)
  let observer = StubServiceRuntimeObserver { service in
    if service == .proxyAgent {
      _ = try? maintainer.perform(.register, on: .proxyAgent)
    }
  }
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: observer
  )
  #expect(
    await maintenanceErrorCode(subject, action: .unregisterGlobalAuthority)
      == .cleanupUnproven)
  #expect(maintainer.registerCalls == 1)
  #expect(maintainer.unregisterCalls == 0)
}

@Test func absentAuthorityRetryExplicitlyReprovesOffAndReturnsToAbsent() async throws {
  let ledger = EventLedger()
  let maintainer = StubServiceMaintainer(
    proxy: .notRegistered,
    authority: .notRegistered,
    onPerform: { mutation, service in
      guard service == .globalAuthority else { return }
      ledger.append(
        mutation == .register ? "register_authority" : "unregister_authority")
    })
  let runtimeObserver = StubServiceRuntimeObserver { service in
    if service == .globalAuthority {
      ledger.append("authority_absence")
    }
  }
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    onAuthorityObservation: {
      ledger.append("authority_off")
    },
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: runtimeObserver
  )

  guard
    case .serviceMaintenance(let result) = try await subject.execute(
      .maintainCurrentServices(.unregisterGlobalAuthority))
  else {
    Issue.record("authority retry returned the wrong result kind")
    return
  }
  #expect(result.engineStatus == .off)
  #expect(result.proxyAgent == .notRegistered)
  #expect(result.globalAuthority == .notRegistered)
  #expect(maintainer.registerCalls == 1)
  #expect(maintainer.unregisterCalls == 1)
  #expect(
    ledger.snapshot == [
      "authority_absence",
      "register_authority",
      "authority_off",
      "unregister_authority",
      "authority_absence",
      "authority_absence",
    ])
}

@Test func absentAuthorityRetryDoesNotUnregisterWhenDurableStateIsActive() async {
  let maintainer = StubServiceMaintainer(
    proxy: .notRegistered, authority: .notRegistered)
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .active, lease: nil),
    serviceMaintainer: maintainer
  )

  #expect(
    await maintenanceErrorCode(subject, action: .unregisterGlobalAuthority) == .busy)
  #expect(maintainer.registerCalls == 1)
  #expect(maintainer.unregisterCalls == 0)
  #expect(maintainer.status(of: .globalAuthority) == .enabled)
}

@Test func authorityAbsenceFailureEmitsNoReceiptAndRetryConvergesForward() async throws {
  let maintainer = StubServiceMaintainer(
    proxy: .notRegistered, authority: .notRegistered)
  let first = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: SequencedServiceRuntimeObserver(
      authorityStatuses: [.absent, .unobservable])
  )
  #expect(
    await maintenanceErrorCode(first, action: .unregisterGlobalAuthority)
      == .cleanupUnproven)
  #expect(maintainer.status(of: .globalAuthority) == .notRegistered)

  let retry = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer
  )
  guard
    case .serviceMaintenance(let result) = try await retry.execute(
      .maintainCurrentServices(.unregisterGlobalAuthority))
  else {
    Issue.record("authority absence retry returned the wrong result kind")
    return
  }
  #expect(result.engineStatus == .off)
  #expect(result.globalAuthority == .notRegistered)
  #expect(maintainer.registerCalls == 2)
  #expect(maintainer.unregisterCalls == 2)
}

@Test func unregisterWaitsForProxyProcessToReachStableAbsence() async throws {
  let maintainer = StubServiceMaintainer()
  let observer = SequencedServiceRuntimeObserver(
    proxyStatuses: [.present, .absent])
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: observer
  )
  guard
    case .serviceMaintenance(let result) = try await subject.execute(
      .maintainCurrentServices(.unregisterProxyAgent))
  else {
    Issue.record("proxy unregister returned the wrong result kind")
    return
  }
  #expect(result.proxyAgent == .notRegistered)
  #expect(result.engineStatus == .off)
}

@Test func tunnelActiveOnlyOnExactFiveWayAgreement() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .tunnelActive(configuration: tunnelDescriptor, sequence: 3),
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(for: tunnelDescriptor, mode: .tunnel)
    )
  )

  guard case .status(.tunnel(let runtime)) = try await coordinator.execute(.queryStatus) else {
    Issue.record("exact five-way agreement did not classify Tunnel Active")
    return
  }
  #expect(runtime.owner == .packetTunnelSystemExtension)
  #expect(runtime.configDigest == tunnelDescriptor.identitySHA256.hex)
  #expect(runtime.context.installationID == installationID)
  #expect(runtime.context.generation == generation)
  #expect(runtime.ready)
}

@Test func systemProxyActiveOnlyOnExactFiveWayAgreement() async throws {
  let proxyDescriptor = try descriptor(slot: .systemProxy)
  let coordinator = coordinator(
    proxy: .proxyActive(configuration: proxyDescriptor, sequence: 2),
    tunnel: .off,
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(for: proxyDescriptor, mode: .systemProxy)
    )
  )

  guard
    case .status(.systemProxy(let runtime)) =
      try await coordinator.execute(.queryStatus)
  else {
    Issue.record("exact five-way agreement did not classify System Proxy Active")
    return
  }
  #expect(runtime.owner == .proxyAgent)
  #expect(runtime.configDigest == proxyDescriptor.identitySHA256.hex)
}

@Test func leaseContextMismatchIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .tunnelActive(configuration: tunnelDescriptor, sequence: 3),
    observation: AuthorityOwnershipObservation(
      state: .active,
      // Authority lease is bound to a different generation than the OS descriptor.
      lease: agreement(for: tunnelDescriptor, mode: .tunnel, generation: generation + 1)
    )
  )
  #expect(await statusErrorCode(coordinator) == .identityRejected)
}

@Test func wrongConfigurationDigestIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .tunnelActive(configuration: tunnelDescriptor, sequence: 3),
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(
        for: tunnelDescriptor,
        mode: .tunnel,
        configSHA256: try digest("ef")
      )
    )
  )
  #expect(await statusErrorCode(coordinator) == .identityRejected)
}

@Test func missingReadyAttestationIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .tunnelActive(configuration: tunnelDescriptor, sequence: 3),
    observation: AuthorityOwnershipObservation(
      state: .active,
      // The owner is bound but has not yet attested ready (lease not Active).
      lease: agreement(for: tunnelDescriptor, mode: .tunnel, leaseState: .bound)
    )
  )
  #expect(await statusErrorCode(coordinator) == .identityRejected)
}

@Test func osStateNotConnectedIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let starting = try EngineSnapshot(
    mode: .tunnel,
    state: EngineState(kind: .tunnelStarting),
    configuration: tunnelDescriptor,
    sequence: 1
  )
  let coordinator = coordinator(
    proxy: .off,
    tunnel: starting,
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(for: tunnelDescriptor, mode: .tunnel)
    )
  )
  // Effective OS state is not connected: the machine is transitional, not Active.
  #expect(await statusErrorCode(coordinator) == .busy)
}

@Test func snapshotStateNotActiveIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let active = EngineSnapshot.tunnelActive(configuration: tunnelDescriptor, sequence: 3)

  let recovering = coordinator(
    proxy: .off,
    tunnel: active,
    observation: AuthorityOwnershipObservation(state: .recovering, lease: nil)
  )
  #expect(await statusErrorCode(recovering) == .globalAuthorityRecovering)

  let quarantined = coordinator(
    proxy: .off,
    tunnel: active,
    observation: AuthorityOwnershipObservation(state: .quarantined, lease: nil)
  )
  #expect(await statusErrorCode(quarantined) == .quarantined)

  // Authority proves global Off while the OS shows an active owner: ambiguity that
  // must fail closed as Quarantined, never Active and never Off.
  let ambiguousOff = coordinator(
    proxy: .off,
    tunnel: active,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil)
  )
  #expect(await statusErrorCode(ambiguousOff) == .quarantined)
}

@Test func offOnlyWhenAuthorityProvesGlobalOff() async throws {
  let allOff = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil)
  )
  guard case .status(.off) = try await allOff.execute(.queryStatus) else {
    Issue.record("stable Off with proven Authority Off did not classify Off")
    return
  }

  // Owners are Off but the Authority still holds/prepares a lease: not Off.
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let leaseHeld = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(for: tunnelDescriptor, mode: .tunnel)
    )
  )
  #expect(await statusErrorCode(leaseHeld) == .busy)

  let recovering = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .recovering, lease: nil)
  )
  #expect(await statusErrorCode(recovering) == .globalAuthorityRecovering)
}

@Test func installationLineageMismatchIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .tunnelActive(configuration: tunnelDescriptor, sequence: 3),
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(
        for: tunnelDescriptor,
        mode: .tunnel,
        installationID: otherInstallationID
      )
    )
  )
  #expect(await statusErrorCode(coordinator) == .identityRejected)
}

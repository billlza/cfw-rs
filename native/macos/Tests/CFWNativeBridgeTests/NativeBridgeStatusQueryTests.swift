import CFWCredentialTransport
import CFWCredentialVault
import CryptoKit
import Foundation
@preconcurrency import NetworkExtension
@preconcurrency import SystemExtensions
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Status queries: registration before the proxy snapshot, released and
// restarted owners, and quarantined or recovering Authorities.
extension NativeBridgeStartCommandIntegrationTests {
  @Test func queryStatusRegistersFreshInstallBeforeProxySnapshotWhenAuthorityIsOff()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      initiallyRegistered: false)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("fresh-install registration did not reach proven global Off")
      return
    }
    let counters = await proxy.counters()
    #expect(counters.ensure == 1)
    #expect(counters.snapshot == 1)
  }

  @Test func queryStatusRegistrationApprovalDenialPrecedesEveryProxySnapshot()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      registrationError: .registrationRequiresApproval,
      initiallyRegistered: false)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    #expect(await failureCode(coordinator, .queryStatus) == .proxyAgentApprovalRequired)
    let counters = await proxy.counters()
    #expect(counters.ensure == 1)
    #expect(counters.snapshot == 0)
  }

  @Test func queryStatusMissingAgentIsTypedUnavailableBeforeProxySnapshot()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      registrationError: .registrationUnavailable,
      initiallyRegistered: false)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    #expect(await failureCode(coordinator, .queryStatus) == .unavailable)
    let counters = await proxy.counters()
    #expect(counters.ensure == 1)
    #expect(counters.snapshot == 0)
  }

  @Test func queryStatusCompletesExactPersistedStoppingLeaseAfterHostRestart()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let recovery = try recoveredStop(for: descriptor)
    let stopping = AuthorityOwnershipObservation(
      state: .stopping,
      lease: agreement(
        for: descriptor,
        mode: .systemProxy,
        leaseState: .stopping))
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(
      observation: stopping,
      recoveredStop: recovery)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: stopping,
      engineLease: lease)

    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("exact persisted stopping lease did not complete global Off")
      return
    }
    #expect(recovery.commandContext == request.context)
    #expect(await lease.recoverCount() == 1)
    #expect(await lease.counters() == (begin: 0, complete: 1))
  }

  @Test(arguments: [false, true], [ConfigurationSlot.localProxy, .systemProxy, .tunnel])
  func stopAcknowledgesReleasedOwnerWithOrWithoutPriorStatusRead(
    priorStatusRead: Bool, slot: ConfigurationSlot
  )
    async throws
  {
    let request = try startRequest(
      tunnelOptions: slot == .tunnel ? TunnelNetworkOptions(ipv6Enabled: true) : nil,
      mode: slot == .localProxy ? .localProxy : nil)
    let descriptor = try request.descriptor(slot: slot)
    let recovery = try recoveredStop(for: descriptor)
    let stopping = AuthorityOwnershipObservation(
      state: .stopping,
      lease: agreement(for: descriptor, mode: slot.authorityMode, leaseState: .stopping))
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(observation: stopping, recoveredStop: recovery)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel, observation: stopping, engineLease: lease)
    if priorStatusRead {
      guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
        Issue.record("the exact stopped owner was not reconciled to global Off")
        return
      }
    }
    let command: NativeBridgeCommand =
      switch slot {
      case .localProxy: .stopLocalProxy(request.context)
      case .systemProxy: .stopSystemProxy(request.context)
      case .tunnel: .stopTunnel(request.context)
      }
    guard case .acknowledged = try await coordinator.execute(command) else {
      Issue.record("an already completed native stop was not acknowledged")
      return
    }
    #expect(await lease.currentState() == .off)
    #expect(await proxy.counters().stop == 0)
    #expect(await lease.counters().begin == 0)
  }

  @Test(arguments: [false, true])
  func releasedOwnerStopRejectsWrongContextAndMissingOwnerProof(wrongContext: Bool)
    async throws
  {
    let request = try startRequest(tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let stopping = AuthorityOwnershipObservation(
      state: .stopping,
      lease: agreement(for: descriptor, mode: .tunnel, leaseState: .stopping))
    let lease = RecordingEngineLease(
      observation: stopping, recoveredStop: try recoveredStop(for: descriptor),
      completeError: wrongContext ? nil : AuthorityDomainError(code: .cleanupUnproven))
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel, observation: stopping, engineLease: lease)
    let context = try EngineCommandContext(
      installationID: request.context.installationID, configEpoch: request.context.configEpoch,
      generation: request.context.generation + (wrongContext ? 1 : 0))
    #expect(
      await failureCode(coordinator, .stopTunnel(context))
        == (wrongContext ? .identityRejected : .cleanupUnproven))
    #expect(await lease.currentState() == .stopping)
    #expect(await lease.counters().begin == 0)
    #expect(await lease.counters().complete == (wrongContext ? 0 : 1))
    #expect(await tunnel.stopCalls == 0)
  }

  @Test(arguments: [false, true])
  func releasedOwnerStopReconcilesRestartedAuthorityButRejectsAnotherGeneration(wrongContext: Bool)
    async throws
  {
    let request = try startRequest(tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let recovering = AuthorityOwnershipObservation(state: .recovering, lease: nil)
    let lease = RecordingEngineLease(observation: recovering, replayContext: request.context)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel, observation: recovering, engineLease: lease)
    let context = try EngineCommandContext(
      installationID: request.context.installationID, configEpoch: request.context.configEpoch,
      generation: request.context.generation + (wrongContext ? 1 : 0))
    if wrongContext {
      #expect(await failureCode(coordinator, .stopTunnel(context)) == .identityRejected)
    } else {
      guard case .acknowledged = try await coordinator.execute(.stopTunnel(context)) else {
        Issue.record("an exact stop did not consume the independently recovered Off proof")
        return
      }
    }
    #expect(await lease.currentState() == .off)
    #expect(await lease.reconcileCount() == 1)
    #expect(await lease.counters() == (begin: 0, complete: 0))
    #expect(await tunnel.stopCalls == 0)
  }

  @Test func queryStatusDoesNotInferOwnerStoppedFromStableOwnerSnapshots()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let recovery = try recoveredStop(for: descriptor)
    let stopping = AuthorityOwnershipObservation(
      state: .stopping,
      lease: agreement(
        for: descriptor,
        mode: .systemProxy,
        leaseState: .stopping))
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(
      observation: stopping,
      recoveredStop: recovery,
      completeError: AuthorityDomainError(code: .cleanupUnproven))
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: stopping,
      engineLease: lease)

    #expect(await failureCode(coordinator, .queryStatus) == .cleanupUnproven)
    #expect(await lease.recoverCount() == 1)
    #expect(await lease.counters() == (begin: 0, complete: 1))
    #expect(await lease.currentState() == .stopping)
  }

  @Test func queryStatusNeverRecoversQuarantinedAuthorityAsOff() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let quarantined = AuthorityOwnershipObservation(state: .quarantined, lease: nil)
    let lease = RecordingEngineLease(
      observation: quarantined,
      recoveredStop: try recoveredStop(for: descriptor))
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: quarantined,
      engineLease: lease)

    #expect(await failureCode(coordinator, .queryStatus) == .quarantined)
    #expect(await lease.recoverCount() == 0)
    #expect(await lease.counters() == (begin: 0, complete: 0))
  }

  @Test func queryStatusReconcilesRestartedAuthorityOnlyAfterBothOwnersProveOff()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      recoveryStatus: .disconnected)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(state: .recovering, lease: nil))
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .recovering, lease: nil),
      engineLease: lease)

    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("exact restart reconciliation did not return global Off")
      return
    }
    #expect((await proxy.counters()).ensure == 1)
    #expect(await lease.reconcileCount() == 1)
  }

  @Test func queryStatusKeepsAuthorityRecoveringForTransitionalManagedTunnel()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      recoveryStatus: .connecting)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(state: .recovering, lease: nil))
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .recovering, lease: nil),
      engineLease: lease)

    let code = await failureCode(coordinator, .queryStatus)
    #expect(code == .cleanupUnproven)
    #expect(await lease.reconcileCount() == 1)
  }
}

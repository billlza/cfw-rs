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

// Startup recovery and preference receipts: status that fails closed while a
// receipt remains, and recovery that completes the Authority before it clears
// its journal.
extension NativeBridgeStartCommandIntegrationTests {
  @Test func firstStatusFailsClosedOnRecoveredPreferenceWriteAheadReceipt()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let cleanupEvents = NativeCleanupEventLog()
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      pendingPreferenceDescriptor: descriptor,
      cleanupEvents: cleanupEvents)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .preparing,
        lease: agreement(
          for: descriptor,
          mode: .tunnel,
          leaseState: .prepared)),
      cancelPreparedResult: true,
      cleanupEvents: cleanupEvents)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    // A read cannot project either Off or Active around a recovered write-ahead
    // receipt. Recovery belongs to the next serialized mutation boundary.
    #expect(await failureCode(coordinator, .queryStatus) == .cleanupUnproven)
    #expect(await lease.cancelPreparedCount() == 0)
    #expect(await tunnel.compensationCounts() == (compensate: 0, finish: 0))
    #expect(cleanupEvents.events.isEmpty)

    guard
      case .tunnelInstall(.ready) =
        try await coordinator.execute(.installTunnel(request.context))
    else {
      Issue.record("startup preference recovery did not unblock the exact mutation")
      return
    }
    #expect(await lease.cancelPreparedCount() == 2)
    #expect(await tunnel.compensationCounts() == (compensate: 1, finish: 1))
    #expect(await tunnel.pendingPreferenceMutationConfiguration() == nil)
    #expect(
      cleanupEvents.events == [
        "cancel-prepared",
        "cancel-prepared",
        "compensate-preferences",
        "finish-preferences",
      ])
  }

  @Test func everyExternalStatusFailsClosedWhileAPreferenceReceiptRemains()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let tunnelDescriptor = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true)
    ).descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: tunnelDescriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("initial external status did not reach proven global Off")
      return
    }
    await tunnel.injectPendingPreferenceMutation(tunnelDescriptor)

    #expect(await failureCode(coordinator, .queryStatus) == .cleanupUnproven)
    #expect((await proxy.counters()).snapshot == 1)
  }

  @Test func ownerControlledStartupRecoveryCompletesAuthorityBeforeClearingJournal()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let cleanupEvents = NativeCleanupEventLog()
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      pendingPreferenceDescriptor: descriptor,
      cleanupEvents: cleanupEvents)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .tunnel)),
      cancelPreparedResult: false,
      cleanupEvents: cleanupEvents)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    guard
      case .tunnelInstall(.ready) =
        try await coordinator.execute(.installTunnel(request.context))
    else {
      Issue.record("owner-controlled preference recovery did not finish")
      return
    }

    #expect(await lease.cancelPreparedCount() == 1)
    #expect(await lease.counters() == (begin: 2, complete: 1))
    #expect(await lease.currentState() == .off)
    #expect(await tunnel.compensationCounts() == (compensate: 1, finish: 1))
    #expect(await tunnel.pendingPreferenceMutationConfiguration() == nil)
    #expect(
      cleanupEvents.events == [
        "cancel-prepared",
        "begin-stop",
        "begin-stop",
        "compensate-preferences",
        "complete-stop",
        "finish-preferences",
      ])
  }

  @Test func startupRecoveryRetriesAfterLostAuthorityCompletionReplyWithoutRecompensating()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let cleanupEvents = NativeCleanupEventLog()
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      pendingPreferenceDescriptor: descriptor,
      cleanupEvents: cleanupEvents)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .tunnel)),
      completeFailures: 1,
      completeFailureCommits: true,
      cancelPreparedResult: false,
      cleanupEvents: cleanupEvents)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    #expect(
      await failureCode(coordinator, .installTunnel(request.context))
        == .unavailable)
    #expect(await tunnel.compensationCounts() == (compensate: 1, finish: 0))
    #expect(await tunnel.pendingPreferenceMutationConfiguration() == descriptor)
    #expect(await lease.currentState() == .off)

    guard
      case .tunnelInstall(.ready) =
        try await coordinator.execute(.installTunnel(request.context))
    else {
      Issue.record("lost Authority completion reply did not remain exactly retryable")
      return
    }
    #expect(await tunnel.compensationCounts() == (compensate: 1, finish: 1))
    #expect(await tunnel.pendingPreferenceMutationConfiguration() == nil)
    #expect(await lease.counters() == (begin: 2, complete: 2))
    #expect(
      cleanupEvents.events == [
        "cancel-prepared",
        "begin-stop",
        "begin-stop",
        "compensate-preferences",
        "complete-stop",
        "complete-stop",
        "finish-preferences",
      ])
  }
}

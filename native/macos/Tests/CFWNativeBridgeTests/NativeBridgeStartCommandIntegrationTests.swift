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

// Integration coverage for task 9.12 (Host / NativeBridge start commands): the
// serialized coordinator's `startSystemProxy` and `startTunnel` command paths are
// driven end to end through `execute(_:)` to prove:
//   - registration denial fails closed BEFORE any preference/network mutation, with
//     no runtime-byte transfer, no owner start, and no fallback to the other mode;
//   - an owner is returned Active only when the Global Authority's machine-wide
//     ownership observation agrees EXACTLY with the effective owner descriptor
//     (lease / context / digest / owner-ready / OS state); any lease disagreement
//     fails closed and never activates or falls back;
//   - a stop that cannot prove the effective OS descriptor is ambiguous, never Active.
// ProxyAgent / Packet Tunnel / Authority mutations live behind injected in-memory
// seams. Some fixtures retain the default maintainer's read-only SM metadata
// queries; the concurrency handshakes below inject their maintainer as well.
// The public command request/response contract is unchanged.
//
// This complements (and does not duplicate) `ActiveAgreementTests`, which drives the
// read-only `queryStatus` agreement matrix, and `CutoverPreflightTests`, which drives
// the preflight (never-start) path.

@Suite(.serialized)
struct NativeBridgeStartCommandIntegrationTests {
  @Test(arguments: [0, 1])
  func failedProxyPreparationAcknowledgesOnlyItsExactProvenOffAttempt(
    observationFailures: Int
  ) async throws {
    let request = try startRequest(tunnelOptions: nil, mode: .localProxy)
    let descriptor = try request.descriptor(slot: .localProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let off = AuthorityOwnershipObservation(state: .off, lease: nil)
    let lease = RecordingEngineLease(observation: off, ownershipFailures: observationFailures)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: off,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(failPreparation: true),
      engineLease: lease)
    #expect(
      await failureCode(coordinator, .startLocalProxy(request))
        == (observationFailures == 0 ? .invalidMessage : .cleanupUnproven))
    let stale = try EngineCommandContext(
      installationID: request.context.installationID, configEpoch: request.context.configEpoch,
      generation: request.context.generation + 1)
    #expect(await failureCode(coordinator, .stopLocalProxy(stale)) == .identityRejected)
    _ = try await coordinator.execute(.stopLocalProxy(request.context))
    #expect((await proxy.counters()).start == 0)
    #expect((await proxy.counters()).stop == 0)
    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("Failed preparation did not reach the proven Off state")
      return
    }
  }

  @Test func failedTunnelOwnerUsesTheSameExactExplicitStopBarrier() async throws {
    let request = try startRequest(tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      failedStartSnapshot: EngineFailure(
        code: "runtime-failed", message: "Runtime exited.", isRetryable: false))
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .tunnel))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel, observation: ownership, engineLease: lease)
    _ = try await coordinator.execute(.startTunnel(request))
    await tunnel.simulateRuntimeFailure()
    #expect(await failureCode(coordinator, .queryStatus) == .unavailable)
    _ = try await coordinator.execute(.stopTunnel(request.context))
    #expect((await tunnel.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 1))
    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("Failed Tunnel cleanup did not reach proven Off")
      return
    }
  }

  @Test(arguments: [NativeStartMode.localProxy, .systemProxy])
  func failedProxyWithoutAnExactDescriptorCannotBeStoppedByGuessing(mode: NativeStartMode)
    async throws
  {
    let request = try startRequest(tunnelOptions: nil, mode: mode)
    let descriptor = try request.descriptor(slot: mode.slot)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: mode.slot.authorityMode))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(
      mode == .localProxy ? .startLocalProxy(request) : .startSystemProxy(request))
    await proxy.simulateRuntimeFailure(omittingDescriptor: true)
    #expect(
      await failureCode(
        coordinator,
        mode == .localProxy ? .stopLocalProxy(request.context) : .stopSystemProxy(request.context))
        == .unavailable)
    #expect((await proxy.counters()).stop == 0)
    #expect(await lease.counters() == (begin: 0, complete: 0))
  }

  @Test(arguments: [NativeStartMode.localProxy, .systemProxy])
  func failedProxyOwnerCanStopExactlyWithoutEverBeingReportedActive(mode: NativeStartMode)
    async throws
  {
    let request = try startRequest(tunnelOptions: nil, mode: mode)
    let descriptor = try request.descriptor(slot: mode.slot)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: mode.slot.authorityMode))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel, observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(
      mode == .localProxy ? .startLocalProxy(request) : .startSystemProxy(request))
    await proxy.simulateRuntimeFailure()
    #expect(await failureCode(coordinator, .queryStatus) == .unavailable)
    let stale = try EngineCommandContext(
      installationID: request.context.installationID, configEpoch: request.context.configEpoch,
      generation: request.context.generation + 1)
    #expect(
      await failureCode(
        coordinator, mode == .localProxy ? .stopLocalProxy(stale) : .stopSystemProxy(stale))
        == .identityRejected)
    #expect((await proxy.counters()).stop == 0)
    #expect(await lease.counters() == (begin: 0, complete: 0))
    _ = try await coordinator.execute(
      mode == .localProxy ? .stopLocalProxy(request.context) : .stopSystemProxy(request.context))
    #expect((await proxy.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 1))
    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("Failed owner cleanup did not reach the proven Off barrier")
      return
    }
  }

  @Test func localProxyStartAndStatusRemainDistinctWithoutNetworkAuthorization() async throws {
    let request = try startRequest(tunnelOptions: nil, mode: .localProxy)
    let descriptor = try request.descriptor(slot: .localProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let preparer = RecordingSystemProxyStartPreparer()
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .localProxy))
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel, observation: ownership, systemProxyPreparer: preparer)
    guard case .runtime(let runtime) = try await coordinator.execute(.startLocalProxy(request))
    else {
      Issue.record("Local Proxy did not return its runtime")
      return
    }
    #expect(runtime.owner == .proxyAgent)
    #expect(runtime.configDigest == request.configDigest.hex)
    guard case .status(.localProxy(let observed)) = try await coordinator.execute(.queryStatus)
    else {
      Issue.record("Local Proxy was projected as another mode")
      return
    }
    #expect(observed == runtime)
    #expect(await proxy.authorizationCalls == 0)
    #expect((await tunnel.counters()).install == 0)
    #expect((await tunnel.counters()).start == 0)
    #expect(await preparer.counters() == (prepare: 1, cancel: 0))
    #expect(await proxy.authorizedContexts().first?.operation.mode == .localProxy)
    let systemRequest = try startRequest(
      tunnelOptions: nil, configuration: Data(request.configJSON.utf8))
    #expect(systemRequest.configContentDigest == request.configContentDigest)
    #expect(systemRequest.credentialAudience == request.credentialAudience)
    #expect(systemRequest.configDigest != request.configDigest)
  }

  @Test func localAndSystemProxyEntryPointsRejectEachOthersRequestsBeforeMutation() async throws {
    let local = try startRequest(tunnelOptions: nil, mode: .localProxy)
    let system = try startRequest(tunnelOptions: nil)
    let descriptor = try local.descriptor(slot: .localProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let preparer = RecordingSystemProxyStartPreparer()
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      systemProxyPreparer: preparer)
    #expect(await failureCode(coordinator, .startSystemProxy(local)) == .configurationRejected)
    #expect(await failureCode(coordinator, .startLocalProxy(system)) == .configurationRejected)
    #expect((await proxy.counters()).ensure == 0)
    #expect((await proxy.counters()).start == 0)
    #expect(await preparer.counters() == (prepare: 0, cancel: 0))
    #expect((await tunnel.counters()).install == 0)
  }

  @Test func localProxyStopRejectsWrongModeAndRetriesOnlyUnprovenAuthorityCompletion() async throws
  {
    let request = try startRequest(tunnelOptions: nil, mode: .localProxy)
    let descriptor = try request.descriptor(slot: .localProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .localProxy))
    let lease = RecordingEngineLease(observation: ownership, completeFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel, observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startLocalProxy(request))
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) != nil)
    #expect((await proxy.counters()).stop == 0)
    #expect(await lease.counters() == (begin: 0, complete: 0))
    #expect(await failureCode(coordinator, .stopLocalProxy(request.context)) == .unavailable)
    #expect((await proxy.counters()).stop == 1)
    _ = try await coordinator.execute(.stopLocalProxy(request.context))
    #expect((await proxy.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 2))
    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("Local Proxy stop did not reach proven Off")
      return
    }
  }

  @Test func localProxyWireRequiresExplicitModeAndBindsModeToTheEntryPoint() throws {
    let request = try startRequest(tunnelOptions: nil, mode: .localProxy)
    let original = NativeRequestEnvelope(command: .startLocalProxy(request))
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(original)
    #expect(try NativeBridgeProtocolCodec.decodeRequest(data) == original)
    let text = String(decoding: data, as: UTF8.self)
    for changed in [
      text.replacingOccurrences(of: "\"mode\":\"local_proxy\",", with: ""),
      text.replacingOccurrences(of: "\"mode\":\"local_proxy\"", with: "\"mode\":\"system_proxy\""),
      text.replacingOccurrences(of: "start_local_proxy", with: "start_system_proxy"),
    ] {
      #expect(changed != text)
      #expect(throws: (any Error).self) {
        try NativeBridgeProtocolCodec.decodeRequest(Data(changed.utf8))
      }
    }
    #expect(throws: NativeBridgeProtocolError.invalidCommand) {
      try request.descriptor(slot: .systemProxy)
    }
    #expect(!NativeStartMode.localProxy.admits(try TunnelNetworkOptions(ipv6Enabled: false)))
    #expect(!NativeStartMode.tunnelSystemProxy.admits(try TunnelNetworkOptions(ipv6Enabled: false)))
  }

  @Test func localProxyRejectsConfigurationThatCouldChangeSystemNetworking() throws {
    let request = try startRequest(tunnelOptions: nil, mode: .localProxy)
    for changed in [
      request.configJSON.replacingOccurrences(
        of: "\"listen\":\"127.0.0.1\"", with: "\"listen\":\"0.0.0.0\""),
      request.configJSON.replacingOccurrences(of: "\"type\":\"mixed\"", with: "\"type\":\"tun\""),
      request.configJSON.replacingOccurrences(
        of: "\"type\":\"mixed\"", with: "\"type\":\"mixed\",\"set_system_proxy\":true"),
      request.configJSON.replacingOccurrences(
        of: "\"inbounds\":[", with: "\"inbounds\":[{\"type\":\"tun\"},"),
    ] {
      #expect(throws: NativeBridgeProtocolError.invalidConfiguration) {
        try startRequest(tunnelOptions: nil, mode: .localProxy, configuration: Data(changed.utf8))
      }
    }
  }

  @Test func tunnelConsentDoesNotReadCredentialsOrStartTheOwner() async throws {
    let reference = CredentialReference(id: UUID(), kind: .trojanPassword)
    let slot = try CredentialSlot(
      reference: reference, target: .trojanPassword,
      outboundIndex: 0, jsonPointer: "/outbounds/0/password")
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true),
      credentialSlots: [slot],
      configuration: Data(#"{"outbounds":[{"type":"trojan","password":""}]}"#.utf8))
    let descriptor = try request.descriptor(slot: .tunnel)
    var material = try CredentialMaterial(entries: [
      CredentialMaterialEntry(reference: reference, secret: Data("test-secret".utf8))
    ])
    defer { material.erase() }
    let vault = StartCredentialVault(material: material)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor, blocksAuthorization: true)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil), credentialVault: vault,
      serviceMaintainer: ServiceUpgradeFixture())
    let command = NativeBridgeCommand.authorizeTunnelConfiguration(request)
    let wire = try JSONEncoder().encode(NativeRequestEnvelope(command: command))
    let decoded = try NativeBridgeProtocolCodec.decodeRequest(wire)
    #expect(decoded.command == command)
    let result = try await whileNativeFixtureBlocked(
      at: tunnel.authorizationHandshake,
      operation: { try await coordinator.execute(decoded.command) },
      body: {
        #expect(vault.resolutionCount == 0)
        #expect(await tunnel.counters().start == 0)
        #expect(await failureCode(coordinator, .startTunnel(request)) == .busy)
        #expect(vault.resolutionCount == 0)
      })
    guard case .acknowledged = result else {
      Issue.record("VPN consent did not complete")
      return
    }
    #expect(await tunnel.authorizationCalls == 1)
    #expect(await tunnel.counters().start == 0)
    #expect(vault.resolutionCount == 0)
  }

  @Test func tunnelConsentCannotMutateAnActiveAuthorityOwner() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .active, lease: agreement(for: descriptor, mode: .tunnel)))
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil), engineLease: lease)
    #expect(await failureCode(coordinator, .authorizeTunnelConfiguration(request)) == .busy)
    #expect(await tunnel.authorizationCalls == 0)
    #expect(await lease.cancelPreparedCount() == 0)
    #expect(await coordinator.pendingStartCleanup == nil)
  }

  @Test func deniedTunnelConsentPreservesItsErrorAndDoesNotResolveCredentials() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let error = AppleNetworkError.preferenceSaveFailed(
      NetworkExtensionOperationFailure(
        domain: NSPOSIXErrorDomain, code: Int(POSIXErrorCode.EPERM.rawValue),
        diagnostic: "consent denied"))
    let tunnel = StartableTunnelHost(descriptor: descriptor, authorizationError: error)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))
    let vault = StartCredentialVault()
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease, credentialVault: vault)
    #expect(
      await failureCode(coordinator, .authorizeTunnelConfiguration(request)) == .permissionDenied)
    #expect(await tunnel.counters().start == 0)
    #expect(vault.resolutionCount == 0)
    #expect(await coordinator.pendingStartCleanup == nil)
  }
}

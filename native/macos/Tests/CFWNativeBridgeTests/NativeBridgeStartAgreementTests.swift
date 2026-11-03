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

// Starts that reach Active only on the Authority's exact agreement:
// registration denial, lease disagreement, credential transfer, and a global
// Off.
extension NativeBridgeStartCommandIntegrationTests {
  @Test func systemProxyRegistrationDenialFailsClosedBeforeAnyMutation() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor, registrationError: .registrationRequiresApproval)
    let preparer = RecordingSystemProxyStartPreparer()
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      systemProxyPreparer: preparer)

    let code = await failureCode(coordinator, .startSystemProxy(request))
    let proxyCounts = await proxy.counters()
    #expect(code == .proxyAgentApprovalRequired)
    #expect(proxyCounts.ensure == 1)
    #expect(await preparer.counters() == (prepare: 0, cancel: 0))
    // Registration denial fails closed before Authority preparation, runtime-byte
    // transfer, or owner start, and never falls back to the Tunnel owner.
    #expect(proxyCounts.start == 0)
    #expect(await proxy.transferredConfigurationDigests().isEmpty)
    let tunnelCounts = await tunnel.counters()
    #expect(tunnelCounts.install == 0)
    #expect(tunnelCounts.start == 0)
  }

  @Test func systemProxyReachesActiveOnlyOnExactAuthorityAgreement() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let preparer = RecordingSystemProxyStartPreparer()
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active, lease: agreement(for: descriptor, mode: .systemProxy)),
      systemProxyPreparer: preparer)

    guard case .runtime(let runtime) = try await coordinator.execute(.startSystemProxy(request))
    else {
      Issue.record("exact Authority agreement did not return a proxy runtime")
      return
    }
    #expect(runtime.owner == .proxyAgent)
    #expect(runtime.context == request.context)
    #expect(runtime.configDigest == request.configDigest.hex)
    #expect(runtime.ready)

    // The Authority-bound owner start is ordered after registration and carries
    // the exact in-memory runtime bytes; the Tunnel owner is never touched.
    let proxyCounts = await proxy.counters()
    #expect(proxyCounts.ensure == 2)
    #expect(proxyCounts.start == 1)
    #expect(await preparer.counters() == (prepare: 1, cancel: 0))
    let contexts = await proxy.authorizedContexts()
    #expect(contexts.count == 1)
    #expect(contexts.first?.operation.root.installationID.rawValue == descriptor.installationID)
    #expect(contexts.first?.operation.configSHA256 == descriptor.sha256)
    #expect(contexts.first?.operation.identitySHA256 == descriptor.identitySHA256)
    #expect(await proxy.transferredConfigurationDigests() == [descriptor.sha256.hex])
    let tunnelCounts = await tunnel.counters()
    #expect(tunnelCounts.start == 0)
  }

  @Test func systemProxyStartFailsClosedWhenAuthorityLeaseDisagrees() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let preparer = RecordingSystemProxyStartPreparer()
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    // The lease binds another configuration than the effective owner
    // descriptor, at the generation the Host prepared: activation is refused
    // and the already-started owner is rolled back to Off.
    let disagreeing = AuthorityOwnershipObservation(
      state: .active,
      lease: AuthorityLeaseAgreement(
        installationID: descriptor.installationID, epoch: descriptor.epoch,
        generation: descriptor.generation, ownerUID: 501, mode: .systemProxy,
        configSHA256: try SHA256Digest(hex: String(repeating: "e", count: 64)),
        identitySHA256: descriptor.identitySHA256, leaseState: .active))
    let lease = RecordingEngineLease(observation: disagreeing)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel, observation: disagreeing,
      systemProxyPreparer: preparer,
      engineLease: lease)

    let code = await failureCode(coordinator, .startSystemProxy(request))
    let proxyCounts = await proxy.counters()
    #expect(code == .identityRejected)
    #expect(proxyCounts.start == 1)
    #expect(proxyCounts.stop == 1)
    #expect(await preparer.counters() == (prepare: 1, cancel: 0))
    #expect(await lease.counters() == (begin: 1, complete: 1))
    // The disagreement never falls back to the Tunnel owner.
    let tunnelCounts = await tunnel.counters()
    #expect(tunnelCounts.start == 0)
  }

  @Test(arguments: [false, true])
  func tunnelTransfersRealCredentialFormatInDescriptorOrder(sharedReference: Bool) async throws {
    let first = CredentialReference(
      id: try #require(UUID(uuidString: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")),
      kind: .trojanPassword)
    let second =
      sharedReference
      ? first
      : CredentialReference(
        id: try #require(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
        kind: .trojanPassword)
    let slots = try [first, second].enumerated().map { index, reference in
      try CredentialSlot(
        reference: reference, target: .trojanPassword,
        outboundIndex: UInt16(index), jsonPointer: "/outbounds/\(index)/password")
    }
    let template = Data(
      #"{"outbounds":[{"type":"trojan","password":""},{"type":"trojan","password":""}]}"#.utf8)
    let expected = Data(
      (sharedReference
        ? #"{"outbounds":[{"type":"trojan","password":"first-test-secret"},{"type":"trojan","password":"first-test-secret"}]}"#
        : #"{"outbounds":[{"type":"trojan","password":"first-test-secret"},{"type":"trojan","password":"second-test-secret"}]}"#)
        .utf8)
    var entries = [
      try CredentialMaterialEntry(reference: first, secret: Data("first-test-secret".utf8))
    ]
    if !sharedReference {
      entries.append(
        try CredentialMaterialEntry(reference: second, secret: Data("second-test-secret".utf8)))
    }
    var material = try CredentialMaterial(entries: entries)
    defer { material.erase() }
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true),
      credentialSlots: slots, configuration: template)
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor, expectedInjectedConfiguration: expected)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .tunnel)),
      credentialVault: StartCredentialVault(material: material))
    guard case .runtime(let runtime) = try await coordinator.execute(.startTunnel(request)) else {
      Issue.record("credential-bearing Tunnel did not reach runtime")
      return
    }
    #expect(runtime.ready)
    #expect(await tunnel.counters().start == 1)
    #expect(await proxy.counters().start == 0)
  }

  @Test func tunnelReachesActiveOnlyOnExactAuthorityAgreement() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active, lease: agreement(for: descriptor, mode: .tunnel)))

    guard case .runtime(let runtime) = try await coordinator.execute(.startTunnel(request)) else {
      Issue.record("exact Authority agreement did not return a tunnel runtime")
      return
    }
    #expect(runtime.owner == .packetTunnelSystemExtension)
    #expect(runtime.context == request.context)
    #expect(runtime.configDigest == request.configDigest.hex)
    #expect(runtime.ready)

    let tunnelCounts = await tunnel.counters()
    #expect(tunnelCounts.start == 1)
    // The Tunnel start path never starts the System Proxy owner as a fallback.
    let proxyCounts = await proxy.counters()
    #expect(proxyCounts.start == 0)
  }

  @Test func tunnelStartFailsClosedWhenAuthorityProvesGlobalOff() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))
    // The provider reports active, but the Authority proves global Off: an
    // unresolved ownership ambiguity that must fail closed as Quarantined.
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    let code = await failureCode(coordinator, .startTunnel(request))
    // Provider active while the Authority proves global Off is an ambiguity that
    // fails closed as Quarantined. It neither activates nor falls back.
    #expect(code == .quarantined)
    #expect((await tunnel.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 1))
    let proxyCounts = await proxy.counters()
    #expect(proxyCounts.start == 0)
  }
}

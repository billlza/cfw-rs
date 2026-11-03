import CFWCredentialTransport
import CFWCredentialVault
import Foundation
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Shared by the active agreement and maintenance tests: installation, epoch,
// generation and digest constants, the descriptor and coordinator builders,
// and the status and maintenance error codes.
let fixtureInstallationID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
let otherInstallationID = UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
private let epoch: UInt64 = 4
let generation: UInt64 = 9

func digest(_ byte: String) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(hex: String(repeating: byte, count: 32))
}

func descriptor(
  slot: ConfigurationSlot,
  epoch: UInt64 = epoch,
  generation: UInt64 = generation,
  installationID: UUID = fixtureInstallationID,
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

func coordinator(
  proxy: EngineSnapshot,
  tunnel: EngineSnapshot,
  observation: AuthorityOwnershipObservation,
  onAuthorityObservation: @escaping @Sendable () -> Void = {},
  pendingPreference: ConfigurationDescriptor? = nil,
  installed40019Proxy: (any Installed40019ProxySnapshotting)? = nil,
  serviceMaintainer: any CurrentAppServiceMaintaining = StubServiceMaintainer(),
  serviceRuntimeObserver: any CurrentAppServiceRuntimeObserving =
    StubServiceRuntimeObserver(),
  systemProxySwitchObserver: any CurrentSystemProxySwitchObserving =
    StubSystemProxySwitchObserver(observed: .disabled),
  hostOperationLease: any NativeHostOperationLeaseAcquiring =
    AvailableNativeHostOperationLease()
) -> NativeBridgeCoordinator {
  let proxyTransport = StubProxyAgent(proxy)
  return NativeBridgeCoordinator(
    proxy: proxyTransport,
    installed40019Proxy: installed40019Proxy ?? proxyTransport,
    systemProxyPreparer: UnusedSystemProxyStartPreparer(),
    tunnel: StubTunnelHost(tunnel, pendingPreference: pendingPreference),
    engineLease: StubLease(
      observation: observation,
      onObservation: onAuthorityObservation
    ),
    installed40019Authority: StubInstalled40019Authority(
      observation: observation,
      onObservation: onAuthorityObservation
    ),
    credentialVault: StubCredentialVault(),
    hostOperationLease: hostOperationLease,
    serviceMaintainer: serviceMaintainer,
    serviceRuntimeObserver: serviceRuntimeObserver,
    systemProxySwitchObserver: systemProxySwitchObserver,
    serviceBuildObserver: FixedCurrentServiceBuildObserver())
}

func statusErrorCode(
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

func maintenanceErrorCode(
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

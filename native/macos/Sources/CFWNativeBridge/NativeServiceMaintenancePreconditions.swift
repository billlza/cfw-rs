import CFWAppleNetwork
import CFWSharedProtocol
import Foundation

extension NativeBridgeCoordinator {
  func requireOrphanedUpgradeIdentities() throws {
    let inspection: CurrentAppServiceBuildInspection
    do {
      inspection = try serviceBuildObserver.inspect()
      try inspection.proxy.requireNonConflictingVersion()
      try inspection.authority.requireNonConflictingVersion()
    } catch {
      throw NativeBridgeExecutionError.failure(
        .identityRejected, "Orphaned service identities changed before retirement.")
    }
    guard inspection.proxy.registration == .enabled, inspection.proxy.runningCode != nil,
      inspection.authority.registration == .notRegistered, inspection.authority.runningCode == nil
    else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven, "Orphaned service registrations changed before retirement.")
    }
  }

  func requireOrphanedServiceRetirementBoundary() async throws {
    try await requireMaintenanceTunnelOff()
    let before = servicePair()
    let authorityProcess = serviceRuntimeObserver.status(of: .globalAuthority)
    try requireUnchangedServicePair(before)
    switch authorityProcess {
    case .absent:
      break
    case .present:
      throw NativeBridgeExecutionError.failure(
        .busy, "A running Authority cannot be retired as orphaned.")
    case .unobservable:
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven, "Authority process absence cannot be observed.")
    }
    switch systemProxySwitchObserver.status() {
    case .disabled:
      return
    case .enabled:
      throw NativeBridgeExecutionError.failure(
        .busy, "System proxy switches must be disabled before orphaned service retirement.")
    case .unobservable:
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven, "System proxy settings cannot be observed for service retirement.")
    }
  }

  func requireAuthorityReadyForServiceRegistration() async throws {
    let observation = try await engineLease.authorityOwnership()
    guard observation.lease == nil else {
      throw NativeBridgeExecutionError.failure(
        .busy, "An engine lease blocks service registration.")
    }
    switch observation.state {
    case .off, .recovering:
      return
    default:
      try Self.requireGlobalOff(observation)
    }
  }

  /// Proves every available owner Off without implicitly registering a service.
  /// A registered endpoint must answer with a stable snapshot. An unregistered
  /// endpoint must instead have a stable, exact process-absence observation.
  func requireCurrentMaintenanceOwnersOff(
    for pair: (proxy: CurrentAppServiceStatus, authority: CurrentAppServiceStatus),
    requireAuthorityProof: Bool
  ) async throws {
    try await requireMaintenanceTunnelOff()

    switch pair.proxy {
    case .enabled:
      let proxySnapshot = try Self.requireObservation(
        await Self.observe { try await self.proxy.snapshot() },
        component: "ProxyAgent"
      )
      guard Self.isStableOff(proxySnapshot) else {
        throw NativeBridgeExecutionError.failure(
          .busy, "ProxyAgent is not at the stable Off barrier."
        )
      }
    case .notRegistered:
      try requireServiceProcessAbsent(.proxyAgent)
    case .requiresApproval, .notFound, .unknown:
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "ProxyAgent registration state cannot prove the maintenance Off barrier."
      )
    }

    if requireAuthorityProof {
      guard pair.authority == .enabled else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "GlobalAuthority must be registered before its Off state can be observed."
        )
      }
      do {
        try Self.requireGlobalOff(try await engineLease.authorityOwnership())
      } catch {
        throw Self.map(error)
      }
    } else {
      guard pair.authority == .notRegistered else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "GlobalAuthority registration state differs from the absence boundary."
        )
      }
      try requireServiceProcessAbsent(.globalAuthority)
    }
    try requireUnchangedServicePair(pair)
  }

  func requireInstalled40019MaintenanceOwnersOff(
    for pair: (proxy: CurrentAppServiceStatus, authority: CurrentAppServiceStatus),
    requireAuthorityProof: Bool
  ) async throws {
    try await requireMaintenanceTunnelOff()

    switch pair.proxy {
    case .enabled:
      let proxySnapshot = try Self.requireObservation(
        await Self.observe {
          try await self.installed40019Proxy.snapshotInstalled40019ForMigration()
        },
        component: "installed 40019 ProxyAgent"
      )
      guard Self.isStableOff(proxySnapshot) else {
        throw NativeBridgeExecutionError.failure(
          .busy, "Installed 40019 ProxyAgent is not at the stable Off barrier."
        )
      }
    case .notRegistered:
      try requireServiceProcessAbsent(.proxyAgent)
    case .requiresApproval, .notFound, .unknown:
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "Installed 40019 ProxyAgent registration cannot prove the Off barrier."
      )
    }

    if requireAuthorityProof {
      guard pair.authority == .enabled else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Installed 40019 GlobalAuthority must remain registered for Off proof."
        )
      }
      do {
        try await installed40019Authority.proveOff()
      } catch {
        throw Self.map(error)
      }
    } else {
      guard pair.authority == .notRegistered else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Installed 40019 GlobalAuthority differs from the absence boundary."
        )
      }
      try requireServiceProcessAbsent(.globalAuthority)
    }
    try requireUnchangedServicePair(pair)
  }

  func requireMaintenanceTunnelOff() async throws {
    do {
      if try await tunnel.pendingPreferenceMutationConfiguration() != nil {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "A durable Tunnel preference mutation blocks service maintenance."
        )
      }
    } catch {
      throw Self.map(error)
    }

    let tunnelSnapshot = try Self.requireObservation(
      await Self.observe { try await self.tunnel.snapshot() },
      component: "Packet Tunnel"
    )
    guard Self.isStableOff(tunnelSnapshot) else {
      throw NativeBridgeExecutionError.failure(
        .busy, "Packet Tunnel is not at the stable Off barrier."
      )
    }
  }

  private func requireUnchangedServicePair(
    _ expected: (proxy: CurrentAppServiceStatus, authority: CurrentAppServiceStatus)
  ) throws {
    let actual = servicePair()
    guard actual.proxy == expected.proxy, actual.authority == expected.authority else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "A current service registration changed during maintenance Off proof."
      )
    }
  }

  func requireServiceProcessAbsent(_ service: CurrentAppService) throws {
    switch try serviceProcessStatusWhileUnregistered(service) {
    case .absent:
      return
    case .present:
      throw NativeBridgeExecutionError.failure(
        .busy, "A current service process is still present."
      )
    case .unobservable:
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven, "A current service process absence could not be proven."
      )
    }
  }

  private func serviceProcessStatusWhileUnregistered(
    _ service: CurrentAppService
  ) throws -> CurrentAppServiceRuntimeStatus {
    guard serviceMaintainer.status(of: service) == .notRegistered else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "A current service registration changed before process absence observation."
      )
    }
    let processStatus = serviceRuntimeObserver.status(of: service)
    guard serviceMaintainer.status(of: service) == .notRegistered else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "A current service registration changed during process absence observation."
      )
    }
    return processStatus
  }

  func waitForServiceProcessAbsence(
    _ service: CurrentAppService
  ) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(5))
    while true {
      switch try serviceProcessStatusWhileUnregistered(service) {
      case .absent:
        return
      case .unobservable:
        try requireServiceProcessAbsent(service)
      case .present:
        if clock.now >= deadline {
          try requireServiceProcessAbsent(service)
        }
        try await Task.sleep(for: .milliseconds(100))
      }
    }
  }
}

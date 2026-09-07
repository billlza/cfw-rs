import CFWAppleNetwork
import CFWSharedProtocol
import Foundation

extension NativeBridgeCoordinator {
  func maintainCurrentServices(
    _ action: NativeServiceMaintenanceAction
  ) async throws -> NativeServiceMaintenanceResult {
    let before = servicePair()
    switch action {
    case .status:
      return maintenanceResult(action: action, engineStatus: nil)
    case .proveOff:
      try requirePair(
        before,
        proxy: [.enabled],
        authority: [.enabled],
        operation: "Off proof"
      )
      try await requireCurrentMaintenanceOwnersOff(
        for: before, requireAuthorityProof: true)
    case .proveInstalled40019Off:
      try requirePair(
        before,
        proxy: [.enabled],
        authority: [.enabled],
        operation: "installed 40019 Off proof"
      )
      try await requireInstalled40019MaintenanceOwnersOff(
        for: before, requireAuthorityProof: true)
    case .unregisterProxyAgent:
      try requirePair(
        before,
        proxy: [.enabled, .notRegistered],
        authority: [.enabled],
        operation: "ProxyAgent unregister"
      )
      try await requireCurrentMaintenanceOwnersOff(
        for: before, requireAuthorityProof: true)
      if before.proxy == .enabled {
        try perform(.unregister, on: .proxyAgent)
      }
      try await waitForServiceProcessAbsence(.proxyAgent)
      try await requireCurrentMaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: true)
    case .unregisterInstalled40019ProxyAgent:
      try requirePair(
        before,
        proxy: [.enabled, .notRegistered],
        authority: [.enabled],
        operation: "installed 40019 ProxyAgent unregister"
      )
      try await requireInstalled40019MaintenanceOwnersOff(
        for: before, requireAuthorityProof: true)
      if before.proxy == .enabled {
        try perform(.unregister, on: .proxyAgent)
      }
      try await waitForServiceProcessAbsence(.proxyAgent)
      try await requireInstalled40019MaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: true)
    case .unregisterGlobalAuthority:
      try requirePair(
        before,
        proxy: [.notRegistered],
        authority: [.enabled, .notRegistered],
        operation: "GlobalAuthority unregister"
      )
      if before.authority == .notRegistered {
        // A crashed caller may have lost the successful unregister receipt.
        // Re-establish an observable Authority boundary explicitly, prove its
        // durable state Off, and then return it to NotRegistered. This avoids
        // the hidden auto-registration side effect of querying the gated
        // Authority client while preserving a self-contained retry proof.
        try await requireCurrentMaintenanceOwnersOff(
          for: before, requireAuthorityProof: false)
        try perform(.register, on: .globalAuthority)
      }
      try await requireCurrentMaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: true)
      try perform(.unregister, on: .globalAuthority)
      try await waitForServiceProcessAbsence(.globalAuthority)
      try await requireCurrentMaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: false)
    case .unregisterInstalled40019GlobalAuthority:
      try requirePair(
        before,
        proxy: [.notRegistered],
        authority: [.enabled],
        operation: "installed 40019 GlobalAuthority unregister"
      )
      try await requireInstalled40019MaintenanceOwnersOff(
        for: before, requireAuthorityProof: true)
      try perform(.unregister, on: .globalAuthority)
      try await waitForServiceProcessAbsence(.globalAuthority)
      try await requireInstalled40019MaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: false)
    case .recoverInstalled40019GlobalAuthority:
      try requirePair(
        before,
        proxy: [.notRegistered],
        authority: [.enabled, .notRegistered],
        operation: "installed 40019 GlobalAuthority recovery"
      )
      if before.authority == .notRegistered {
        try await requireCurrentMaintenanceOwnersOff(
          for: before, requireAuthorityProof: false)
        try perform(.register, on: .globalAuthority)
      }
      try await requireCurrentMaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: true)
      try perform(.unregister, on: .globalAuthority)
      try await waitForServiceProcessAbsence(.globalAuthority)
      try await requireCurrentMaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: false)
    case .registerGlobalAuthority:
      try requirePair(
        before,
        proxy: [.notRegistered],
        authority: [.notRegistered, .enabled],
        operation: "GlobalAuthority register"
      )
      if before.authority == .notRegistered {
        try await requireCurrentMaintenanceOwnersOff(
          for: before, requireAuthorityProof: false)
        try perform(.register, on: .globalAuthority)
      }
      try await requireCurrentMaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: true)
    case .registerProxyAgent:
      try requirePair(
        before,
        proxy: [.notRegistered, .enabled],
        authority: [.enabled],
        operation: "ProxyAgent register"
      )
      try await requireCurrentMaintenanceOwnersOff(
        for: before, requireAuthorityProof: true)
      if before.proxy == .notRegistered {
        try perform(.register, on: .proxyAgent)
      }
      try await requireCurrentMaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: true)
    }
    let result = maintenanceResult(action: action, engineStatus: .off)
    try requireMaintenancePostcondition(result)
    return result
  }

  /// Proves every available owner Off without implicitly registering a service.
  /// A registered endpoint must answer with a stable snapshot. An unregistered
  /// endpoint must instead have a stable, exact process-absence observation.
  private func requireCurrentMaintenanceOwnersOff(
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

  private func requireInstalled40019MaintenanceOwnersOff(
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

  private func requireMaintenanceTunnelOff() async throws {
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

  private func requireServiceProcessAbsent(_ service: CurrentAppService) throws {
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

  private func waitForServiceProcessAbsence(
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

  private func servicePair() -> (
    proxy: CurrentAppServiceStatus, authority: CurrentAppServiceStatus
  ) {
    (
      proxy: serviceMaintainer.status(of: .proxyAgent),
      authority: serviceMaintainer.status(of: .globalAuthority)
    )
  }

  private func perform(
    _ mutation: CurrentAppServiceMutation,
    on service: CurrentAppService
  ) throws {
    do {
      _ = try serviceMaintainer.perform(mutation, on: service)
    } catch let error as CurrentAppServiceMaintenanceError {
      switch error {
      case .approvalRequired:
        throw NativeBridgeExecutionError.failure(
          .approvalDenied, "Service maintenance requires operating-system approval.")
      case .serviceNotFound:
        throw NativeBridgeExecutionError.failure(
          .unavailable, "A fixed service descriptor is missing from the application bundle.")
      case .statusUnknown:
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven, "A fixed service registration status is unknown.")
      case .mutationFailed, .postconditionFailed:
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven, "A fixed service mutation did not prove its postcondition.")
      }
    } catch {
      throw NativeBridgeExecutionError.failure(
        .internal, "A fixed service mutation failed at its native boundary.")
    }
  }

  private func requirePair(
    _ pair: (proxy: CurrentAppServiceStatus, authority: CurrentAppServiceStatus),
    proxy allowedProxy: Set<CurrentAppServiceStatus>,
    authority allowedAuthority: Set<CurrentAppServiceStatus>,
    operation: String
  ) throws {
    guard allowedProxy.contains(pair.proxy), allowedAuthority.contains(pair.authority) else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "\(operation) service ordering precondition is not satisfied."
      )
    }
  }

  private func maintenanceResult(
    action: NativeServiceMaintenanceAction,
    engineStatus: NativeServiceEngineStatus?
  ) -> NativeServiceMaintenanceResult {
    let pair = servicePair()
    return NativeServiceMaintenanceResult(
      action: action,
      engineStatus: engineStatus,
      globalAuthority: nativeStatus(pair.authority),
      offProofProfile: offProofProfile(for: action),
      proxyAgent: nativeStatus(pair.proxy)
    )
  }

  private func requireMaintenancePostcondition(
    _ result: NativeServiceMaintenanceResult
  ) throws {
    let valid: Bool =
      switch result.action {
      case .status:
        result.engineStatus == nil && result.offProofProfile == nil
      case .proveOff:
        result.engineStatus == .off
          && result.offProofProfile == .currentEngineV6AuthorityV11
          && result.proxyAgent == .enabled
          && result.globalAuthority == .enabled
      case .proveInstalled40019Off:
        result.engineStatus == .off
          && result.offProofProfile == .installed40019EngineV5AuthorityV10
          && result.proxyAgent == .enabled
          && result.globalAuthority == .enabled
      case .unregisterProxyAgent:
        result.engineStatus == .off
          && result.offProofProfile == .currentEngineV6AuthorityV11
          && result.proxyAgent == .notRegistered
          && result.globalAuthority == .enabled
      case .unregisterInstalled40019ProxyAgent:
        result.engineStatus == .off
          && result.offProofProfile == .installed40019EngineV5AuthorityV10
          && result.proxyAgent == .notRegistered
          && result.globalAuthority == .enabled
      case .unregisterGlobalAuthority:
        result.engineStatus == .off
          && result.offProofProfile == .currentEngineV6AuthorityV11
          && result.proxyAgent == .notRegistered
          && result.globalAuthority == .notRegistered
      case .unregisterInstalled40019GlobalAuthority:
        result.engineStatus == .off
          && result.offProofProfile == .installed40019EngineV5AuthorityV10
          && result.proxyAgent == .notRegistered
          && result.globalAuthority == .notRegistered
      case .recoverInstalled40019GlobalAuthority:
        result.engineStatus == .off
          && result.offProofProfile == .installed40019RecoveryCurrentAuthorityV11
          && result.proxyAgent == .notRegistered
          && result.globalAuthority == .notRegistered
      case .registerGlobalAuthority:
        result.engineStatus == .off
          && result.offProofProfile == .currentEngineV6AuthorityV11
          && result.proxyAgent == .notRegistered
          && result.globalAuthority == .enabled
      case .registerProxyAgent:
        result.engineStatus == .off
          && result.offProofProfile == .currentEngineV6AuthorityV11
          && result.proxyAgent == .enabled
          && result.globalAuthority == .enabled
      }
    guard valid else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven, "Service maintenance postcondition was not proven."
      )
    }
  }

  private func offProofProfile(
    for action: NativeServiceMaintenanceAction
  ) -> NativeServiceOffProofProfile? {
    switch action {
    case .status:
      nil
    case .proveInstalled40019Off, .unregisterInstalled40019ProxyAgent,
      .unregisterInstalled40019GlobalAuthority:
      .installed40019EngineV5AuthorityV10
    case .recoverInstalled40019GlobalAuthority:
      .installed40019RecoveryCurrentAuthorityV11
    case .proveOff, .unregisterProxyAgent, .unregisterGlobalAuthority,
      .registerGlobalAuthority, .registerProxyAgent:
      .currentEngineV6AuthorityV11
    }
  }

  private func nativeStatus(
    _ status: CurrentAppServiceStatus
  ) -> NativeServiceRegistrationStatus {
    switch status {
    case .enabled: .enabled
    case .requiresApproval: .requiresApproval
    case .notRegistered: .notRegistered
    case .notFound: .notFound
    case .unknown: .unknown
    }
  }
}

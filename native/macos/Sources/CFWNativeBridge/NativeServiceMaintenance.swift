import CFWAppleNetwork
import CFWSharedProtocol
import Foundation
import OSLog

extension NativeBridgeCoordinator {
  private static let maintenanceLog = Logger(
    subsystem: "com.bill.clashformac", category: "service-maintenance")
  func maintainCurrentServices(
    _ action: NativeServiceMaintenanceAction, authorityWasUnregistered: Bool = false
  ) async throws -> NativeServiceMaintenanceResult {
    let before = servicePair()
    switch action {
    case .status:
      return maintenanceResult(action: action, engineStatus: nil)
    case .retireOrphanedServices:
      return try await retireOrphanedServices()
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
        try await perform(.unregister, on: .proxyAgent)
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
        try await perform(.unregister, on: .proxyAgent)
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
        try await perform(.register, on: .globalAuthority)
      }
      try await requireCurrentMaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: true)
      try await perform(.unregister, on: .globalAuthority)
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
      try await perform(.unregister, on: .globalAuthority)
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
        try await perform(.register, on: .globalAuthority)
      }
      try await requireCurrentMaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: true)
      try await perform(.unregister, on: .globalAuthority)
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
        try await perform(
          .register, on: .globalAuthority,
          retryAuthorityRegistrationFrom: authorityWasUnregistered ? before : nil)
      }
      try await requireMaintenanceTunnelOff()
      try requireServiceProcessAbsent(.proxyAgent)
      try await requireAuthorityReadyForServiceRegistration()
      let result = maintenanceResult(action: action, engineStatus: nil)
      try requireMaintenancePostcondition(result)
      return result
    case .registerProxyAgent:
      try requirePair(
        before,
        proxy: [.notRegistered, .enabled],
        authority: [.enabled],
        operation: "ProxyAgent register"
      )
      try await requireMaintenanceTunnelOff()
      try await requireAuthorityReadyForServiceRegistration()
      if before.proxy == .notRegistered {
        try requireServiceProcessAbsent(.proxyAgent)
        try await perform(.register, on: .proxyAgent)
      }
      // A restarted Authority cannot prove Off until the Agent has recovered
      // its ownership journal. Registering the observer starts no data plane;
      // the normal query then verifies both owners and reconciles the Authority.
      guard case .off = try await queryStatus() else {
        throw NativeBridgeExecutionError.failure(
          .busy, "A native owner is active during service registration.")
      }
      try await requireCurrentMaintenanceOwnersOff(
        for: servicePair(), requireAuthorityProof: true)
    }
    let result = maintenanceResult(action: action, engineStatus: .off)
    try requireMaintenancePostcondition(result)
    return result
  }

  func retireOrphanedServicesForUpgrade() async throws -> NativeServiceMaintenanceResult {
    try Task.checkCancellation()
    try requirePair(
      servicePair(), proxy: [.enabled], authority: [.notRegistered],
      operation: "Automatic orphaned service retirement")
    return try await retireOrphanedServices(requireStableProxyOff: true)
  }

  private func retireOrphanedServices(
    requireStableProxyOff: Bool = false
  ) async throws -> NativeServiceMaintenanceResult {
    try requirePair(
      servicePair(), proxy: [.enabled, .notRegistered], authority: [.enabled, .notRegistered],
      operation: "Orphaned service retirement")
    try await requireOrphanedServiceRetirementBoundary()
    if requireStableProxyOff {
      try Task.checkCancellation()
      try requirePair(
        servicePair(), proxy: [.enabled], authority: [.notRegistered],
        operation: "Automatic orphaned Proxy observation")
    }
    if requireStableProxyOff || servicePair().proxy == .enabled {
      let observation = await Self.observe { try await self.proxy.snapshot() }
      if requireStableProxyOff { try Task.checkCancellation() }
      let snapshot = try Self.requireObservation(observation, component: "ProxyAgent")
      guard
        Self.isStableOff(snapshot)
          || (!requireStableProxyOff
            && (snapshot.mode == .localProxy || snapshot.mode == .systemProxy)
            && snapshot.state.kind == .failed)
      else {
        throw NativeBridgeExecutionError.failure(.busy, "An active ProxyAgent cannot be retired.")
      }
      try await requireOrphanedServiceRetirementBoundary()
      if requireStableProxyOff {
        // The boundary above awaits the Tunnel. Re-observe the Proxy afterwards;
        // an Off -> failed/active transition must not inherit manual recovery's
        // permission to retire a failed owner. Recheck trusted identities and
        // the exact mixed pair immediately before the unregister mutation.
        try Task.checkCancellation()
        let fresh = try Self.requireObservation(
          await Self.observe { try await self.proxy.snapshot() }, component: "ProxyAgent")
        try Task.checkCancellation()
        guard Self.isStableOff(fresh) else {
          throw NativeBridgeExecutionError.failure(
            .busy, "Automatic service retirement requires a stable Off ProxyAgent.")
        }
        try requireOrphanedUpgradeIdentities()
      }
      try await perform(.unregister, on: .proxyAgent)
    }
    try await waitForServiceProcessAbsence(.proxyAgent)
    if requireStableProxyOff { try requireAutomaticallyRetiredPair() }
    try await requireOrphanedServiceRetirementBoundary()
    if requireStableProxyOff { try requireAutomaticallyRetiredPair() }
    // Automatic recovery only owned the orphaned Proxy mutation. A newly
    // registered Authority is a state change, never permission to retire it.
    if !requireStableProxyOff && servicePair().authority == .enabled {
      try await perform(.unregister, on: .globalAuthority)
    }
    try await waitForServiceProcessAbsence(.globalAuthority)
    if requireStableProxyOff { try requireAutomaticallyRetiredPair() }
    try requireServiceProcessAbsent(.proxyAgent)
    try await requireOrphanedServiceRetirementBoundary()
    if requireStableProxyOff { try requireAutomaticallyRetiredPair() }
    // No Off attestation: the journals remain for the replacement's recovery.
    let result = maintenanceResult(action: .retireOrphanedServices, engineStatus: nil)
    try requireMaintenancePostcondition(result)
    return result
  }

  private func requireAutomaticallyRetiredPair() throws {
    try Task.checkCancellation()
    try requirePair(
      servicePair(), proxy: [.notRegistered], authority: [.notRegistered],
      operation: "Automatic orphaned service retirement completion")
  }

  func servicePair() -> (
    proxy: CurrentAppServiceStatus, authority: CurrentAppServiceStatus
  ) {
    (
      proxy: serviceMaintainer.status(of: .proxyAgent),
      authority: serviceMaintainer.status(of: .globalAuthority)
    )
  }

  private func perform(
    _ mutation: CurrentAppServiceMutation,
    on service: CurrentAppService,
    retryAuthorityRegistrationFrom pair: (
      proxy: CurrentAppServiceStatus, authority: CurrentAppServiceStatus
    )? = nil
  ) async throws {
    do {
      do {
        _ = try await serviceMaintainer.perform(mutation, on: service)
      } catch CurrentAppServiceMaintenanceError.registrationOperationNotPermitted(.globalAuthority)
        where pair != nil
      {
        // On an installed upgrade the OS can still refuse the first register
        // after unregister has completed. Keep the same Host operation lease
        // and prove that both jobs and the Tunnel are still Off before retrying.
        Self.maintenanceLog.notice(
          "GlobalAuthority register was refused after unregister. Rechecking Off before one retry.")
        try await Task.sleep(for: .seconds(4))
        if let pair {
          try await requireCurrentMaintenanceOwnersOff(for: pair, requireAuthorityProof: false)
        }
        _ = try await serviceMaintainer.perform(mutation, on: service)
      }
      try Task.checkCancellation()
    } catch let error as CurrentAppServiceMaintenanceError {
      Self.maintenanceLog.error(
        "Service maintenance failed: service=\(service.rawValue) mutation=\(mutation.rawValue) cause=\(String(describing: error), privacy: .public)"
      )
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
      case .mutationFailed, .registrationOperationNotPermitted, .postconditionFailed:
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven, "A fixed service mutation did not prove its postcondition.")
      case .unregistrationPending:
        throw NativeBridgeExecutionError.failure(
          .busy, "The previous service unregistration has not completed.")
      case .unregistrationTimedOut:
        throw NativeBridgeExecutionError.failure(
          .timeout, "Service unregistration did not complete before its bounded deadline.")
      }
    } catch is CancellationError {
      Self.maintenanceLog.notice(
        "Service maintenance wait cancelled: service=\(service.rawValue) mutation=\(mutation.rawValue)"
      )
      throw CancellationError()
    } catch let error as NativeBridgeExecutionError {
      throw error
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
      case .retireOrphanedServices:
        result.engineStatus == nil && result.offProofProfile == nil
          && result.proxyAgent == .notRegistered && result.globalAuthority == .notRegistered
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
        result.engineStatus == nil
          && result.offProofProfile == nil
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
    case .status, .registerGlobalAuthority, .retireOrphanedServices:
      nil
    case .proveInstalled40019Off, .unregisterInstalled40019ProxyAgent,
      .unregisterInstalled40019GlobalAuthority:
      .installed40019EngineV5AuthorityV10
    case .recoverInstalled40019GlobalAuthority:
      .installed40019RecoveryCurrentAuthorityV11
    case .proveOff, .unregisterProxyAgent, .unregisterGlobalAuthority,
      .registerProxyAgent:
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

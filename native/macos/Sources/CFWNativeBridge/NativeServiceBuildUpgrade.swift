import CFWAppleNetwork
import CFWSharedProtocol
import Foundation
import OSLog

struct ServiceBuildRegistrationCheckpoint: Equatable {
  let proxy: CurrentAppServiceStatus
  let authority: CurrentAppServiceStatus
}

struct ServiceBuildHandoffFailure: Error {
  let failure: NativeBridgeExecutionError
}

extension NativeBridgeCoordinator {
  private static let serviceUpgradeLog = Logger(
    subsystem: "com.bill.clashformac", category: "service-upgrade")

  func serviceBuildCheckpoint() -> ServiceBuildRegistrationCheckpoint {
    .init(
      proxy: serviceMaintainer.status(of: .proxyAgent),
      authority: serviceMaintainer.status(of: .globalAuthority))
  }

  /// Status polling never uses this checkpoint to authorize a start. Every new
  /// operation re-inspects, and its XPC connection requires the embedded code's
  /// CDHash. The checkpoint only avoids repeated signature/process scans while
  /// displaying a stable registration pair. Errors/registration changes and an
  /// active-to-Off transition with an upgrade pending invalidate that shortcut.
  func queryStatusWithServiceBuildReconciliation() async throws -> NativeEngineStatus {
    let checkpoint = serviceBuildCheckpoint()
    if serviceBuildPollCheckpoint == checkpoint {
      do {
        let status = try await queryStatus(enforcePreferenceBarrier: true)
        if !serviceBuildUpgradePending || status != .off { return status }
      } catch {
        serviceBuildPollCheckpoint = nil
        throw error
      }
    }
    do {
      try await requireCurrentServiceBuilds(allowHandoff: true)
    } catch {
      let original = error
      serviceBuildUpgradePending = true
      serviceBuildPollCheckpoint = nil
      // A partial handoff must retain its failure. The ordinary query may
      // auto-register jobs, so it is not a safe fallback after mutation begins.
      if error is ServiceBuildHandoffFailure || error is CancellationError || Task.isCancelled
        || (checkpoint.proxy == .enabled && checkpoint.authority == .notRegistered)
      {
        // An orphaned Proxy cannot prove global Active without its Authority.
        // A normal query here would implicitly register the missing Authority,
        // bypassing the ordered recovery that just failed.
        throw Self.map(error)
      }
      // Preserve the actual active session and the existing stop path. An
      // upgrade is never permission to stop it or erase its status.
      let status: NativeEngineStatus
      do { status = try await queryStatus(enforcePreferenceBarrier: true) } catch {
        serviceBuildPollCheckpoint = nil
        throw Self.map(original)
      }
      guard status != .off else { throw Self.map(original) }
      serviceBuildPollCheckpoint = serviceBuildCheckpoint()
      Self.serviceUpgradeLog.notice(
        "Background service upgrade is pending until the active session is Off.")
      return status
    }
    do {
      let status = try await queryStatus(enforcePreferenceBarrier: true)
      serviceBuildPollCheckpoint = serviceBuildCheckpoint()
      serviceBuildUpgradePending = false
      return status
    } catch {
      serviceBuildPollCheckpoint = nil
      throw error
    }
  }

  /// Caller holds the existing Host operation lease, except for the explicitly
  /// read-only no-handoff gate used by profile probes and authorization dialogs.
  func requireCurrentServiceBuilds(allowHandoff: Bool) async throws {
    try Task.checkCancellation()
    let inspection: CurrentAppServiceBuildInspection
    do { inspection = try serviceBuildObserver.inspect() } catch {
      throw NativeBridgeExecutionError.failure(
        .identityRejected, "The running background service version could not be verified.")
    }
    if inspection.isCurrent { return }
    serviceBuildUpgradePending = true
    serviceBuildPollCheckpoint = nil
    for observation in [inspection.proxy, inspection.authority] {
      do { try observation.requireNonConflictingVersion() } catch {
        throw NativeBridgeExecutionError.failure(
          .identityRejected, "A background service conflicts with this application version.")
      }
    }
    if inspection.proxy.registration == .requiresApproval {
      throw Self.map(ProxyAgentHostError.registrationRequiresApproval)
    }
    if inspection.authority.registration == .requiresApproval {
      throw Self.map(AuthorityDomainError(code: .globalAuthorityApprovalRequired))
    }
    guard allowHandoff else {
      throw NativeBridgeExecutionError.failure(
        .busy, "Background services must finish updating after the connection is Off.")
    }
    guard
      [CurrentAppServiceStatus.enabled, .notRegistered].contains(inspection.proxy.registration),
      [CurrentAppServiceStatus.enabled, .notRegistered].contains(inspection.authority.registration)
    else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven, "Background service registration could not be verified for an update.")
    }

    let actions: [NativeServiceMaintenanceAction]
    switch (inspection.proxy.registration, inspection.authority.registration) {
    case (.enabled, .enabled):
      // Observation may encounter an enabled lazy job before its first XPC
      // activation. Warm it by the existing status query, never a start command.
      guard case .off = try await queryStatus(enforcePreferenceBarrier: true) else {
        throw NativeBridgeExecutionError.failure(
          .busy, "Background services will update after the active connection stops.")
      }
      let refreshed = try serviceBuildObserver.inspect()
      try refreshed.proxy.requireNonConflictingVersion()
      try refreshed.authority.requireNonConflictingVersion()
      if refreshed.isCurrent { return }
      guard refreshed.proxy.runningCode != nil, refreshed.authority.runningCode != nil,
        refreshed.proxy.registration == .enabled, refreshed.authority.registration == .enabled
      else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Registered background services did not expose a stable running identity.")
      }
      actions = [
        .proveOff, .unregisterProxyAgent, .unregisterGlobalAuthority,
        .registerGlobalAuthority, .registerProxyAgent,
      ]
    case (.notRegistered, .enabled):
      // Resume a completed Proxy unregister using fresh absence/Off proofs.
      actions =
        inspection.authority.isCurrent
        ? [.registerProxyAgent]
        : [.unregisterGlobalAuthority, .registerGlobalAuthority, .registerProxyAgent]
    case (.notRegistered, .notRegistered):
      actions = [.registerGlobalAuthority, .registerProxyAgent]
    case (.enabled, .notRegistered):
      // Quit/recovery may have registered the Proxy while Authority registration
      // was unavailable. Retire only a freshly proven, stable-Off orphan before
      // restoring the existing Authority -> Proxy registration order.
      actions = [.retireOrphanedServices, .registerGlobalAuthority, .registerProxyAgent]
    default:
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven, "Background service update ordering requires explicit recovery.")
    }
    do {
      for action in actions {
        try Task.checkCancellation()
        Self.serviceUpgradeLog.info(
          "Background service update phase: \(String(describing: action), privacy: .public)")
        do {
          if action == .retireOrphanedServices {
            _ = try await retireOrphanedServicesForUpgrade()
          } else {
            _ = try await maintainCurrentServices(action)
          }
        } catch {
          let failure = Self.map(error).responseFailure
          throw NativeBridgeExecutionError.failure(
            failure.code,
            "Background service update could not complete \(String(describing: action)): \(failure.message)"
          )
        }
        try Task.checkCancellation()
      }
      guard try serviceBuildObserver.inspect().isCurrent else {
        throw NativeBridgeExecutionError.failure(
          .identityRejected, "Updated background services do not match this application.")
      }
    } catch { throw ServiceBuildHandoffFailure(failure: Self.map(error)) }
    serviceBuildUpgradePending = false
    Self.serviceUpgradeLog.info(
      "Background service update completed with matching signed component identities.")
  }

  static func requiresCurrentServices(_ command: NativeBridgeCommand) -> Bool {
    switch command {
    case .startSystemProxy, .startLocalProxy, .startTunnel, .installTunnel,
      .authorizeTunnelConfiguration, .checkConfiguration, .preflightCutover:
      true
    default:
      false
    }
  }
}

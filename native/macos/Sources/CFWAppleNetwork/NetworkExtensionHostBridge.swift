import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension

private struct ClosureAuthorityPreparationRevoker: AuthorityPreparationRevoking {
  let body: @Sendable () async throws -> Void

  func revokePreparation() async throws {
    try await body()
  }
}

/// Serializes all NETunnelProviderManager mutations in one actor. It never
/// reports TunnelActive from NEVPNStatus alone: the connected provider must
/// return a typed snapshot whose configuration digest matches preferences.
public actor NetworkExtensionHostBridge: TunnelHostBridging, ManagedTunnelOperating,
  ManagedTunnelPreferences
{
  /// How long a stop waits for macOS to report the tunnel disconnected.
  package static let tunnelStopWait: Duration = .seconds(5)

  private let providerBundleIdentifier: String
  private let installer: any SystemExtensionInstalling
  private let preparer: any TunnelStartPreparing
  let callbackDeadline: CallbackDeadlineScheduler
  private let authorizationDeadline: CallbackDeadlineScheduler
  private let preferenceMutationJournal: PreferenceMutationJournal
  private var inFlightManager: NETunnelProviderManager?
  private var pendingStartedConfiguration: ConfigurationDescriptor?

  public init(
    providerBundleIdentifier: String,
    installer: any SystemExtensionInstalling,
    preparer: any TunnelStartPreparing = FailClosedTunnelStartPreparer(),
    preferenceMutationKeychainAccessGroup: String,
    callbackTimeout: Duration = .seconds(5),
    authorizationTimeout: Duration = .seconds(270)
  ) throws {
    self.providerBundleIdentifier = providerBundleIdentifier
    self.installer = installer
    self.preparer = preparer
    callbackDeadline = CallbackDeadlineScheduler(timeout: callbackTimeout)
    authorizationDeadline = CallbackDeadlineScheduler(timeout: authorizationTimeout)
    do {
      preferenceMutationJournal = try PreferenceMutationJournal(
        store: KeychainTunnelPreferenceMutationJournalStore(
          keychainAccessGroup: preferenceMutationKeychainAccessGroup
        )
      )
    } catch {
      throw AppleNetworkError.preferenceMutationJournalUnavailable(
        "The Host-only Keychain receipt could not be loaded."
      )
    }
  }

  /// Builds the single-key `NETunnelProviderSession.startTunnel(options:)` dictionary carrying only the
  /// bounded, opaque start ticket. Exposed for focused ticket-only option tests.
  static func ticketStartOptions(_ ticketBytes: Data) -> [String: NSData] {
    [NativeProtocolConstants.tunnelStartTicketOptionKey: ticketBytes as NSData]
  }

  public func installTunnel() async throws -> SystemExtensionInstallResult {
    try await installer.install()
  }

  public func awaitTunnelInstallationApproval() async throws -> SystemExtensionApprovalWait {
    try await installer.awaitApprovalResolution()
  }

  public func cancelTunnelInstallationWait() async {
    // This intentionally does not call stopTunnel. Approval/activation is a
    // SystemExtensions control-plane operation, not a running VPN session,
    // and Apple exposes no public cancellation API once a request is submitted.
    installer.cancelInstallationWait()
  }

  public func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) async throws {
    // Prepare with the Global Authority before any preference mutation, persist only
    // the descriptor-only manager, verify the exact reloaded preferences, and start
    // with only the single-use ticket. There is no direct configuration/credential
    // payload path: `NETunnelProviderSession.startTunnel(options:)` carries only the ticket.
    do {
      try await TicketOnlyTunnelStartFlow.run(
        descriptor: descriptor,
        configuration: configuration,
        credentialPayload: credentialPayload,
        preparer: preparer,
        manager: self
      )
    } catch {
      // A timed-out load/save callback may still arrive, but its manager object
      // must never be reused by a later mutation. A retry reloads the durable
      // preference store and reconciles what the OS actually committed.
      inFlightManager = nil
      throw error
    }
  }

  public func authorizeTunnelConfiguration(_ descriptor: ConfigurationDescriptor) async throws {
    let (manager, createdManager) = try await loadOrCreateManager()
    guard try managedConnectionStatus(manager).isStopped else {
      throw AppleNetworkError.cleanupUnproven("VPN authorization requires a stopped connection.")
    }
    // An existing verified configuration already has its macOS consent. Preserve
    // it until the ordinary Authority-backed start transaction replaces it.
    guard createdManager else { return }
    let values = ManagedTunnelPreferenceValues(
      descriptor: descriptor, providerBundleIdentifier: providerBundleIdentifier,
      serverAddress: "Clash for Mac", isEnabled: false,
      localizedDescription: "Clash for Mac Tunnel")
    let receipt = TunnelPreferenceMutationReceipt(
      operationID: UUID(), createdManager: true, priorValues: nil, writtenValues: values)
    try Self.applyDescriptorOnlyPreferences(values, to: manager)
    try await save(manager, receipt: receipt, deadline: authorizationDeadline)
    try Task.checkCancellation()
    try await reload(manager)
    guard try Self.managedPreferenceValues(manager) == values,
      try managedConnectionStatus(manager).isStopped,
      let pending = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: descriptor, requireSettledCurrentProcessMutation: true),
      pending == receipt
    else {
      throw AppleNetworkError.cleanupUnproven(
        "The disabled VPN authorization configuration changed.")
    }
    try preferenceMutationJournal.clear(operationID: receipt.operationID)
    inFlightManager = nil
  }

  // MARK: - ManagedTunnelOperating (NetworkExtension-backed)

  func saveDescriptorOnly(
    _ descriptor: ConfigurationDescriptor,
    operationID: UUID
  ) async throws {
    let (manager, createdManager) = try await loadOrCreateManager()
    guard !createdManager else {
      throw AppleNetworkError.managedManagerVerificationFailed(
        "The authorized VPN configuration disappeared before start.")
    }
    guard try managedConnectionStatus(manager).isStopped else {
      throw AppleNetworkError.cleanupUnproven(
        "Managed tunnel preferences cannot be replaced while the OS connection is active."
      )
    }
    let priorValues = createdManager ? nil : try Self.managedPreferenceValues(manager)
    let writtenValues = ManagedTunnelPreferenceValues(
      descriptor: descriptor,
      providerBundleIdentifier: providerBundleIdentifier,
      serverAddress: "Clash for Mac",
      isEnabled: true,
      localizedDescription: "Clash for Mac Tunnel"
    )
    let receipt = TunnelPreferenceMutationReceipt(
      operationID: operationID,
      createdManager: createdManager,
      priorValues: priorValues,
      writtenValues: writtenValues
    )
    // Always replace the protocol object. Reusing a legacy protocol would retain
    // inherited credential, proxy, sleep, route, or on-demand state that is outside
    // the descriptor-only preference contract.
    try Self.applyDescriptorOnlyPreferences(writtenValues, to: manager)
    try await save(manager, receipt: receipt)
    inFlightManager = manager
  }

  func reloadDescriptor() async throws -> ConfigurationDescriptor {
    guard let manager = inFlightManager else {
      throw AppleNetworkError.managedManagerVerificationFailed(
        "No managed tunnel manager is staged for reload verification."
      )
    }
    try await reload(manager)
    let reloaded = try Self.managedPreferenceValues(manager)
    guard
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: reloaded.descriptor,
        requireSettledCurrentProcessMutation: true
      ),
      reloaded == receipt.writtenValues
    else {
      throw AppleNetworkError.managedManagerVerificationFailed(
        "Reloaded managed tunnel preferences do not match the durable write receipt."
      )
    }
    return reloaded.descriptor
  }

  func startWithTicket(_ ticketBytes: Data) async throws {
    guard let manager = inFlightManager else {
      throw AppleNetworkError.managedManagerVerificationFailed(
        "No managed tunnel manager is staged for start."
      )
    }
    defer { inFlightManager = nil }
    do {
      guard let session = manager.connection as? NETunnelProviderSession else {
        throw AppleNetworkError.providerDidNotRespond
      }
      // Use the provider-session API documented for custom provider options.
      // macOS may add its own connection metadata before the Provider callback.
      pendingStartedConfiguration = try manager.configurationDescriptor()
      try Self.startProviderSession(session, ticketBytes: ticketBytes)
    } catch let startError {
      pendingStartedConfiguration = nil
      if startError is CancellationError {
        throw startError
      }
      throw AppleNetworkError.tunnelStartFailed(startError.localizedDescription)
    }
  }

  static func startProviderSession(_ session: NETunnelProviderSession, ticketBytes: Data) throws {
    try session.startTunnel(options: ticketStartOptions(ticketBytes))
  }

  public func stopTunnel(expectedConfiguration: ConfigurationDescriptor) async throws {
    guard let manager = try await soleManager() else {
      throw AppleNetworkError.staleStopRequest
    }
    guard try manager.configurationDescriptor() == expectedConfiguration else {
      throw AppleNetworkError.staleStopRequest
    }
    pendingStartedConfiguration = nil
    manager.connection.stopVPNTunnel()

    // Awake time, as the provider's bound on closing libbox counts it, so a
    // sleep during the stop cannot end this wait before that bound.
    let clock = SuspendingClock()
    let deadline = clock.now.advanced(by: Self.tunnelStopWait)
    while clock.now < deadline {
      switch manager.connection.status {
      case .disconnected, .invalid:
        return
      default:
        try await Task.sleep(for: .milliseconds(100))
      }
    }
    throw AppleNetworkError.tunnelStopTimedOut
  }

  public func snapshot() async throws -> EngineSnapshot {
    try Task.checkCancellation()
    guard let manager = try await soleManager() else {
      return .off
    }
    try Task.checkCancellation()
    switch manager.connection.status {
    case .invalid, .disconnected:
      if let expected = pendingStartedConfiguration,
        try manager.configurationDescriptor() == expected
      {
        let failure: EngineFailure? = try await awaitBoundedCallback(
          deadline: callbackDeadline,
          timeoutError: AppleNetworkError.providerMessageTimedOut
        ) { finish in
          manager.connection.fetchLastDisconnectError { error in
            finish(
              .success(
                TunnelStartupFailure.matchingFailure(
                  error.map { $0 as NSError }, configuration: expected)))
          }
        }
        try Task.checkCancellation()
        if pendingStartedConfiguration == expected,
          try manager.configurationDescriptor() == expected,
          manager.connection.status == .disconnected,
          let failure
        {
          return .tunnelFailed(failure, configuration: expected, sequence: 0)
        }
      }
      return .off
    case .connecting, .reasserting:
      return .tunnelStarting(
        configuration: try manager.configurationDescriptor(),
        sequence: 0
      )
    case .disconnecting:
      return .tunnelStopping(
        configuration: try manager.configurationDescriptor(),
        sequence: 0
      )
    case .connected:
      return try await providerSnapshot(manager)
    @unknown default:
      return .tunnelFailed(
        EngineFailure(
          .unknownConnectionStatus,
          message: "NetworkExtension returned an unknown VPN status."),
        configuration: try manager.configurationDescriptor(),
        sequence: 0
      )
    }
  }

  public func recoveryManagedTunnelStatus() async throws -> RecoveryManagedTunnelStatus {
    try Task.checkCancellation()
    guard let manager = try await soleManager() else {
      return .invalid
    }
    try Task.checkCancellation()
    switch manager.connection.status {
    case .disconnected:
      return .disconnected
    case .invalid:
      return .invalid
    case .connecting, .reasserting:
      return .connecting
    case .connected:
      return .connected
    case .disconnecting:
      return .unknown
    @unknown default:
      return .unknown
    }
  }

  public func hasManagedTunnelConfiguration() async throws -> Bool {
    try await soleManager() != nil
  }

  public func managedTunnelConfiguration() async throws -> ConfigurationDescriptor? {
    guard let manager = try await soleManager() else {
      return nil
    }
    return try manager.configurationDescriptor()
  }

  public func pendingPreferenceMutationConfiguration() async throws
    -> ConfigurationDescriptor?
  {
    try preferenceMutationJournal.pendingDescriptor()
  }

  public func compensatePendingPreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor,
    revokePreparation: @escaping @Sendable () async throws -> Void
  ) async throws -> Bool {
    guard
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: expectedConfiguration,
        requireSettledCurrentProcessMutation: true
      )
    else {
      return false
    }

    try await TunnelPreferenceCompensation.run(
      receipt: receipt,
      authority: ClosureAuthorityPreparationRevoker(body: revokePreparation),
      preferences: self
    )
    inFlightManager = nil
    pendingStartedConfiguration = nil
    return true
  }

  public func finishPreferenceCompensation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws {
    guard
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: expectedConfiguration,
        requireSettledCurrentProcessMutation: true
      )
    else { return }
    guard try await loadCurrentValues() == receipt.expectedRestoredValues,
      try await connectionStatus().isStopped
    else {
      throw AppleNetworkError.cleanupUnproven(
        "Tunnel preference compensation is not durably restored and Off."
      )
    }
    try preferenceMutationJournal.clear(operationID: receipt.operationID)
    inFlightManager = nil
    pendingStartedConfiguration = nil
  }

  public func completePreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws {
    guard
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: expectedConfiguration,
        requireSettledCurrentProcessMutation: true
      )
    else {
      throw AppleNetworkError.cleanupUnproven(
        "A Tunnel start reached readiness without its durable preference receipt."
      )
    }

    let manager = try await soleManager()
    guard let manager,
      try Self.managedPreferenceValues(manager) == receipt.writtenValues,
      try managedConnectionStatus(manager) == .connected
    else {
      throw AppleNetworkError.cleanupUnproven(
        "The ready Tunnel no longer matches its durable preference receipt."
      )
    }
    try preferenceMutationJournal.clear(operationID: receipt.operationID)
    inFlightManager = nil
    pendingStartedConfiguration = nil
  }

  // MARK: - ManagedTunnelPreferences (durable compensation)

  public func loadCurrentValues() async throws -> ManagedTunnelPreferenceValues? {
    try await soleManager().map(Self.managedPreferenceValues)
  }

  public func connectionStatus() async throws -> ManagedTunnelConnectionStatus {
    guard let manager = try await soleManager() else { return .invalid }
    return try managedConnectionStatus(manager)
  }

  public func stop() async throws {
    guard let manager = try await soleManager() else { return }
    manager.connection.stopVPNTunnel()
  }

  public func apply(_ values: ManagedTunnelPreferenceValues) async throws {
    guard let manager = try await soleManager(),
      let descriptor = try preferenceMutationJournal.pendingDescriptor(),
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: descriptor,
        requireSettledCurrentProcessMutation: false
      ),
      try Self.managedPreferenceValues(manager) == receipt.writtenValues
    else {
      throw AppleNetworkError.compensationConflict(
        "Managed tunnel preferences changed before the restore save."
      )
    }

    let stageID = try preferenceMutationJournal.prepareCompensation(
      operationID: receipt.operationID,
      operation: .compensationSave
    )

    try Self.applyDescriptorOnlyPreferences(values, to: manager)
    try await saveCompensation(
      manager,
      operationID: receipt.operationID,
      stageID: stageID
    )
    try await reload(manager)
    guard try Self.managedPreferenceValues(manager) == values else {
      throw AppleNetworkError.cleanupUnproven(
        "Reloaded managed tunnel preferences do not match the compensation receipt."
      )
    }
    inFlightManager = nil
  }

  public func removeManager() async throws {
    guard let manager = try await soleManager(),
      let descriptor = try preferenceMutationJournal.pendingDescriptor(),
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: descriptor,
        requireSettledCurrentProcessMutation: false
      ),
      try Self.managedPreferenceValues(manager) == receipt.writtenValues
    else {
      throw AppleNetworkError.compensationConflict(
        "Managed tunnel preferences changed before manager removal."
      )
    }

    let stageID = try preferenceMutationJournal.prepareCompensation(
      operationID: receipt.operationID,
      operation: .compensationRemove
    )
    let wait = PreferenceSaveWait(
      operationID: receipt.operationID,
      stageID: stageID,
      operation: .compensationRemove,
      journal: preferenceMutationJournal,
      timeoutError: .preferenceRemoveTimedOut,
      failureError: AppleNetworkError.preferenceRemoveFailed
    )
    try await awaitPreferenceMutationCallback(wait) { callback in
      manager.removeFromPreferences(completionHandler: callback)
    }
    inFlightManager = nil
  }

  private func loadOrCreateManager() async throws -> (NETunnelProviderManager, Bool) {
    if let manager = try await soleManager() {
      let values = try Self.managedPreferenceValues(manager)
      guard values.providerBundleIdentifier == providerBundleIdentifier else {
        throw AppleNetworkError.compensationConflict(
          "The calling application's managed tunnel has an unexpected provider identity."
        )
      }
      return (manager, false)
    }
    return (NETunnelProviderManager(), true)
  }

  private func save(
    _ manager: NETunnelProviderManager,
    receipt: TunnelPreferenceMutationReceipt,
    deadline: CallbackDeadlineScheduler? = nil
  ) async throws {
    let stageID = try preferenceMutationJournal.begin(receipt)
    let wait = PreferenceSaveWait(
      operationID: receipt.operationID,
      stageID: stageID,
      operation: .originalSave,
      journal: preferenceMutationJournal,
      timeoutError: .preferenceSaveTimedOut,
      failureError: AppleNetworkError.preferenceSaveFailed
    )
    var cancelDeadline: CallbackDeadlineScheduler.Cancel?
    defer { cancelDeadline?() }
    do {
      let _: Void = try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
          wait.install(continuation)
          guard !Task.isCancelled else {
            wait.cancel()
            return
          }
          cancelDeadline = (deadline ?? callbackDeadline).schedule { wait.timeout() }
          guard wait.beginSubmission() else { return }
          manager.saveToPreferences { error in
            wait.finish(error)
          }
        }
      } onCancel: {
        wait.cancel()
      }
    } catch {
      if !wait.wasSubmitted {
        try preferenceMutationJournal.abandonUnsubmitted(
          operationID: receipt.operationID,
          stageID: stageID)
      }
      throw error
    }
  }

  private func saveCompensation(
    _ manager: NETunnelProviderManager,
    operationID: UUID,
    stageID: UUID
  ) async throws {
    let wait = PreferenceSaveWait(
      operationID: operationID,
      stageID: stageID,
      operation: .compensationSave,
      journal: preferenceMutationJournal,
      timeoutError: .preferenceSaveTimedOut,
      failureError: AppleNetworkError.preferenceSaveFailed
    )
    try await awaitPreferenceMutationCallback(wait) { callback in
      manager.saveToPreferences(completionHandler: callback)
    }
  }

}

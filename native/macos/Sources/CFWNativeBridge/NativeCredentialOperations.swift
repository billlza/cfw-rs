import CFWAppleNetwork
import CFWCredentialTransport
import CFWSharedProtocol
import Foundation

extension NativeBridgeCoordinator {
  func preflightCredentials(_ request: EngineStartRequest) throws {
    do {
      var material = try credentialVault.resolve(slots: request.credentialSlots)
      material.erase()
    } catch {
      throw Self.map(error)
    }
  }

  func provisionCredentials(
    _ request: CredentialProvisionRequest
  ) throws -> NativeCredentialReceipt {
    try beginMutation()
    defer { endMutation() }
    var request = request
    defer { request.erase() }
    var material: CredentialMaterial
    do {
      material = try CredentialMaterial(
        entries: request.entries.map { entry in
          try entry.withSecretBytes {
            try CredentialMaterialEntry(reference: entry.reference, secret: $0)
          }
        }
      )
    } catch {
      throw Self.map(error)
    }
    defer { material.erase() }
    do {
      let receipt = try credentialVault.provision(
        profileID: request.profileID.uuidString.lowercased(),
        requiredReferences: request.requiredReferences,
        material: material
      )
      return NativeCredentialReceipt(profileID: receipt.profileID)
    } catch {
      throw Self.map(error)
    }
  }

  func queryCredentialPresence(
    _ request: CredentialPresenceRequest
  ) throws -> [NativeCredentialPresence] {
    do {
      return try credentialVault.presence(of: request.references).map {
        NativeCredentialPresence(reference: $0.reference, present: $0.present)
      }
    } catch {
      throw Self.map(error)
    }
  }

  func previewCredentialGarbageCollection(
    _ request: CredentialGarbageCollectionRequest
  ) async throws -> CredentialGarbageCollectionPreview {
    try beginMutation()
    defer { endMutation() }
    let references = try await protectedCredentialReferences(
      repositoryReferences: request.liveReferences
    )
    do {
      return try credentialVault.previewGarbageCollection(
        CredentialGarbageCollectionRequest(
          snapshotDigest: request.snapshotDigest,
          liveReferences: references
        )
      )
    } catch {
      throw Self.map(error)
    }
  }

  func preflightCutover(
    _ request: CutoverPreflightRequest
  ) async throws -> CutoverPreflightOutcome {
    try beginMutation()
    defer { endMutation() }
    if let pendingInstallationContext {
      guard pendingInstallationContext == request.tunnelRequest.context else {
        throw NativeBridgeExecutionError.failure(
          .busy,
          "A different System Extension approval request is still pending."
        )
      }
      // A user-approval callback may have completed after the earlier caller
      // returned AwaitingApproval. Cancel only any local wait, preserve the OS
      // request identity, and submit a fresh readiness check. If the original
      // request is still pending, the installer fails Busy without data-plane
      // mutation.
      await tunnel.cancelTunnelInstallationWait()
      self.pendingInstallationContext = nil
    }
    guard case .off = try await queryStatus() else {
      throw NativeBridgeExecutionError.failure(
        .busy,
        "Cutover preflight requires the replacement engine to be globally Off."
      )
    }
    try await checkConfiguration(request.systemProxyRequest)
    try await checkConfiguration(request.tunnelRequest)

    if request.target == .tunnel {
      let installResult: SystemExtensionInstallResult
      do {
        installResult = try await tunnel.installTunnel()
      } catch {
        throw Self.map(error)
      }
      switch installResult {
      case .awaitingApproval:
        pendingInstallationContext = request.tunnelRequest.context
        return .awaitingApproval(
          target: request.target,
          context: request.tunnelRequest.context,
          systemProxyConfigDigest: request.systemProxyRequest.configDigest,
          tunnelConfigDigest: request.tunnelRequest.configDigest
        )
      case .requiresRestart:
        throw NativeBridgeExecutionError.failure(
          .unavailable,
          "System Extension activation requires a restart before cutover."
        )
      case .completed:
        break
      }
    }
    guard case .off = try await queryStatus() else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "System Extension preparation changed replacement engine ownership."
      )
    }
    let references = Set(request.tunnelRequest.credentialSlots.map(\.reference)).sorted {
      $0.id.uuidString.lowercased() < $1.id.uuidString.lowercased()
    }
    return .ready(
      try CutoverPreflightAttestation(
        attestationID: UUID(),
        target: request.target,
        context: request.tunnelRequest.context,
        systemProxyConfigDigest: request.systemProxyRequest.configDigest,
        tunnelConfigDigest: request.tunnelRequest.configDigest,
        credentialReferences: references,
        validForMillis: CutoverPreflightAttestation.maximumValidityMilliseconds
      )
    )
  }

  func checkConfiguration(_ request: EngineStartRequest) async throws {
    var material: CredentialMaterial
    do {
      material = try credentialVault.resolve(slots: request.credentialSlots)
    } catch {
      throw Self.map(error)
    }
    defer { material.erase() }
    var template = Data(request.configJSON.utf8)
    defer {
      template.resetBytes(in: template.startIndex..<template.endIndex)
      template.removeAll(keepingCapacity: false)
    }
    var configuration: Data
    do {
      configuration = try CredentialInjector.inject(
        template: template,
        slots: request.credentialSlots,
        material: material
      )
    } catch {
      throw Self.map(error)
    }
    defer {
      configuration.resetBytes(in: configuration.startIndex..<configuration.endIndex)
      configuration.removeAll(keepingCapacity: false)
    }
    let descriptor = try request.descriptor(
      slot: request.tunnelOptions == nil ? .systemProxy : .tunnel
    )
    do {
      try await proxy.validateConfiguration(configuration, descriptor: descriptor)
    } catch {
      throw Self.map(error)
    }
  }

  func commitCredentialGarbageCollection(
    _ request: CredentialGarbageCollectionCommitRequest
  ) async throws -> CredentialGarbageCollectionReceipt {
    try beginMutation()
    defer { endMutation() }
    let references = try await protectedCredentialReferences(
      repositoryReferences: request.liveReferences
    )
    do {
      return try credentialVault.commitGarbageCollection(
        CredentialGarbageCollectionCommitRequest(
          snapshotDigest: request.snapshotDigest,
          liveReferences: references,
          expectedVaultRevision: request.expectedVaultRevision,
          expectedOrphanReferences: request.expectedOrphanReferences
        )
      )
    } catch {
      throw Self.map(error)
    }
  }

  /// Unions repository references with every descriptor still observed by an
  /// endpoint or persisted Tunnel manager. If any native state cannot be
  /// observed safely, GC fails closed without deleting Keychain material.
  func protectedCredentialReferences(
    repositoryReferences: [CredentialReference]
  ) async throws -> [CredentialReference] {
    async let proxyObservation = Self.observe { try await self.proxy.snapshot() }
    async let tunnelObservation = Self.observe { try await self.tunnel.snapshot() }
    async let tunnelManagerConfiguration = Self.observe {
      try await self.tunnel.managedTunnelConfiguration()
    }
    let (proxyValue, tunnelValue, managerConfigurationValue) = await (
      proxyObservation,
      tunnelObservation,
      tunnelManagerConfiguration
    )
    let proxySnapshot = try Self.requireObservation(proxyValue, component: "ProxyAgent")
    let tunnelSnapshot = try Self.requireObservation(tunnelValue, component: "Packet Tunnel")
    let managerConfiguration = try Self.requireObservation(
      managerConfigurationValue,
      component: "Tunnel manager configuration"
    )
    var referencesByID: [UUID: CredentialReference] = [:]
    func preserve(_ reference: CredentialReference) throws {
      if let existing = referencesByID[reference.id], existing.kind != reference.kind {
        throw NativeBridgeExecutionError.failure(
          .configurationRejected,
          "Credential reference kind conflicts across protected native state."
        )
      }
      referencesByID[reference.id] = reference
    }
    for reference in repositoryReferences {
      try preserve(reference)
    }
    for descriptor in [
      proxySnapshot.configuration,
      tunnelSnapshot.configuration,
      managerConfiguration,
    ].compactMap({ $0 }) {
      for slot in descriptor.credentialSlots {
        try preserve(slot.reference)
      }
    }
    return referencesByID.values.sorted {
      let leftID = $0.id.uuidString.lowercased()
      let rightID = $1.id.uuidString.lowercased()
      if leftID != rightID {
        return leftID < rightID
      }
      return $0.kind.rawValue < $1.kind.rawValue
    }
  }
}

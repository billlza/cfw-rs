import Foundation

/// Marker used by the canonical codec. Every public wire model validates semantic
/// invariants after decoding; secret-bearing types deliberately do not conform.
public protocol AuthorityV1WireModel: Codable, Sendable {
  func validateAuthorityV1() throws
}

extension AuthorityProtocolVersion: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = try AuthorityProtocolVersion(
      major: major, minor: minor, minimumMinor: minimumMinor,
      featureBits: featureBits, maxMessageBytes: maxMessageBytes)
  }
}
extension RootContext: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = try RootContext(installationID: installationID, epoch: epoch, generation: generation)
  }
}
extension OperationContext: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try root.validateAuthorityV1()
    _ = try OperationContext(
      operationID: operationID, root: root, mode: mode, configSHA256: configSHA256,
      identitySHA256: identitySHA256, ownerUID: ownerUID,
      authorityRevision: authorityRevision)
  }
}
extension GlobalLease: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try GlobalLease(
      leaseID: leaseID, operation: operation, state: state,
      issuedMonotonic: issuedMonotonic, expiryMonotonic: expiryMonotonic,
      ownerConnectionNonce: ownerConnectionNonce)
  }
}
extension ReplayCursor: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    guard schemaVersion == 1 else { throw AuthorityV1ValidationError.invalidContext }
    _ = try ReplayCursor(
      installationID: installationID, acceptedEpoch: acceptedEpoch,
      acceptedGeneration: acceptedGeneration, revision: revision,
      previousRecordSHA256: previousRecordSHA256)
  }
}
extension AuthorityConfigurationDescriptor: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = try AuthorityConfigurationDescriptor(
      byteCount: byteCount, configSHA256: configSHA256,
      identitySHA256: identitySHA256, credentialAudience: credentialAudience,
      credentialSlots: credentialSlots,
      tunnelOptions: tunnelOptions)
  }
}
extension LeaseView: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try LeaseView(
      leaseID: leaseID, operation: operation, state: state,
      expiryMonotonic: expiryMonotonic)
  }
}
extension AuthorityFailureSummary: AuthorityV1WireModel {
  public func validateAuthorityV1() throws { _ = try AuthorityFailureSummary(code: code) }
}
extension AuthoritySnapshot: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try protocolVersion.validateAuthorityV1()
    try replayCursor?.validateAuthorityV1()
    try leaseView?.validateAuthorityV1()
    try lastFailure?.validateAuthorityV1()
    _ = try AuthoritySnapshot(
      protocolVersion: protocolVersion, state: state, revision: revision,
      replayCursor: replayCursor, leaseView: leaseView,
      lastFailure: lastFailure, consoleUID: consoleUID)
  }
}
extension PacketPumpLimits: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = try PacketPumpLimits(
      maximumQueuedPackets: maximumQueuedPackets,
      maximumQueuedBytes: maximumQueuedBytes,
      maximumPacketBytes: maximumPacketBytes,
      maximumReadBatch: maximumReadBatch)
  }
}
extension ReadyAttestation: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    try packetPumpLimits?.validateAuthorityV1()
    _ = try ReadyAttestation(
      operation: operation, leaseID: leaseID, runtimeDigest: runtimeDigest,
      ownerRole: ownerRole, readyFlags: readyFlags,
      packetPumpLimits: packetPumpLimits, monotonicTimestamp: monotonicTimestamp)
  }
}
extension StoppedAttestation: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try StoppedAttestation(
      operation: operation, leaseID: leaseID, libboxStopped: libboxStopped,
      transportClosed: transportClosed, osRestored: osRestored,
      monotonicTimestamp: monotonicTimestamp)
  }
}
extension TunnelPreferenceValues: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = try TunnelPreferenceValues(
      descriptorSHA256: descriptorSHA256, isEnabled: isEnabled,
      localizedDescription: localizedDescription)
  }
}
extension PreferenceMutationReceipt: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try priorValues?.validateAuthorityV1()
    _ = try PreferenceMutationReceipt(
      operationID: operationID, createdManager: createdManager,
      priorValues: priorValues, writtenDescriptorSHA256: writtenDescriptorSHA256)
  }
}
extension HandshakeRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws { try version.validateAuthorityV1() }
}
extension HandshakeResponse: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try version.validateAuthorityV1()
    guard self == (try HandshakeResponse.v1()) else {
      throw AuthorityV1ValidationError.boundViolation
    }
  }
}
extension PrepareStartRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    try configuration.validateAuthorityV1()
    _ = try PrepareStartRequest(
      operation: operation, expectedRevision: expectedRevision,
      configuration: configuration)
  }
}
extension ProxyOwnerContext: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try ProxyOwnerContext(operation: operation, leaseID: leaseID)
  }
}
extension BeginStopRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try BeginStopRequest(
      operation: operation, leaseID: leaseID, expectedRevision: expectedRevision)
  }
}
extension CompleteStopRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try CompleteStopRequest(
      operation: operation, leaseID: leaseID,
      expectedRevision: expectedRevision)
  }
}
extension RecoveryProxyOffEvidence: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = RecoveryProxyOffEvidence(
      ownershipCleared: ownershipCleared,
      listenerClosed: listenerClosed,
      effectiveSystemConfigurationRestored: effectiveSystemConfigurationRestored)
  }
}
extension RecoveryProviderOffEvidence: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = RecoveryProviderOffEvidence(
      ownershipCleared: ownershipCleared,
      libboxStopped: libboxStopped,
      packetPumpClosed: packetPumpClosed)
  }
}
extension ReconcileOffRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try replayCursor.validateAuthorityV1()
    try proxy.validateAuthorityV1()
    try provider.validateAuthorityV1()
    _ = try ReconcileOffRequest(
      expectedRevision: expectedRevision,
      replayCursor: replayCursor,
      proxy: proxy,
      provider: provider,
      managedTunnel: managedTunnel)
  }
}
extension ReconcileOffReceipt: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try replayCursor.validateAuthorityV1()
    _ = try ReconcileOffReceipt(
      revision: revision,
      replayCursor: replayCursor)
  }
}
extension StopDirective: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try StopDirective(
      operation: operation, leaseID: leaseID,
      deadlineMonotonic: deadlineMonotonic, revision: revision)
  }
}
extension CancelPreparedRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try CancelPreparedRequest(operation: operation, expectedRevision: expectedRevision)
  }
}
extension SnapshotRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {}
}
extension OwnerLeaseStatusRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {}
}
extension OwnerLeaseStatusResponse: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {}
}
extension AuthorityAcknowledgement: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    guard revision > 0 else { throw AuthorityV1ValidationError.invalidContext }
  }
}
extension AuthorityEvent: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    switch self {
    case .snapshot(let value): try value.validateAuthorityV1()
    case .revoke(let value), .stop(let value): try value.validateAuthorityV1()
    }
  }
}
extension AuthorityResponseEnvelope: AuthorityV1WireModel where Payload: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    guard major == AuthorityV1Limits.major else {
      throw AuthorityV1ValidationError.unsupportedMajor(major)
    }
    guard minor == AuthorityV1Limits.minor else {
      throw AuthorityV1ValidationError.unsupportedMinor(minor)
    }
    try result.validateAuthorityV1()
  }
}

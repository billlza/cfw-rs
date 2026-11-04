public enum ManagedTunnelObservation: Equatable, Sendable {
  case disconnected
  case invalid
  case connecting
  case connected
  case unknown
}

public enum AuthorityCleanupObservation: Equatable, Sendable {
  case systemProxy(listenerClosed: Bool, systemConfigurationRestored: Bool)
  case tunnel(libboxStopped: Bool, packetPumpClosed: Bool)
  case reconciledBoth(
    proxyListenerClosed: Bool, systemConfigurationRestored: Bool,
    providerLibboxStopped: Bool, packetPumpClosed: Bool)
  case unknown
}

public struct GlobalOffProof: Equatable, Sendable {
  public let leaseReleased: Bool
  public let capabilityOrTicketCleared: Bool
  public let secretBufferCleared: Bool
  public let ownerEndpointCleared: Bool
  public let cleanup: AuthorityCleanupObservation
  public let managedTunnel: ManagedTunnelObservation

  public init(
    leaseReleased: Bool, capabilityOrTicketCleared: Bool,
    secretBufferCleared: Bool, ownerEndpointCleared: Bool,
    cleanup: AuthorityCleanupObservation, managedTunnel: ManagedTunnelObservation
  ) {
    self.leaseReleased = leaseReleased
    self.capabilityOrTicketCleared = capabilityOrTicketCleared
    self.secretBufferCleared = secretBufferCleared
    self.ownerEndpointCleared = ownerEndpointCleared
    self.cleanup = cleanup
    self.managedTunnel = managedTunnel
  }
}

public enum AuthorityOffResolution: Equatable, Sendable {
  case off(revision: UInt64)
  case quarantined(revision: UInt64)
}

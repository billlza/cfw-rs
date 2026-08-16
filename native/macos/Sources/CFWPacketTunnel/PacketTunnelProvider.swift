import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
import OSLog

public enum PacketTunnelProviderError: Error, Equatable, Sendable {
  case providerUnavailable
  case globalAuthorityUnavailable
  case invalidStartTicket
  case malformedProviderConfiguration
  case invalidConfigurationSlot
  case lifecycleConflict
  case startupCancelled
  case configuration(String)
  case engineCreation(String)
  case packetPumpSetup(String)
  case packetPump(PacketPumpError)
  case engineStart(String)
  case engineStop(String)
  case networkSettings(String)
}

extension PacketTunnelProviderError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .providerUnavailable:
      return "Packet tunnel provider lifecycle is unavailable."
    case .globalAuthorityUnavailable:
      return GlobalAuthorityGateError.stableMessage
    case .invalidStartTicket:
      return "Packet tunnel start ticket is missing or invalid."
    case .malformedProviderConfiguration:
      return "Packet tunnel provider configuration is malformed."
    case .invalidConfigurationSlot:
      return "Packet tunnel received a configuration for another engine slot."
    case .lifecycleConflict:
      return "Packet tunnel already owns a starting, active, or failed runtime."
    case .startupCancelled:
      return "Packet tunnel startup was cancelled."
    case .configuration:
      return "Packet tunnel configuration validation failed."
    case .engineCreation:
      return "Packet tunnel engine creation failed."
    case .packetPumpSetup:
      return "Packet pump setup failed."
    case .packetPump(let error):
      return "Packet pump failed: \(error)"
    case .engineStart:
      return "Packet tunnel engine start failed."
    case .engineStop:
      return "Packet tunnel engine stop failed."
    case .networkSettings:
      return "Packet tunnel network settings failed."
    }
  }
}

extension PacketTunnelProviderError {
  var engineFailure: EngineFailure {
    let fields: (code: String, message: String, isRetryable: Bool) =
      switch self {
      case .providerUnavailable:
        (
          "tunnel-provider-unavailable",
          "Packet tunnel provider lifecycle is unavailable.",
          true
        )
      case .globalAuthorityUnavailable:
        (
          GlobalAuthorityGateError.stableCode,
          GlobalAuthorityGateError.stableMessage,
          false
        )
      case .invalidStartTicket:
        (
          "tunnel-start-ticket-invalid",
          "Packet tunnel start ticket is missing or invalid.",
          false
        )
      case .malformedProviderConfiguration:
        (
          "tunnel-provider-configuration-malformed",
          "Packet tunnel provider configuration is malformed.",
          false
        )
      case .invalidConfigurationSlot:
        (
          "tunnel-configuration-slot-invalid",
          "Packet tunnel received a configuration for another engine slot.",
          false
        )
      case .lifecycleConflict:
        (
          "tunnel-lifecycle-conflict",
          "Packet tunnel already owns a starting, active, or failed runtime.",
          false
        )
      case .startupCancelled:
        (
          "tunnel-startup-cancelled",
          "Packet tunnel startup was cancelled.",
          false
        )
      case .configuration:
        (
          "tunnel-configuration-invalid",
          "Packet tunnel configuration validation failed.",
          false
        )
      case .engineCreation:
        (
          "tunnel-engine-creation-failed",
          "Packet tunnel engine creation failed.",
          true
        )
      case .packetPumpSetup:
        (
          "tunnel-packet-pump-setup-failed",
          "Packet tunnel packet pump setup failed.",
          true
        )
      case .packetPump:
        (
          "tunnel-packet-pump-failed",
          "Packet tunnel packet transport failed.",
          true
        )
      case .engineStart:
        (
          "tunnel-engine-start-failed",
          "Packet tunnel engine startup failed.",
          true
        )
      case .engineStop:
        (
          "tunnel-engine-stop-failed",
          "Packet tunnel engine stop failed.",
          true
        )
      case .networkSettings:
        (
          "tunnel-network-settings-failed",
          "Packet tunnel network settings failed.",
          true
        )
      }
    return EngineFailure(
      code: fields.code,
      message: fields.message,
      isRetryable: fields.isRetryable
    )
  }
}

private final class ProviderMessageCompletion: @unchecked Sendable {
  private let lock = NSLock()
  private var handler: ((Data?) -> Void)?

  init(_ handler: @escaping (Data?) -> Void) {
    self.handler = handler
  }

  func finish(_ data: Data?) {
    lock.lock()
    let handler = handler
    self.handler = nil
    lock.unlock()
    handler?(data)
  }
}

public final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
  private static let logger = Logger(
    subsystem: "com.bill.clashformac",
    category: "packet-tunnel"
  )
  private let engineFactory: any PacketEngineFactory
  private var sessionLifecycle: PacketTunnelSessionLifecycle?
  private var startCoordinator: TunnelTicketStartCoordinator?

  public override init() {
    engineFactory = LibboxPacketEngineFactory()
    super.init()
    let lifecycle = PacketTunnelSessionLifecycle(
      engineFactory: engineFactory,
      dependencies: makeSessionDependencies()
    ) { [weak self] error in
      self?.cancelTunnelWithError(error)
    }
    sessionLifecycle = lifecycle
    // The Provider redeems the opaque ticket only through the authenticated,
    // bounded Global Authority channel. No configuration/credential fallback
    // exists in the provider process.
    let revocation = TunnelRevocationChannel()
    let authorityRemote = NSXPCGlobalAuthorityRemote(
      role: .provider,
      onEvent: { event in
        switch event {
        case .revoke, .stop: revocation.revoke()
        case .snapshot: break
        }
      },
      onDisconnect: { revocation.revoke() })
    startCoordinator = TunnelTicketStartCoordinator(
      authority: BoundedAuthorityXPCClient(remote: authorityRemote),
      sessionLifecycle: lifecycle,
      revocation: revocation,
      reportRevocationFailure: { [weak self] error in
        self?.cancelTunnelWithError(error.providerError)
      },
      completeRevocation: { [weak self] in
        self?.cancelTunnelWithError(nil)
      })
  }

  /// Extracts the single bounded, opaque 32-byte start ticket from the tunnel start
  /// options. The production channel carries only this value; a missing, extra, or
  /// wrong-sized entry fails closed with `invalidStartTicket`.
  static func startTicket(from options: [String: NSObject]?) throws -> StartTicket {
    guard
      let options,
      options.count == 1,
      let ticketData = options[NativeProtocolConstants.tunnelStartTicketOptionKey] as? NSData
    else {
      throw PacketTunnelProviderError.invalidStartTicket
    }
    do {
      return try StartTicket(copying: ticketData as Data)
    } catch {
      throw PacketTunnelProviderError.invalidStartTicket
    }
  }

  public override func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping @Sendable (Error?) -> Void
  ) {
    guard let startCoordinator else {
      completionHandler(PacketTunnelProviderError.providerUnavailable)
      return
    }
    let ticket: StartTicket
    let descriptor: ConfigurationDescriptor
    do {
      ticket = try Self.startTicket(from: options)
      descriptor = try configurationDescriptor()
    } catch {
      completionHandler(error)
      return
    }
    startCoordinator.start(
      ticket: ticket,
      descriptor: descriptor,
      completion: completionHandler
    )
  }

  public override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping @Sendable () -> Void
  ) {
    guard let startCoordinator else {
      guard let sessionLifecycle else {
        cancelTunnelWithError(PacketTunnelProviderError.providerUnavailable)
        completionHandler()
        return
      }
      sessionLifecycle.stop { [weak self] result in
        if case .failure(let error) = result {
          // NetworkExtension has a void stop completion. Preserve its required
          // callback while reporting the typed failure through the platform's
          // explicit provider-error channel.
          self?.cancelTunnelWithError(error.providerError)
        }
        completionHandler()
      }
      return
    }
    startCoordinator.stop { [weak self] result in
      if case .failure(let error) = result {
        self?.cancelTunnelWithError(error.providerError)
      }
      completionHandler()
    }
  }

  public override func handleAppMessage(
    _ messageData: Data,
    completionHandler: ((Data?) -> Void)? = nil
  ) {
    guard let completionHandler else {
      return
    }
    let completion = ProviderMessageCompletion(completionHandler)
    do {
      let request = try ProtocolCodec.decodeRequest(messageData)
      guard request.command.kind == .snapshot else {
        let response = ResponseEnvelope(
          requestID: request.requestID,
          failure: EngineFailure(
            code: "unsupported-provider-command",
            message: "The packet tunnel provider accepts snapshot requests only.",
            isRetryable: false
          )
        )
        completion.finish(try ProtocolCodec.encode(response))
        return
      }
      guard let sessionLifecycle else {
        throw PacketTunnelProviderError.providerUnavailable
      }
      sessionLifecycle.snapshot { snapshot in
        do {
          let result = try CommandResult(kind: .snapshot, snapshot: snapshot)
          completion.finish(
            try ProtocolCodec.encode(
              ResponseEnvelope(requestID: request.requestID, result: result)
            )
          )
        } catch {
          Self.logger.error(
            "Failed to encode provider snapshot: \(String(describing: error), privacy: .public)"
          )
          completion.finish(nil)
        }
      }
    } catch {
      // No response is safer than fabricating a request identifier for an
      // undecodable, unauthenticated provider message.
      Self.logger.error(
        "Rejected provider message: \(String(describing: error), privacy: .public)"
      )
      completion.finish(nil)
    }
  }

  private func makeSessionDependencies() -> PacketTunnelSessionDependencies {
    PacketTunnelSessionDependencies(
      prepareConfiguration: { [weak self] descriptor, configuration, _ in
        guard let self else {
          throw PacketTunnelProviderError.providerUnavailable
        }
        guard try configurationDescriptor() == descriptor else {
          throw PacketTunnelProviderError.malformedProviderConfiguration
        }
        // The Global Authority owns the single machine-wide lease under the
        // ticket-only model, so the Provider holds no local cross-process lease.
        return PreparedTunnelConfiguration(
          descriptor: descriptor,
          configuration: configuration,
          lease: UnleasedEngineOwnership()
        )
      },
      resolveConfiguration: { template, descriptor, credentialMaterial in
        try CredentialInjector.inject(
          template: template,
          slots: descriptor.credentialSlots,
          material: credentialMaterial
        )
      },
      makePump: { [weak self] descriptor, failureHandler in
        guard let self else {
          throw PacketTunnelProviderError.providerUnavailable
        }
        guard let tunnelOptions = descriptor.tunnelOptions else {
          throw PacketTunnelProviderError.malformedProviderConfiguration
        }
        return try PacketPump(
          packetFlow: NetworkExtensionPacketFlowClient(packetFlow: packetFlow),
          maximumPacketBytes: Int(tunnelOptions.mtu),
          failureHandler: failureHandler
        )
      },
      applyNetworkSettings: { [weak self] descriptor, completion in
        guard let self else {
          completion(PacketTunnelProviderError.providerUnavailable)
          return
        }
        setTunnelNetworkSettings(
          Self.networkSettings(descriptor: descriptor),
          completionHandler: completion
        )
      },
      recordAcceptance: { _ in
        // Replay protection is enforced by the Global Authority's single-use ticket
        // redemption. The Provider no longer keeps a local acceptance cursor.
      }
    )
  }

  private func configurationDescriptor() throws -> ConfigurationDescriptor {
    guard
      let values = (protocolConfiguration as? NETunnelProviderProtocol)?
        .providerConfiguration,
      let schemaVersionValue = values["schemaVersion"] as? String,
      let schemaVersion = UInt16(schemaVersionValue),
      schemaVersion == NativeProtocolConstants.schemaVersion,
      let slotValue = values["slot"] as? String,
      let slot = ConfigurationSlot(rawValue: slotValue),
      let tunnelOptions = try decodeTunnelOptions(values, slot: slot),
      let installationIDValue = values["installationID"] as? String,
      let installationID = UUID(uuidString: installationIDValue),
      installationIDValue == installationID.uuidString.lowercased(),
      let credentialProfileIDValue = values["credentialProfileID"] as? String,
      let credentialProfileID = UUID(uuidString: credentialProfileIDValue),
      credentialProfileIDValue == credentialProfileID.uuidString.lowercased(),
      let credentialProfileDigestValue = values["credentialProfileDigest"] as? String,
      let epochValue = values["epoch"] as? String,
      let epoch = UInt64(epochValue),
      let generationValue = values["generation"] as? String,
      let generation = UInt64(generationValue),
      let byteCountValue = values["byteCount"] as? String,
      let byteCount = UInt64(byteCountValue),
      let digestValue = values["sha256"] as? String,
      let identityDigestValue = values["identitySha256"] as? String,
      let credentialSlotsData = values["credentialSlots"] as? Data,
      let credentialSlots = try? JSONDecoder().decode(
        [CredentialSlot].self,
        from: credentialSlotsData
      )
    else {
      throw PacketTunnelProviderError.malformedProviderConfiguration
    }
    do {
      return try ConfigurationDescriptor(
        slot: slot,
        tunnelOptions: tunnelOptions,
        credentialAudience: CredentialAudience(
          profileID: credentialProfileID,
          profileDigest: try SHA256Digest(hex: credentialProfileDigestValue)
        ),
        installationID: installationID,
        epoch: epoch,
        generation: generation,
        byteCount: byteCount,
        sha256: SHA256Digest(hex: digestValue),
        identitySHA256: SHA256Digest(hex: identityDigestValue),
        credentialSlots: credentialSlots
      )
    } catch {
      throw PacketTunnelProviderError.malformedProviderConfiguration
    }
  }

  private func decodeTunnelOptions(
    _ values: [String: Any],
    slot: ConfigurationSlot
  ) throws -> TunnelNetworkOptions? {
    guard slot == .tunnel,
      let ipv6Value = values["ipv6Enabled"] as? String,
      let bypassPrivateNetworksValue = values["bypassPrivateNetworks"] as? String,
      let directIPv4Hosts = values["directIPv4Hosts"] as? [String],
      let mtuValue = values["mtu"] as? String,
      let mtu = UInt16(mtuValue)
    else {
      throw PacketTunnelProviderError.malformedProviderConfiguration
    }
    let ipv6Enabled: Bool
    switch ipv6Value {
    case "true":
      ipv6Enabled = true
    case "false":
      ipv6Enabled = false
    default:
      throw PacketTunnelProviderError.malformedProviderConfiguration
    }
    let bypassPrivateNetworks: Bool
    switch bypassPrivateNetworksValue {
    case "true":
      bypassPrivateNetworks = true
    case "false":
      bypassPrivateNetworks = false
    default:
      throw PacketTunnelProviderError.malformedProviderConfiguration
    }
    return try TunnelNetworkOptions(
      ipv6Enabled: ipv6Enabled,
      bypassPrivateNetworks: bypassPrivateNetworks,
      directIPv4Hosts: directIPv4Hosts,
      mtu: mtu
    )
  }

  static func networkSettings(
    descriptor: ConfigurationDescriptor
  ) -> NEPacketTunnelNetworkSettings {
    guard let tunnelOptions = descriptor.tunnelOptions else {
      preconditionFailure("Tunnel descriptor must contain network options")
    }
    let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

    let ipv4 = NEIPv4Settings(
      addresses: [TunnelAddressPlan.ipv4Address],
      subnetMasks: [TunnelAddressPlan.ipv4SubnetMask]
    )
    ipv4.includedRoutes = [.default()]
    var excludedIPv4Routes: [NEIPv4Route] = []
    if tunnelOptions.bypassPrivateNetworks {
      excludedIPv4Routes = [
        NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
        NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
        NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
        NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
        NEIPv4Route(destinationAddress: "169.254.0.0", subnetMask: "255.255.0.0"),
        NEIPv4Route(destinationAddress: "224.0.0.0", subnetMask: "240.0.0.0"),
        NEIPv4Route(destinationAddress: "255.255.255.255", subnetMask: "255.255.255.255"),
      ]
    }
    excludedIPv4Routes.append(
      contentsOf: tunnelOptions.directIPv4Hosts.map {
        NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255")
      }
    )
    if !excludedIPv4Routes.isEmpty {
      ipv4.excludedRoutes = excludedIPv4Routes
    }
    settings.ipv4Settings = ipv4

    if tunnelOptions.ipv6Enabled {
      let ipv6 = NEIPv6Settings(
        addresses: [TunnelAddressPlan.ipv6Address],
        networkPrefixLengths: [NSNumber(value: TunnelAddressPlan.ipv6PrefixLength)]
      )
      ipv6.includedRoutes = [.default()]
      if tunnelOptions.bypassPrivateNetworks {
        ipv6.excludedRoutes = [
          NEIPv6Route(destinationAddress: "::1", networkPrefixLength: 128),
          NEIPv6Route(destinationAddress: "fc00::", networkPrefixLength: 7),
          NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: 10),
          NEIPv6Route(destinationAddress: "ff00::", networkPrefixLength: 8),
        ]
      }
      settings.ipv6Settings = ipv6
    }

    // These are provider-owned peers in IANA-reserved benchmark/documentation
    // ranges. libbox must service them; the provider never pins an external
    // resolver or routes DNS outside the tunnel.
    let dnsServers =
      tunnelOptions.ipv6Enabled
      ? [TunnelAddressPlan.ipv4DNSPeer, TunnelAddressPlan.ipv6DNSPeer]
      : [TunnelAddressPlan.ipv4DNSPeer]
    let dns = NEDNSSettings(servers: dnsServers)
    dns.matchDomains = [""]
    dns.matchDomainsNoSearch = true
    settings.dnsSettings = dns
    settings.mtu = NSNumber(value: tunnelOptions.mtu)
    return settings
  }
}

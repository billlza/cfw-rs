import CFWPacketTunnel
import Foundation
import NetworkExtension

// NetworkExtension exclusively owns the NEMachServiceName bootstrap endpoint.
// Host control and status use NETunnelProviderSession public APIs; this process
// must never register a second listener on the same Mach service.
autoreleasepool {
  _ = PacketTunnelProvider.self
  NEProvider.startSystemExtensionMode()
}
dispatchMain()

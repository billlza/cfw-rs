// swift-tools-version: 6.2

import PackageDescription

let package = Package(
  name: "CFMPhysicalTransportPeer",
  platforms: [
    .iOS(.v17),
    .macOS(.v15),
  ],
  products: [
    .library(name: "TransportPeerCore", targets: ["TransportPeerCore"]),
    .executable(name: "TransportPeerMacProbe", targets: ["TransportPeerMacProbe"]),
  ],
  targets: [
    .target(name: "TransportPeerCore"),
    .target(
      name: "TransportPeerMacProbeSupport",
      dependencies: ["TransportPeerCore"],
      linkerSettings: [
        .linkedFramework("Network"),
        .linkedFramework("Security"),
      ]
    ),
    .executableTarget(
      name: "TransportPeerMacProbe",
      dependencies: ["TransportPeerMacProbeSupport"]
    ),
    .testTarget(
      name: "TransportPeerCoreTests",
      dependencies: ["TransportPeerCore", "TransportPeerMacProbeSupport"]
    ),
  ]
)

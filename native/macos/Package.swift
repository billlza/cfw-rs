// swift-tools-version: 6.2

import PackageDescription

let package = Package(
  name: "CFWNative",
  platforms: [
    .macOS(.v15)
  ],
  products: [
    .library(name: "CFWSharedProtocol", targets: ["CFWSharedProtocol"]),
    .library(name: "CFWPacketTransport", targets: ["CFWPacketTransport"]),
    .library(name: "CFWAppleNetwork", targets: ["CFWAppleNetwork"]),
    .library(name: "CFWCredentialTransport", targets: ["CFWCredentialTransport"]),
    .library(name: "CFWCredentialVault", targets: ["CFWCredentialVault"]),
    .library(name: "CFWLibboxRuntime", targets: ["CFWLibboxRuntime"]),
    .library(name: "CFWPacketTunnel", targets: ["CFWPacketTunnel"]),
    .library(name: "CFWNativeBridge", targets: ["CFWNativeBridge"]),
    .executable(name: "CFWProxyAgent", targets: ["CFWProxyAgent"]),
  ],
  targets: [
    .target(
      name: "CFWSharedProtocol",
      linkerSettings: [
        .linkedFramework("CryptoKit"),
        .linkedFramework("Security"),
      ]
    ),
    .target(
      name: "CFWPacketTransport",
      dependencies: ["CFWSharedProtocol"]
    ),
    .target(
      name: "CFWAppleNetwork",
      dependencies: ["CFWSharedProtocol"]
    ),
    .target(
      name: "CFWNativeBridge",
      dependencies: [
        "CFWAppleNetwork", "CFWCredentialTransport", "CFWCredentialVault",
        "CFWSharedProtocol",
      ],
      linkerSettings: [
        .linkedFramework("Security"),
        .linkedFramework("ServiceManagement"),
      ]
    ),
    .target(
      name: "CFWCredentialTransport",
      dependencies: ["CFWSharedProtocol"]
    ),
    .target(
      name: "CFWCredentialVault",
      dependencies: ["CFWCredentialTransport", "CFWSharedProtocol"],
      linkerSettings: [
        .linkedFramework("Security")
      ]
    ),
    .target(
      name: "CFWLibboxRuntime",
      dependencies: ["CFWSharedProtocol"],
      linkerSettings: [
        .linkedFramework("Network")
      ]
    ),
    .target(
      name: "CFWPacketTunnel",
      dependencies: [
        "CFWSharedProtocol", "CFWCredentialTransport", "CFWPacketTransport",
        "CFWLibboxRuntime",
      ]
    ),
    .target(
      name: "CFWProxyAgentCore",
      dependencies: [
        "CFWSharedProtocol", "CFWCredentialTransport", "CFWCredentialVault", "CFWLibboxRuntime",
      ],
      path: "Sources/CFWProxyAgent",
      linkerSettings: [
        .linkedFramework("Security"),
        .linkedFramework("SystemConfiguration"),
      ]
    ),
    .executableTarget(
      name: "CFWProxyAgent",
      dependencies: ["CFWProxyAgentCore"],
      path: "Sources/CFWProxyAgentMain"
    ),
    .testTarget(
      name: "CFWSharedProtocolTests",
      dependencies: ["CFWSharedProtocol"]
    ),
    .testTarget(
      name: "CFWPacketTransportTests",
      dependencies: ["CFWPacketTransport"]
    ),
    .testTarget(
      name: "CFWLibboxRuntimeTests",
      dependencies: ["CFWLibboxRuntime", "CFWSharedProtocol"]
    ),
    .testTarget(
      name: "CFWPacketTunnelTests",
      dependencies: ["CFWPacketTunnel", "CFWSharedProtocol"]
    ),
    .testTarget(
      name: "CFWAppleNetworkTests",
      dependencies: ["CFWAppleNetwork", "CFWSharedProtocol"]
    ),
    .testTarget(
      name: "CFWNativeBridgeTests",
      dependencies: [
        "CFWNativeBridge", "CFWAppleNetwork", "CFWCredentialTransport", "CFWCredentialVault",
        "CFWSharedProtocol",
      ]
    ),
    .testTarget(
      name: "CFWCredentialTransportTests",
      dependencies: ["CFWCredentialTransport", "CFWSharedProtocol"]
    ),
    .testTarget(
      name: "CFWCredentialVaultTests",
      dependencies: ["CFWCredentialTransport", "CFWCredentialVault", "CFWSharedProtocol"]
    ),
    .testTarget(
      name: "CFWProxyAgentTests",
      dependencies: ["CFWProxyAgentCore", "CFWSharedProtocol"]
    ),
  ],
  swiftLanguageModes: [.v6]
)

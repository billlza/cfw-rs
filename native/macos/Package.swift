// swift-tools-version: 6.2

import PackageDescription

let package = Package(
  name: "CFWNative",
  platforms: [
    .macOS(.v15)
  ],
  products: [
    .library(name: "CFWSharedProtocol", targets: ["CFWSharedProtocol"]),
    .library(name: "CFWGlobalAuthority", targets: ["CFWGlobalAuthority"]),
    .library(name: "CFWPacketTransport", targets: ["CFWPacketTransport"]),
    .library(name: "CFWAppleNetwork", targets: ["CFWAppleNetwork"]),
    .library(name: "CFWCredentialTransport", targets: ["CFWCredentialTransport"]),
    .library(name: "CFWCredentialVault", targets: ["CFWCredentialVault"]),
    .library(name: "CFWLibboxRuntime", targets: ["CFWLibboxRuntime"]),
    .library(name: "CFWPacketTunnel", targets: ["CFWPacketTunnel"]),
    .library(name: "CFWNativeBridge", targets: ["CFWNativeBridge"]),
    .executable(name: "CFWGlobalAuthorityDaemon", targets: ["CFWGlobalAuthorityDaemon"]),
    .executable(name: "CFWAdversarialProbe", targets: ["CFWAdversarialProbe"]),
    .executable(
      name: "CFWAdversarialAuthorityOperationReplayController",
      targets: ["CFWAdversarialAuthorityOperationReplayController"]),
    .executable(
      name: "CFWAdversarialBoundedAuthorityLoadController",
      targets: ["CFWAdversarialBoundedAuthorityLoadController"]),
    .executable(
      name: "CFWAdversarialFastUserSwitchController",
      targets: ["CFWAdversarialFastUserSwitchController"]),
    .executable(
      name: "CFWAdversarialIsolatedAuditSessionController",
      targets: ["CFWAdversarialIsolatedAuditSessionController"]),
    .executable(
      name: "CFWAdversarialIsolatedConsoleSessionController",
      targets: ["CFWAdversarialIsolatedConsoleSessionController"]),
    .executable(
      name: "CFWAdversarialPidReuseWindowController",
      targets: ["CFWAdversarialPidReuseWindowController"]),
    .executable(
      name: "CFWAdversarialRootOwnedAuthorityJournalSnapshot",
      targets: ["CFWAdversarialRootOwnedAuthorityJournalSnapshot"]),
    .executable(
      name: "CFWAdversarialRootOwnedSecretCanaryScanner",
      targets: ["CFWAdversarialRootOwnedSecretCanaryScanner"]),
    .executable(
      name: "CFWAdversarialRootOwnedUidLauncher",
      targets: ["CFWAdversarialRootOwnedUidLauncher"]),
    .executable(
      name: "CFWAdversarialSignedOwnerLivenessController",
      targets: ["CFWAdversarialSignedOwnerLivenessController"]),
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
      name: "CFWGlobalAuthority",
      dependencies: ["CFWSharedProtocol"],
      linkerSettings: [
        .linkedFramework("CryptoKit"),
        .linkedFramework("Security"),
        .linkedFramework("SystemConfiguration"),
      ]
    ),
    .executableTarget(
      name: "CFWGlobalAuthorityDaemon",
      dependencies: ["CFWGlobalAuthority"],
      path: "Sources/CFWGlobalAuthorityMain"
    ),
    .executableTarget(
      name: "CFWAdversarialProbe",
      dependencies: ["CFWSharedProtocol"],
      path: "PhysicalFixtures/CFWAdversarialProbe",
      linkerSettings: [
        .linkedFramework("CryptoKit"),
        .linkedFramework("Security"),
      ]
    ),
    .target(
      name: "CFWAdversarialFixtureSupport",
      dependencies: ["CFWSharedProtocol"],
      path: "PhysicalFixtures/CFWAdversarialFixtureSupport",
      linkerSettings: [
        .linkedFramework("CryptoKit"),
        .linkedFramework("Security"),
        .linkedFramework("SystemConfiguration"),
      ]
    ),
    .executableTarget(
      name: "CFWAdversarialAuthorityOperationReplayController",
      dependencies: ["CFWAdversarialFixtureSupport"],
      path: "PhysicalFixtures/CFWAdversarialAuthorityOperationReplayController"
    ),
    .executableTarget(
      name: "CFWAdversarialBoundedAuthorityLoadController",
      dependencies: ["CFWAdversarialFixtureSupport"],
      path: "PhysicalFixtures/CFWAdversarialBoundedAuthorityLoadController"
    ),
    .executableTarget(
      name: "CFWAdversarialFastUserSwitchController",
      dependencies: ["CFWAdversarialFixtureSupport"],
      path: "PhysicalFixtures/CFWAdversarialFastUserSwitchController"
    ),
    .executableTarget(
      name: "CFWAdversarialIsolatedAuditSessionController",
      dependencies: ["CFWAdversarialFixtureSupport"],
      path: "PhysicalFixtures/CFWAdversarialIsolatedAuditSessionController"
    ),
    .executableTarget(
      name: "CFWAdversarialIsolatedConsoleSessionController",
      dependencies: ["CFWAdversarialFixtureSupport"],
      path: "PhysicalFixtures/CFWAdversarialIsolatedConsoleSessionController"
    ),
    .executableTarget(
      name: "CFWAdversarialPidReuseWindowController",
      dependencies: ["CFWAdversarialFixtureSupport"],
      path: "PhysicalFixtures/CFWAdversarialPidReuseWindowController"
    ),
    .executableTarget(
      name: "CFWAdversarialRootOwnedAuthorityJournalSnapshot",
      dependencies: ["CFWAdversarialFixtureSupport"],
      path: "PhysicalFixtures/CFWAdversarialRootOwnedAuthorityJournalSnapshot"
    ),
    .executableTarget(
      name: "CFWAdversarialRootOwnedSecretCanaryScanner",
      dependencies: ["CFWAdversarialFixtureSupport"],
      path: "PhysicalFixtures/CFWAdversarialRootOwnedSecretCanaryScanner"
    ),
    .executableTarget(
      name: "CFWAdversarialRootOwnedUidLauncher",
      dependencies: ["CFWAdversarialFixtureSupport"],
      path: "PhysicalFixtures/CFWAdversarialRootOwnedUidLauncher"
    ),
    .executableTarget(
      name: "CFWAdversarialSignedOwnerLivenessController",
      dependencies: ["CFWAdversarialFixtureSupport"],
      path: "PhysicalFixtures/CFWAdversarialSignedOwnerLivenessController"
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
      name: "CFWGlobalAuthorityTests",
      dependencies: ["CFWGlobalAuthority", "CFWSharedProtocol"]
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
    .testTarget(
      name: "CFWAdversarialFixtureSupportTests",
      dependencies: ["CFWAdversarialFixtureSupport", "CFWSharedProtocol"]
    ),
  ],
  swiftLanguageModes: [.v6]
)

// swift-tools-version: 6.2
import PackageDescription

let package = Package(
  name: "CFMNativeDashboard",
  defaultLocalization: "en",
  platforms: [.macOS(.v15)],
  products: [.library(name: "CFMNativeDashboard", type: .dynamic, targets: ["CFMNativeDashboard"])],
  targets: [
    .target(name: "CFMNativeDashboard", resources: [.process("Resources")]),
    .testTarget(
      name: "CFMNativeDashboardTests", dependencies: ["CFMNativeDashboard"],
      resources: [.copy("Fixtures")]),
  ]
)

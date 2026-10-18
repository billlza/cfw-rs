import Foundation
import UIKit

@main
@MainActor
final class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?
  private var runtime: PeerRuntime?
  private var packetLanRuntime: PacketLanPeerRuntime?
  private var primerRuntime: LocalNetworkPrimerRuntime?
  private let statusLabel = UILabel()

  func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    let window = UIWindow(frame: UIScreen.main.bounds)
    let controller = UIViewController()
    controller.view.backgroundColor = .systemBackground
    statusLabel.translatesAutoresizingMaskIntoConstraints = false
    statusLabel.font = .monospacedSystemFont(ofSize: 16, weight: .regular)
    statusLabel.numberOfLines = 0
    statusLabel.textAlignment = .center
    statusLabel.text = "Starting test-only transport peer…"
    controller.view.addSubview(statusLabel)
    NSLayoutConstraint.activate([
      statusLabel.leadingAnchor.constraint(
        equalTo: controller.view.layoutMarginsGuide.leadingAnchor),
      statusLabel.trailingAnchor.constraint(
        equalTo: controller.view.layoutMarginsGuide.trailingAnchor),
      statusLabel.centerYAnchor.constraint(equalTo: controller.view.centerYAnchor),
    ])
    window.rootViewController = controller
    window.makeKeyAndVisible()
    self.window = window

    var failureTitle = "CFM transport peer"
    do {
      let mode = try PeerLaunchMode.parse(
        arguments: Array(ProcessInfo.processInfo.arguments.dropFirst())
      )
      guard Bundle.main.bundleIdentifier == PeerContract.bundleIdentifier else {
        throw PeerContractError.identityMismatch("bundle identifier")
      }
      switch mode {
      case .primer:
        failureTitle = "CFM local-network primer"
        let primer = LocalNetworkPrimerRuntime(
          paths: try LocalNetworkPrimerPaths.applicationDocuments(),
          processID: ProcessInfo.processInfo.processIdentifier
        ) { [weak self] state in
          self?.statusLabel.text = "CFM local-network primer\n\(state)"
        }
        primerRuntime = primer
        try primer.start()
      case .session:
        failureTitle = "CFM physical transport peer"
        let now = Date()
        _ = try LocalNetworkPrimerPaths.applicationDocuments().loadFreshResult(now: now)
        let paths = try PeerPaths.applicationDocuments()
        try paths.validateCleanInputs()
        let session = try paths.loadSession(now: now)
        let identity = try PeerIdentity(paths: paths, session: session)
        let runtime = PeerRuntime(
          session: session,
          paths: paths,
          identity: identity,
          processID: ProcessInfo.processInfo.processIdentifier
        ) { [weak self] state in
          self?.statusLabel.text = "CFM physical transport peer\n\(state)"
        }
        self.runtime = runtime
        try runtime.start(now: now)
      case .packetLan:
        failureTitle = "CFM packet LAN peer"
        let now = Date()
        _ = try LocalNetworkPrimerPaths.applicationDocuments().loadFreshResult(now: now)
        let paths = try PacketLanPeerPaths.applicationDocuments()
        try paths.prepareCopiedInputs()
        let session = try paths.loadSessionAndRemove(now: now)
        let runtime = PacketLanPeerRuntime(
          session: session,
          paths: paths,
          processID: ProcessInfo.processInfo.processIdentifier
        ) { [weak self] state in
          self?.statusLabel.text = "CFM packet LAN peer\n\(state)"
        }
        packetLanRuntime = runtime
        try runtime.start(now: now)
      }
    } catch {
      statusLabel.text = "\(failureTitle)\nfailed: \(error.localizedDescription)"
      primerRuntime?.stop()
      primerRuntime = nil
      runtime?.stop(failurePhase: .applicationLifecycle)
      runtime = nil
      packetLanRuntime?.stop()
      packetLanRuntime = nil
    }
    return true
  }

  func applicationDidEnterBackground(_ application: UIApplication) {
    primerRuntime?.stop()
    runtime?.stop(failurePhase: .applicationLifecycle)
    packetLanRuntime?.stop()
  }

  func applicationWillTerminate(_ application: UIApplication) {
    primerRuntime?.stop()
    runtime?.stop(failurePhase: .applicationLifecycle)
    packetLanRuntime?.stop()
  }
}

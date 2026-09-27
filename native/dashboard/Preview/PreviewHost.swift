import AppKit
import Foundation

// This process loads only the production presentation library. It has no Rust
// coordinator, production storage, native network bridge or service credentials.
@MainActor private var closeCount = 0
@MainActor private var commandCount = 0

private let didClose: @convention(c) (UInt) -> Void = { _ in
  MainActor.assumeIsolated { closeCount += 1 }
}
private let rejectControl: @convention(c) (UInt, UInt64, UInt64, UInt64, UInt32, UInt8) -> Int32 = {
  _, _, _, _, _, _ in
  MainActor.assumeIsolated { commandCount += 1 }
  return 0
}

@MainActor
private final class PreviewHost: NSObject, NSApplicationDelegate {
  private var revision: UInt64 = 0
  private var locale = "zh-Hans"
  private var scenario = 0
  private var noticeAttached = false
  private let selfCheck = CommandLine.arguments.contains("--self-check")
  private let scenarios = ["未接入网络服务", "示例：已停止", "示例：已连接", "示例：等待授权", "示例：连接失败"]

  func applicationDidFinishLaunching(_ notification: Notification) {
    do {
      try validateResources()
      installMenus()
      try present()
      if selfCheck {
        try verifyPackagedPresentation()
        return
      }
      NSApp.activate()
    } catch {
      fail(error)
    }
  }

  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    !selfCheck
  }

  private func validateResources() throws {
    guard
      let bundleURL = Bundle.main.url(
        forResource: "CFMNativeDashboard_CFMNativeDashboard", withExtension: "bundle")
    else { throw PreviewError.invalid("缺少应用内的界面资源。") }
    for language in ["en", "zh-Hans", "zh-Hant", "ja"] {
      guard let bundle = Bundle(url: bundleURL),
        let resource = bundle.url(
          forResource: "Localizable", withExtension: "strings", subdirectory: nil,
          localization: language),
        let strings = try PropertyListSerialization.propertyList(
          from: Data(contentsOf: resource), options: [], format: nil) as? [String: String],
        strings["overview"] != nil, strings["approvalHelp"] != nil
      else { throw PreviewError.invalid("缺少 \(language) 本地化资源。") }
    }
  }

  private func frame() throws -> Data {
    let unavailable: [String: String] = [
      "en": "UI preview: network controls are disabled.",
      "zh-Hans": "界面预览：不执行网络操作。",
      "zh-Hant": "介面預覽：不執行網路操作。",
      "ja": "UI プレビュー：ネットワーク操作は無効です。",
    ]
    let disconnected: [String: String] = [
      "en":
        "This preview is not connected to network services. The status menu shows explicitly labelled examples, not this Mac's VPN state.",
      "zh-Hans": "此预览未接入网络服务。可在“预览状态”菜单切换界面示例；它们不反映本机 VPN 状态。",
      "zh-Hant": "此預覽未接入網路服務。可在「預覽狀態」選單切換介面範例；它們不反映本機 VPN 狀態。",
      "ja": "ネットワークサービスには接続していません。状態メニューの例は、この Mac の VPN 状態ではありません。",
    ]
    guard let reason = unavailable[locale], let notice = disconnected[locale] else {
      throw PreviewError.invalid("Unsupported preview locale: \(locale)")
    }
    let isActive = scenario == 2
    let wantsTunnel = isActive || scenario == 3
    let status =
      scenario == 1 ? "inactive" : isActive ? "active" : scenario == 3 ? "pending" : "unknown"
    let phase = scenario == 1 ? "off" : isActive ? "active" : scenario == 3 ? "approval" : "failed"
    let switchValue: (Bool) -> [String: Any] = { enabled in
      ["enabled": enabled, "available": false, "retry": false, "reason": reason]
    }
    let object: [String: Any] = [
      "version": 2, "sequence": revision, "session": 1, "locale": locale,
      "phase": phase, "core": status, "systemProxy": isActive ? "inactive" : status,
      "tunnel": status, "failure": phase == "failed" ? notice : NSNull(),
      "controls": [
        "core": switchValue(wantsTunnel), "systemProxy": switchValue(false),
        "tunnel": switchValue(wantsTunnel),
      ],
      "command": NSNull(),
    ]
    return try JSONSerialization.data(withJSONObject: object)
  }

  private func present() throws {
    revision += 1
    let payload = try frame()
    let result = payload.withUnsafeBytes { bytes in
      cfm_dashboard_present_v2(
        bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, didClose, rejectControl, 1)
    }
    guard result == 1 else { throw PreviewError.invalid("原生窗口启动失败：\(result)") }
    labelWindow()
  }

  private func publish() throws {
    revision += 1
    let payload = try frame()
    let result = payload.withUnsafeBytes { bytes in
      cfm_dashboard_publish_v2(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
    }
    guard result == 1 else { throw PreviewError.invalid("界面更新失败：\(result)") }
    labelWindow()
  }

  private func labelWindow() {
    for window in NSApp.windows where window.isVisible {
      window.title = "Clash for Mac 0.5 · 界面预览"
      window.subtitle = "示例展示 · 不接管本机 VPN · \(scenarios[scenario])"
      window.setFrameAutosaveName("CFM050UIPreview")
      // SwiftUI owns the navigation title and may replace NSWindow.subtitle.
      // An AppKit accessory keeps the example-data notice visible in every state.
      if !noticeAttached {
        let accessory = NSTitlebarAccessoryViewController()
        accessory.layoutAttribute = .bottom
        accessory.view = NSView(frame: NSRect(x: 0, y: 0, width: 850, height: 30))
        let notice = NSTextField(labelWithString: "界面预览 · 示例数据 · 不代表本机 VPN 状态")
        notice.font = .systemFont(ofSize: 12, weight: .medium)
        notice.textColor = .secondaryLabelColor
        notice.translatesAutoresizingMaskIntoConstraints = false
        accessory.view.addSubview(notice)
        NSLayoutConstraint.activate([
          notice.centerXAnchor.constraint(equalTo: accessory.view.centerXAnchor),
          notice.centerYAnchor.constraint(equalTo: accessory.view.centerYAnchor),
        ])
        window.addTitlebarAccessoryViewController(accessory)
        noticeAttached = true
      }
    }
  }

  private func installMenus() {
    let main = NSMenu()
    let appMenu = NSMenu()
    appMenu.addItem(withTitle: "关于界面预览", action: #selector(about), keyEquivalent: "")
    appMenu.addItem(.separator())
    appMenu.addItem(
      withTitle: "退出界面预览", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    attach(appMenu, title: "CFM 0.5 Preview", to: main)
    let states = NSMenu()
    for (index, title) in scenarios.enumerated() {
      let item = NSMenuItem(title: title, action: #selector(selectScenario(_:)), keyEquivalent: "")
      item.tag = index
      item.target = self
      states.addItem(item)
    }
    attach(states, title: "预览状态", to: main)
    let languages = NSMenu()
    for (title, value) in [
      ("简体中文", "zh-Hans"), ("繁體中文", "zh-Hant"), ("English", "en"), ("日本語", "ja"),
    ] {
      let item = NSMenuItem(title: title, action: #selector(selectLocale(_:)), keyEquivalent: "")
      item.representedObject = value
      item.target = self
      languages.addItem(item)
    }
    attach(languages, title: "语言", to: main)
    let appearances = NSMenu()
    for (index, title) in ["跟随系统", "浅色", "深色"].enumerated() {
      let item = NSMenuItem(
        title: title, action: #selector(selectAppearance(_:)), keyEquivalent: "")
      item.tag = index
      item.target = self
      appearances.addItem(item)
    }
    attach(appearances, title: "外观", to: main)
    NSApp.mainMenu = main
  }

  private func attach(_ menu: NSMenu, title: String, to main: NSMenu) {
    let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
    item.submenu = menu
    main.addItem(item)
  }

  @objc private func selectScenario(_ item: NSMenuItem) {
    guard scenarios.indices.contains(item.tag) else { return }
    scenario = item.tag
    do { try publish() } catch { fail(error) }
  }

  @objc private func selectLocale(_ item: NSMenuItem) {
    guard let language = item.representedObject as? String,
      ["en", "zh-Hans", "zh-Hant", "ja"].contains(language)
    else { return }
    locale = language
    do { try publish() } catch { fail(error) }
  }

  @objc private func selectAppearance(_ item: NSMenuItem) {
    NSApp.appearance =
      item.tag == 1
      ? NSAppearance(named: .aqua) : item.tag == 2 ? NSAppearance(named: .darkAqua) : nil
  }

  @objc private func about() {
    let alert = NSAlert()
    alert.messageText = "Clash for Mac 0.5 界面预览"
    alert.informativeText =
      "复用开发中的 SwiftUI 总览与 Liquid Glass 控件。仅展示界面，网络开关禁用；不读取正式版配置、节点或凭据，也不会替换正在使用的 0.4。完整 0.5 客户端仍在开发。"
    alert.runModal()
  }

  private func verifyPackagedPresentation() throws {
    for language in ["en", "zh-Hans", "zh-Hant", "ja"] {
      locale = language
      for index in scenarios.indices {
        scenario = index
        try publish()
        guard cfm_dashboard_request_v2(1, 1, 1) == 0 else {
          throw PreviewError.invalid("预览意外接受了网络请求。")
        }
      }
    }
    // SwiftUI attaches the toolbar on the AppKit run loop, after initial layout.
    let layoutDeadline = Date(timeIntervalSinceNow: 1)
    while !NSApp.windows.contains(where: { $0.toolbar != nil }) && Date() < layoutDeadline {
      RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
    }
    guard noticeAttached,
      NSApp.windows.contains(where: { !$0.titlebarAccessoryViewControllers.isEmpty })
    else {
      throw PreviewError.invalid("The persistent preview notice is missing.")
    }
    guard commandCount == 0 else {
      throw PreviewError.invalid("Preview controls reached their callback \(commandCount) times.")
    }
    guard NSApp.windows.contains(where: { $0.toolbar != nil }) else {
      throw PreviewError.invalid(
        "The actual native toolbar did not attach within the layout bound.")
    }
    let closed = cfm_dashboard_close_v2(1)
    guard closed == 1, closeCount == 1 else {
      throw PreviewError.invalid("Window close status=\(closed), callbacks=\(closeCount).")
    }
    print(
      "PREVIEW_SELF_CHECK_OK: 20 localized example states; controls disabled; native toolbar; one close; bundled resources."
    )
    NSApp.terminate(nil)
  }

  private func fail(_ error: Error) {
    if selfCheck {
      FileHandle.standardError.write(Data("\(error)\n".utf8))
      exit(1)
    }
    let alert = NSAlert()
    alert.messageText = "无法打开界面预览"
    alert.informativeText = String(describing: error)
    alert.runModal()
    NSApp.terminate(nil)
  }
}

private enum PreviewError: Error {
  case invalid(String)
}

@main
private enum PreviewApplication {
  @MainActor static func main() {
    let application = NSApplication.shared
    let delegate = PreviewHost()
    application.setActivationPolicy(
      CommandLine.arguments.contains("--self-check") ? .prohibited : .regular)
    application.delegate = delegate
    withExtendedLifetime(delegate) { application.run() }
  }
}

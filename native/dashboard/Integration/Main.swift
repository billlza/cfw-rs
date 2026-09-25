import AppKit
import Foundation
import WebKit

@MainActor private final class Completion {
  weak var host: IntegrationHost?
  let requestID: String
  let channel: Int
  let session: UInt64
  let epoch: UInt64
  let kind: String
  var index = 0
  init(host: IntegrationHost, requestID: String, channel: Int, session: UInt64, kind: String) {
    self.host = host
    self.requestID = requestID
    self.channel = channel
    self.session = session
    epoch = host.epoch
    self.kind = kind
  }
  func send(_ result: [String: Any], end: Bool) {
    guard let host, host.epoch == epoch else { return }
    let packet: [String: Any] = ["index": index, "message": result]
    index += 1
    host.deliver(
      channel: channel, packets: end ? [packet, ["index": index, "end": true]] : [packet])
    host.record("channel", ["kind": kind, "session": session, "index": index, "end": end])
  }
}

private let profileClosed: CFMProfileMenuCallback = { context, session, action in
  guard let pointer = UnsafeRawPointer(bitPattern: context) else { return }
  let completion = Unmanaged<Completion>.fromOpaque(pointer).takeRetainedValue()
  MainActor.assumeIsolated {
    guard completion.session == session else { return }
    let actions = [
      "select", "edit", "edit-external", "update", "reveal", "outbounds", "route", "copy", "qrcode",
      "credentials", "settings", "delete",
    ]
    let selected: Any = action > 0 && action <= actions.count ? actions[Int(action) - 1] : NSNull()
    completion.host?.completions.removeValue(forKey: completion.requestID)
    completion.send(
      ["requestId": completion.requestID, "action": selected, "error": NSNull()], end: true)
  }
}

private let runtimeEvent: CFMRuntimeSettingsEvent = { context, session, bytes, count in
  guard let pointer = UnsafeRawPointer(bitPattern: context), let bytes, count > 0, count <= 16_384
  else { return 0 }
  let completion = Unmanaged<Completion>.fromOpaque(pointer).takeUnretainedValue()
  let data = Data(bytes: bytes, count: count)
  return MainActor.assumeIsolated {
    guard completion.session == session, let host = completion.host, host.epoch == completion.epoch,
      let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
      value["action"] as? String == "submit", let submission = value["submissionId"],
      let draft = value["draft"]
    else { return 0 }
    completion.send(
      [
        "requestId": completion.requestID, "kind": "submit", "submissionId": submission,
        "draft": draft,
      ], end: false)
    host.record("runtime_submit", ["session": session, "submissionId": submission])
    return 1
  }
}

private let runtimeClosed: CFMRuntimeSettingsClosed = { context, session in
  guard let pointer = UnsafeRawPointer(bitPattern: context) else { return }
  let completion = Unmanaged<Completion>.fromOpaque(pointer).takeRetainedValue()
  MainActor.assumeIsolated {
    guard completion.session == session else { return }
    completion.host?.completions.removeValue(forKey: completion.requestID)
    completion.send(["requestId": completion.requestID, "kind": "closed"], end: true)
  }
}

private let generalInput: CFMGeneralSwitchInput = {
  context, session, sequence, submission, key, action, value in
  guard let pointer = UnsafeRawPointer(bitPattern: context) else { return 0 }
  let completion = Unmanaged<Completion>.fromOpaque(pointer).takeUnretainedValue()
  return MainActor.assumeIsolated {
    guard completion.session == session, let host = completion.host, host.epoch == completion.epoch
    else { return 0 }
    completion.send(
      [
        "kind": "input", "requestId": completion.requestID, "sequence": sequence,
        "submission": submission, "key": key, "action": action, "value": value == 1,
      ], end: false)
    host.record(
      "general_input",
      [
        "session": session, "sequence": sequence, "submission": submission,
        "key": key, "action": action, "value": value == 1,
      ])
    return 1
  }
}

private let generalClosed: CFMGeneralSwitchClosed = { context in
  guard let pointer = UnsafeRawPointer(bitPattern: context) else { return }
  let completion = Unmanaged<Completion>.fromOpaque(pointer).takeRetainedValue()
  MainActor.assumeIsolated {
    completion.host?.completions.removeValue(forKey: completion.requestID)
    completion.send(["kind": "closed", "requestId": completion.requestID], end: true)
  }
}

@MainActor
private final class IntegrationHost: NSObject, NSApplicationDelegate, NSWindowDelegate,
  WKScriptMessageHandlerWithReply, WKNavigationDelegate
{
  var window: NSWindow?
  var web: WKWebView?
  var completions: [String: Completion] = [:]
  var epoch: UInt64 = 0
  private var nextSession: UInt64 = 1
  private var nextListener = 1
  private var runtimeRevision = 0
  private var currentPage = "general"
  private var observations = 0
  private var appKitDiagnosticCount = 0
  private var generalFrameCount = 0
  private var appKitEventMonitor: Any?
  private var appKitObservers: [NSObjectProtocol] = []
  private var fixtures: [String: Any] = [:]
  private let output: URL
  private let journal: FileHandle
  private var resourceRoot: URL { Bundle.main.resourceURL!.appendingPathComponent("ui") }

  override init() {
    // The test app lives exclusively under target/050-completion/<run>/.
    output = Bundle.main.bundleURL.deletingLastPathComponent()
    let log = output.appendingPathComponent("intents.jsonl")
    FileManager.default.createFile(atPath: log.path, contents: nil)
    do { journal = try FileHandle(forWritingTo: log) } catch {
      fatalError("Cannot open component test journal: \(error)")
    }
    super.init()
  }

  func record(_ event: String, _ fields: [String: Any] = [:]) {
    do {
      var value = fields
      value["event"] = event
      value["test_data"] = true
      value["time"] = ISO8601DateFormatter().string(from: Date())
      var data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
      data.append(10)
      try journal.write(contentsOf: data)
    } catch { FileHandle.standardError.write(Data("Test journal failure: \(error)\n".utf8)) }
  }

  func applicationDidFinishLaunching(_ notification: Notification) {
    buildMenu()
    Task { @MainActor in
      do { try await start() } catch {
        record("startup_failure", ["error": String(describing: error)])
        NSApp.terminate(nil)
      }
    }
  }

  private func start() async throws {
    guard let resources = Bundle.main.resourceURL else { throw Failure("Test resources missing") }
    fixtures = try object(Data(contentsOf: resources.appendingPathComponent("fixtures.json")))
    let script = try String(
      contentsOf: resources.appendingPathComponent("bridge.js"), encoding: .utf8)
    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .nonPersistent()
    configuration.userContentController.addUserScript(
      WKUserScript(source: script, injectionTime: .atDocumentStart, forMainFrameOnly: true))
    configuration.userContentController.addScriptMessageHandler(
      self, contentWorld: .page, name: "cfmIntegration")
    let rules =
      #"[{"trigger":{"url-filter":"^http"},"action":{"type":"block"}},{"trigger":{"url-filter":"^ws"},"action":{"type":"block"}}]"#
    let rulesDirectory = output.appendingPathComponent("content-rules")
    try FileManager.default.createDirectory(at: rulesDirectory, withIntermediateDirectories: true)
    let blocker = try await WKContentRuleListStore(url: rulesDirectory).compileContentRuleList(
      forIdentifier: "CFMComponentIntegrationNoNetwork", encodedContentRuleList: rules)
    guard let blocker else { throw Failure("Could not compile mandatory test network block") }
    configuration.userContentController.add(blocker)
    let web = WKWebView(
      frame: NSRect(x: 0, y: 0, width: 850, height: 603), configuration: configuration)
    web.navigationDelegate = self
    self.web = web
    let window = NSWindow(
      contentRect: web.frame, styleMask: [.titled, .closable, .miniaturizable, .resizable],
      backing: .buffered, defer: false)
    window.title = "CFM Component Integration Test — TEST DATA"
    window.isReleasedWhenClosed = false
    window.contentMinSize = NSSize(width: 850, height: 603)
    window.contentView = web
    window.delegate = self
    self.window = window
    installAppKitDiagnostics()
    window.center()
    window.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: false)
    web.loadFileURL(
      resourceRoot.appendingPathComponent("index.html"), allowingReadAccessTo: resourceRoot)
    record(
      "started",
      [
        "pid": ProcessInfo.processInfo.processIdentifier, "bundle": Bundle.main.bundleURL.path,
        "network": "blocked", "production_host": false,
      ])
    let receipt: [String: Any] = [
      "pid": ProcessInfo.processInfo.processIdentifier, "bundle": Bundle.main.bundleURL.path,
      "windowNumber": window.windowNumber,
      "scope": "TEST DATA: existing frontend + actual native component ABI only",
      "production_tauri_or_rust": false, "network_or_vpn_acceptance": false,
    ]
    try JSONSerialization.data(withJSONObject: receipt, options: [.prettyPrinted, .sortedKeys])
      .write(to: output.appendingPathComponent("running.json"))
  }

  /// These are process-local AppKit events and notifications. Never inspect
  /// another application's windows, event text, field values, or accessibility.
  private func installAppKitDiagnostics() {
    appKitEventMonitor = NSEvent.addLocalMonitorForEvents(matching: [
      .leftMouseDown, .rightMouseDown, .otherMouseDown, .keyDown,
    ]) { [weak self] event in
      MainActor.assumeIsolated {
        self?.recordAppKitState(
          "local_event", observedWindow: event.window,
          details: [
            "eventType": String(describing: event.type), "eventWindowNumber": event.windowNumber,
            "keyCode": event.type == .keyDown ? Int(event.keyCode) : -1,
          ])
      }
      // Deliberately return the same event instance in every case.
      return event
    }
    let names: [Notification.Name] = [
      NSWindow.didBecomeKeyNotification, NSWindow.didResignKeyNotification,
      NSWindow.didBecomeMainNotification, NSWindow.didResignMainNotification,
      NSWindow.willCloseNotification, NSWindow.didMiniaturizeNotification,
      NSWindow.didDeminiaturizeNotification, NSWindow.didChangeOcclusionStateNotification,
      NSApplication.didBecomeActiveNotification, NSApplication.didResignActiveNotification,
    ]
    for name in names {
      appKitObservers.append(
        NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) {
          [weak self] notification in
          let observedWindow = notification.object as? NSWindow
          MainActor.assumeIsolated {
            self?.recordAppKitState(name.rawValue, observedWindow: observedWindow)
          }
        })
    }
    recordAppKitState("installed", observedWindow: window)
  }

  private func windowDiagnostic(_ candidate: NSWindow?) -> Any {
    guard let candidate else { return NSNull() }
    return [
      "number": candidate.windowNumber, "class": String(describing: type(of: candidate)),
      "isKey": candidate.isKeyWindow, "isMain": candidate.isMainWindow,
      "isVisible": candidate.isVisible, "isMiniaturized": candidate.isMiniaturized,
      "firstResponderType": candidate.firstResponder.map { String(describing: type(of: $0)) }
        ?? "nil",
      "parentNumber": candidate.parent?.windowNumber ?? -1,
    ] as [String: Any]
  }

  private func recordAppKitState(
    _ reason: String, observedWindow: NSWindow?, details: [String: Any] = [:]
  ) {
    guard appKitDiagnosticCount < 1500 else { return }
    appKitDiagnosticCount += 1
    var fields = details
    fields["reason"] = reason
    fields["appActive"] = NSApp.isActive
    fields["testWindow"] = windowDiagnostic(window)
    fields["observedWindow"] = windowDiagnostic(observedWindow)
    fields["keyWindow"] = windowDiagnostic(NSApp.keyWindow)
    fields["mainWindow"] = windowDiagnostic(NSApp.mainWindow)
    fields["testChildWindows"] = Array((window?.childWindows ?? []).prefix(16)).map {
      windowDiagnostic($0)
    }
    record("appkit_diagnostic", fields)
    if appKitDiagnosticCount == 1500 { record("appkit_diagnostic_limit", ["limit": 1500]) }
  }

  private func buildMenu() {
    let menu = NSMenu()
    let app = NSMenuItem()
    menu.addItem(app)
    let appMenu = NSMenu(title: "CFM Component Integration Test")
    let activation = appMenu.addItem(
      withTitle: "Activate test window (TEST DATA)",
      action: #selector(activateTestWindow(_:)), keyEquivalent: "")
    activation.target = self
    appMenu.addItem(.separator())
    appMenu.addItem(
      withTitle: "Quit CFM Component Integration Test",
      action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    app.submenu = appMenu
    let edit = NSMenuItem()
    menu.addItem(edit)
    let editMenu = NSMenu(title: "Edit")
    for (name, selector, key) in [
      ("Undo", "undo:", "z"), ("Cut", "cut:", "x"), ("Copy", "copy:", "c"),
      ("Paste", "paste:", "v"), ("Select All", "selectAll:", "a"),
    ] {
      editMenu.addItem(withTitle: name, action: Selector(selector), keyEquivalent: key)
    }
    edit.submenu = editMenu
    NSApp.mainMenu = menu
  }

  /// Explicit test-only control. Component dismissal never invokes this action.
  /// Activation is a request, not proof that the application became active;
  /// the existing AppKit notification journal records the eventual result.
  @objc private func activateTestWindow(_ sender: Any?) {
    guard let window, let web else {
      record("fixture_activation", ["requested": false, "reason": "test_window_unavailable"])
      return
    }
    record(
      "fixture_activation",
      [
        "requested": true, "appActiveBefore": NSApp.isActive,
        "windowNumber": window.windowNumber,
      ])
    NSApp.activate()
    window.makeKeyAndOrderFront(nil)
    let accepted = window.makeFirstResponder(web)
    record(
      "fixture_activation",
      [
        "requestCompleted": true, "firstResponderAccepted": accepted,
        "appActiveImmediatelyAfter": NSApp.isActive, "windowNumber": window.windowNumber,
      ])
    recordAppKitState("fixture_activation_requested", observedWindow: window)
  }

  func userContentController(
    _ userContentController: WKUserContentController, didReceive message: WKScriptMessage,
    replyHandler: @escaping @MainActor (Any?, String?) -> Void
  ) {
    func rejectEnvelope(_ reason: String) {
      record("bridge_envelope_rejected", ["reason": reason])
      replyHandler(nil, "TEST DATA bridge rejected envelope: \(reason)")
    }
    guard message.frameInfo.isMainFrame else {
      rejectEnvelope("not_main_frame")
      return
    }
    guard let origin = message.frameInfo.request.url, origin.isFileURL,
      origin.standardizedFileURL.path.hasPrefix(resourceRoot.standardizedFileURL.path + "/")
    else {
      rejectEnvelope("origin_outside_fixture_ui")
      return
    }
    guard let body = message.body as? [String: Any] else {
      rejectEnvelope("body_not_object")
      return
    }
    guard let command = body["command"] as? String, !command.isEmpty, command.utf8.count <= 128
    else {
      rejectEnvelope("invalid_command")
      return
    }
    guard let arguments = body["args"] as? [String: Any] else {
      rejectEnvelope("arguments_not_object")
      return
    }
    record("invoke", ["command": command])
    do { replyHandler(try dispatch(command, arguments), nil) } catch {
      record("rejected", ["command": command, "error": String(describing: error)])
      replyHandler(nil, String(describing: error))
    }
  }

  private func dispatch(_ command: String, _ args: [String: Any]) throws -> Any {
    switch command {
    case "component_test_observation":
      try observeFixtureEvent(args)
      return NSNull()
    case "open_page":
      let pages = [
        "general", "proxies", "profiles", "providers", "logs", "connections", "rules", "settings",
        "feedback",
      ]
      guard Set(args.keys) == ["page"], let page = args["page"] as? String, pages.contains(page)
      else {
        throw Failure("TEST DATA rejected unknown page")
      }
      let previous = currentPage
      currentPage = page
      record("fixture_page", ["previous": previous, "page": page])
      return NSNull()
    case "report_dashboard_startup":
      let codes = [
        "script_loaded", "ready", "script_failed", "unhandled_rejection", "startup_timeout",
        "bootstrap_failed",
      ]
      guard Set(args.keys) == ["code"], let code = args["code"] as? String, codes.contains(code)
      else {
        throw Failure("TEST DATA rejected unknown startup code")
      }
      record("fixture_startup", ["code": code])
      return NSNull()
    case "present_native_profile_menu", "present_native_runtime_settings":
      return try present(command, args)
    case "sync_native_general_switches":
      return try syncGeneral(args)
    case "focus_native_general_switch":
      guard let id = args["requestId"] as? String, let completion = completions[id],
        completion.kind == "general", let sequence = args["sequence"] as? UInt64,
        let key = args["key"] as? UInt32
      else { return false }
      return cfm_general_switches_focus_v1(completion.session, sequence, key) == 1
    case "dismiss_native_general_switches":
      guard let id = args["requestId"] as? String, let completion = completions[id],
        completion.kind == "general"
      else { return false }
      return cfm_general_switches_dismiss_v1(completion.session) == 1
    case "update_native_profile_menu", "update_native_runtime_settings":
      return try update(command, args)
    case "dismiss_native_profile_menu", "dismiss_native_runtime_settings":
      guard let id = args["requestId"] as? String, let completion = completions[id] else {
        return false
      }
      return
        (completion.kind == "profile"
        ? cfm_profile_menu_dismiss_v1(completion.session)
        : cfm_runtime_settings_dismiss_v1(completion.session)) == 1
    case "plugin:event|listen":
      nextListener += 1
      return nextListener
    case "plugin:event|unlisten": return NSNull()
    case "plugin:window|start_dragging":
      guard let event = NSApp.currentEvent else { return NSNull() }
      window?.performDrag(with: event)
      return NSNull()
    case "plugin:window|is_maximized": return window?.isZoomed ?? false
    case "plugin:window|internal_toggle_maximize":
      window?.zoom(nil)
      return NSNull()
    case "write_settings_snapshot":
      guard let settings = args["settings"] as? [String: Any],
        settings["launch_at_login"] as? Bool == false
      else { throw Failure("TEST DATA never registers login items") }
      var snapshot = try dictionary(fixture("read_settings_snapshot"))
      snapshot["settings"] = settings
      snapshot["resolved_locale"] =
        (settings["language"] as? String).flatMap { $0 == "system" ? "zh-Hans" : $0 } ?? "zh-Hans"
      fixtures["read_settings_snapshot"] = snapshot
      record("fixture_settings_write")
      return snapshot
    case "write_runtime_settings_snapshot":
      var snapshot = try dictionary(fixture("read_runtime_settings_snapshot"))
      guard let settings = args["settings"] as? [String: Any],
        args["revision"] as? String == snapshot["revision"] as? String
      else { throw Failure("TEST DATA fixture revision changed") }
      record("fixture_runtime_intent", ["settings": settings])
      if settings["preferred_mixed_port"] as? Int == 7899 {
        throw Failure("TEST DATA: port 7899 is reserved to exercise failure retention")
      }
      runtimeRevision += 1
      snapshot["revision"] = "fixture-runtime-\(runtimeRevision)"
      snapshot["settings"] = settings
      snapshot["effective"] = [
        "mixed_port": settings["preferred_mixed_port"] as? Int ?? 7890,
        "log_level": settings["log_level"] ?? "info", "tunnel_mtu": settings["tunnel_mtu"] ?? 1500,
        "ipv6_dns_enabled": settings["ipv6_dns_enabled"] ?? true,
        "lan_proxy": settings["lan_proxy"] ?? NSNull(),
      ]
      fixtures["read_runtime_settings_snapshot"] = snapshot
      return snapshot
    case "read_profile_text":
      let profile = try selectedProfile(args["id"] as? String)
      return [
        "id": profile["id"]!, "name": profile["name"]!, "body": profileBody,
        "source_url": NSNull(), "proxy_selections": [:],
      ]
    case "read_runtime_config_text":
      let snapshot = try dictionary(fixture("read_runtime_settings_snapshot"))
      let effective = try dictionary(snapshot["effective"] as Any)
      guard let port = effective["mixed_port"] as? Int,
        let level = effective["log_level"] as? String
      else {
        throw Failure("TEST DATA runtime effective projection is invalid")
      }
      let projection: [String: Any] = [
        "log": level == "silent" ? ["disabled": true] : ["level": level],
        "inbounds": [
          ["type": "mixed", "tag": "cfw-system-proxy", "listen": "127.0.0.1", "listen_port": port]
        ],
        "outbounds": [["type": "direct", "tag": "DIRECT"]],
      ]
      let data = try JSONSerialization.data(withJSONObject: projection)
      guard let result = String(data: data, encoding: .utf8) else {
        throw Failure("TEST DATA projection encoding failed")
      }
      record("fixture_runtime_projection", ["mixed_port": port, "log_level": level])
      return result
    case "select_profile":
      guard let id = args["id"] as? String else { throw Failure("Missing fixture profile id") }
      _ = try selectedProfile(id)
      let profiles = try profileList().map { profile -> [String: Any] in
        var copy = profile
        copy["active"] = profile["id"] as? String == id
        return copy
      }
      fixtures["profiles_snapshot"] = profiles
      record("fixture_profile_select", ["id": id])
      return NSNull()
    default:
      if let response = fixtures[command] { return response }
      throw Failure("TEST DATA: unsupported command explicitly rejected: \(command)")
    }
  }

  private func observeFixtureEvent(_ fields: [String: Any]) throws {
    guard let kind = fields["kind"] as? String else {
      throw Failure("Invalid TEST DATA observation kind")
    }
    func boundedText(_ key: String, maximum: Int, nullable: Bool = false) -> Bool {
      if nullable, fields[key] is NSNull { return true }
      return (fields[key] as? String).map { $0.unicodeScalars.count <= maximum } ?? false
    }
    let valid: Bool
    switch kind {
    case "click":
      valid =
        Set(fields.keys) == ["kind", "dataPage", "dataAction"]
        && boundedText("dataPage", maximum: 64, nullable: true)
        && boundedText("dataAction", maximum: 64, nullable: true)
    case "keydown": valid = Set(fields.keys) == ["kind", "key"] && boundedText("key", maximum: 64)
    case "error", "unhandledrejection":
      valid = Set(fields.keys) == ["kind", "message"] && boundedText("message", maximum: 512)
    default: valid = false
    }
    guard valid else { throw Failure("Invalid or oversized TEST DATA observation") }
    guard observations < 1000 else { return }
    observations += 1
    record("fixture_observation", fields)
    if observations == 1000 { record("fixture_observation_limit", ["limit": 1000]) }
  }

  private var profileBody: String {
    #"{"outbounds":[{"type":"selector","tag":"TEST DATA","outbounds":["DIRECT"]},{"type":"direct","tag":"DIRECT"}],"route":{"final":"TEST DATA","rules":[]}}"#
  }
  private func fixture(_ command: String) throws -> Any {
    guard let value = fixtures[command] else { throw Failure("Missing fixture \(command)") }
    return value
  }
  private func profileList() throws -> [[String: Any]] {
    guard let value = fixtures["profiles_snapshot"] as? [[String: Any]] else {
      throw Failure("Invalid fixture profiles")
    }
    return value
  }
  private func selectedProfile(_ id: String?) throws -> [String: Any] {
    guard let id, let profile = try profileList().first(where: { $0["id"] as? String == id }) else {
      throw Failure("Unknown TEST DATA profile")
    }
    return profile
  }
  private func dictionary(_ value: Any) throws -> [String: Any] {
    guard let dictionary = value as? [String: Any] else { throw Failure("Expected JSON object") }
    return dictionary
  }
  private func object(_ data: Data) throws -> [String: Any] {
    try dictionary(JSONSerialization.jsonObject(with: data))
  }

  private func envelope(_ request: [String: Any], kind: String, session: UInt64) throws -> [String:
    Any]
  {
    guard let web, let window else { throw Failure("Test window is unavailable") }
    var frame = request
    frame.removeValue(forKey: "requestId")
    frame["version"] = 1
    frame["session"] = session
    if kind != "general" { frame["windowNumber"] = window.windowNumber }
    if kind == "profile" {
      guard let point = frame.removeValue(forKey: "point") as? [String: Any],
        let x = point["x"] as? Double, let y = point["y"] as? Double,
        let width = point["viewportWidth"] as? Double,
        let height = point["viewportHeight"] as? Double
      else { throw Failure("Invalid test anchor") }
      var number: Int64 = 0
      var screenX = 0.0
      var screenY = 0.0
      let status = cfm_profile_menu_anchor_v1(
        Unmanaged.passUnretained(web).toOpaque(), x, y, width, height, &number, &screenX, &screenY)
      guard status == 1 else { throw Failure("Native anchor rejected: \(status)") }
      frame["windowNumber"] = number
      frame["anchor"] = ["x": screenX, "y": screenY]
    }
    return frame
  }
  private func syncGeneral(_ args: [String: Any]) throws -> Any {
    guard let web, let request = args["request"] as? [String: Any],
      let id = request["requestId"] as? String, UUID(uuidString: id) != nil
    else { throw Failure("Invalid General presentation") }
    if generalFrameCount < 16 {
      generalFrameCount += 1
      record("general_frame", ["frame": request])
    }
    if let completion = completions[id] {
      guard completion.kind == "general" else { throw Failure("Component request type changed") }
      guard args["completion"] is NSNull else {
        throw Failure("General updates must retain the original Tauri Channel")
      }
      let data = try JSONSerialization.data(
        withJSONObject: envelope(request, kind: "general", session: completion.session))
      let status = data.withUnsafeBytes { bytes in
        cfm_general_switches_sync_v1(
          Unmanaged.passUnretained(web).toOpaque(),
          bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, nil, nil, 0)
      }
      if status == 2 {
        record("general_geometry_pending", ["sequence": request["sequence"] as Any])
        return false
      }
      guard status == 1 else { throw Failure("Native General update rejected: \(status)") }
      record(
        "general_update", ["session": completion.session, "sequence": request["sequence"] as Any])
      return true
    }
    guard let channelText = args["completion"] as? String, channelText.hasPrefix("__CHANNEL__:"),
      let channel = Int(channelText.dropFirst(12))
    else { throw Failure("Missing initial General Channel") }
    let session = nextSession
    nextSession += 1
    let completion = Completion(
      host: self, requestID: id, channel: channel, session: session, kind: "general")
    let data = try JSONSerialization.data(
      withJSONObject: envelope(request, kind: "general", session: session))
    let pointer = Unmanaged.passRetained(completion).toOpaque()
    completions[id] = completion
    let status = data.withUnsafeBytes { bytes in
      cfm_general_switches_sync_v1(
        Unmanaged.passUnretained(web).toOpaque(),
        bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, generalInput, generalClosed,
        UInt(bitPattern: pointer))
    }
    guard status == 1 else {
      completions.removeValue(forKey: id)
      Unmanaged<Completion>.fromOpaque(pointer).release()
      // Match Tauri ChannelInner::drop for a rejected initial presentation.
      // A subsequent initial attempt must supply a fresh JavaScript callback.
      deliver(channel: channel, packets: [["index": 0, "end": true]])
      if status == 2 {
        record("general_geometry_pending", ["sequence": request["sequence"] as Any])
        return false
      }
      throw Failure("Native General presentation rejected: \(status)")
    }
    record("native_present", ["kind": "general", "session": session, "requestId": id])
    return true
  }

  private func present(_ command: String, _ args: [String: Any]) throws -> Any {
    guard let request = args["request"] as? [String: Any], let id = request["requestId"] as? String,
      UUID(uuidString: id) != nil, let channelText = args["completion"] as? String,
      channelText.hasPrefix("__CHANNEL__:"), let channel = Int(channelText.dropFirst(12))
    else { throw Failure("Invalid presentation request or Tauri Channel") }
    let session = nextSession
    nextSession += 1
    let kind = command == "present_native_profile_menu" ? "profile" : "runtime"
    let data = try JSONSerialization.data(
      withJSONObject: envelope(request, kind: kind, session: session))
    let completion = Completion(
      host: self, requestID: id, channel: channel, session: session, kind: kind)
    let pointer = Unmanaged.passRetained(completion).toOpaque()
    completions[id] = completion
    let status = data.withUnsafeBytes { bytes in
      if kind == "profile" {
        return cfm_profile_menu_present_v1(
          bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, profileClosed,
          UInt(bitPattern: pointer))
      }
      return cfm_runtime_settings_present_v1(
        bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, runtimeEvent, runtimeClosed,
        UInt(bitPattern: pointer))
    }
    guard status == 1 else {
      completions.removeValue(forKey: id)
      Unmanaged<Completion>.fromOpaque(pointer).release()
      throw Failure("Native \(kind) presentation rejected: \(status)")
    }
    record("native_present", ["kind": kind, "session": session, "requestId": id, "status": status])
    return NSNull()
  }
  private func update(_ command: String, _ args: [String: Any]) throws -> Any {
    guard let request = args["request"] as? [String: Any], let id = request["requestId"] as? String,
      let completion = completions[id]
    else { return false }
    let kind = command == "update_native_profile_menu" ? "profile" : "runtime"
    guard completion.kind == kind else { throw Failure("Component request type changed") }
    let data = try JSONSerialization.data(
      withJSONObject: envelope(request, kind: kind, session: completion.session))
    let status = data.withUnsafeBytes { bytes in
      kind == "profile"
        ? cfm_profile_menu_update_v1(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
        : cfm_runtime_settings_update_v1(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
    }
    guard status == 1 || status == 2 else {
      throw Failure("Native \(kind) update rejected: \(status)")
    }
    record("native_update", ["kind": kind, "session": completion.session, "status": status])
    return status == 1
  }
  func deliver(channel: Int, packets: [[String: Any]]) {
    do {
      let data = try JSONSerialization.data(withJSONObject: packets)
      guard let json = String(data: data, encoding: .utf8) else {
        throw Failure("Channel encoding failed")
      }
      web?.evaluateJavaScript(
        "\(json).forEach(packet => window.__CFM_COMPONENT_TEST__.deliver(\(channel), packet))"
      ) { [weak self] _, error in
        if let error {
          self?.record("channel_delivery_failure", ["error": String(describing: error)])
        }
      }
    } catch { record("channel_encoding_failure", ["error": String(describing: error)]) }
  }
  private func dismissAll() {
    for completion in Array(completions.values) {
      if completion.kind == "profile" {
        _ = cfm_profile_menu_dismiss_v1(completion.session)
      } else if completion.kind == "general" {
        _ = cfm_general_switches_dismiss_v1(completion.session)
      } else {
        _ = cfm_runtime_settings_dismiss_v1(completion.session)
      }
    }
  }
  func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
    epoch += 1
    observations = 0
    currentPage = "general"
    dismissAll()
  }
  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    record("page_loaded", ["url": webView.url?.lastPathComponent ?? "unknown"])
    webView.evaluateJavaScript(
      "JSON.stringify({page:document.getElementById('page').innerText,nav:document.getElementById('nav').innerText})"
    ) { [weak self] value, error in
      self?.record(
        "dom_loaded",
        [
          "fixture_page": value as? String ?? "",
          "error": error.map(String.init(describing:)) ?? "",
        ])
    }
  }
  func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
    record("navigation_failure", ["error": String(describing: error)])
  }
  func webView(
    _ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
    decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void
  ) {
    let url = navigationAction.request.url
    let allowed =
      url?.isFileURL == true
      && url?.standardizedFileURL.path.hasPrefix(resourceRoot.standardizedFileURL.path + "/")
        == true
    if !allowed { record("navigation_blocked", ["scheme": url?.scheme ?? "none"]) }
    decisionHandler(allowed ? .allow : .cancel)
  }
  func windowWillClose(_ notification: Notification) { NSApp.terminate(nil) }
  func applicationWillTerminate(_ notification: Notification) {
    if let appKitEventMonitor { NSEvent.removeMonitor(appKitEventMonitor) }
    appKitEventMonitor = nil
    for observer in appKitObservers { NotificationCenter.default.removeObserver(observer) }
    appKitObservers.removeAll()
    dismissAll()
    record("terminated")
  }
  struct Failure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
  }
}

@main private enum ComponentIntegrationApplication {
  @MainActor static func main() {
    let application = NSApplication.shared
    let delegate = IntegrationHost()
    application.setActivationPolicy(.regular)
    application.delegate = delegate
    withExtendedLifetime(delegate) { application.run() }
  }
}

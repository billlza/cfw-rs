import AppKit
import Foundation
import SwiftUI
import Testing

@testable import CFMNativeDashboard

private func runtimePayload(_ fields: [String: Any] = [:], draft edits: [String: Any] = [:]) throws
  -> Data
{
  var draft: [String: Any] = [
    "port": "", "level": "info", "mtu": "1500", "ipv6DNS": true, "allow": false,
    "lanAddress": "0.0.0.0", "lanPort": "7898", "lanSources": "192.168.1.0/24",
    "ipv6DNSEdited": false,
  ]
  for (key, value) in edits { draft[key] = value }
  var value: [String: Any] = [
    "version": 1, "session": 1, "sequence": 1, "windowNumber": 1, "locale": "en",
    "appearance": "light", "saving": false, "error": NSNull(), "draft": draft,
    "acknowledgedSubmission": 0,
    "labels": [
      "title": "Network settings",
      "description": "Changes apply to the current core. Existing connections may reconnect.",
      "port": "Local proxy port", "automatic": "Automatic", "level": "Log level", "mtu": "TUN MTU",
      "ipv6DNS": "Enable IPv6 DNS",
      "ipv6Note":
        "Turn off for a proxy server with a broken IPv6 exit. TUN still captures IPv6 traffic.",
      "allow": "Share with trusted LAN devices",
      "lanNote":
        "LAN devices use a separate port. Enter the private source networks allowed to use it.",
      "lanAddress": "LAN listener", "lanPort": "LAN port", "lanSources": "Trusted source ranges",
      "cancel": "Cancel", "apply": "Apply", "applying": "Applying…",
      "transportFailure": "Could not deliver settings. Try again.",
      "inputTooLong": "{label} must contain at most {maximum} characters",
    ],
  ]
  for (key, field) in fields { value[key] = field }
  return try JSONSerialization.data(withJSONObject: value)
}

@MainActor private final class RuntimeProbe {
  var payloads: [Data] = []
  var closedSessions: [UInt64] = []
  var accept: Int32 = 1
  var context: UInt { UInt(bitPattern: Unmanaged.passUnretained(self).toOpaque()) }
}

private let runtimeEvent: RuntimeSettingsEventCallback = { context, _, bytes, count in
  guard let pointer = UnsafeRawPointer(bitPattern: context), let bytes, count > 0 else { return 0 }
  let payload = Data(bytes: bytes, count: count)
  let probe = Unmanaged<RuntimeProbe>.fromOpaque(pointer).takeUnretainedValue()
  return MainActor.assumeIsolated {
    probe.payloads.append(payload)
    return probe.accept
  }
}

private let runtimeClosed: RuntimeSettingsClosedCallback = { context, session in
  guard let pointer = UnsafeRawPointer(bitPattern: context) else { return }
  let probe = Unmanaged<RuntimeProbe>.fromOpaque(pointer).takeUnretainedValue()
  MainActor.assumeIsolated { probe.closedSessions.append(session) }
}

@Suite(.serialized)
struct RuntimeSettingsTests {
  @Test func strictFramesAndResourceBounds() throws {
    #expect(try RuntimeSettingsFrame.decode(runtimePayload()).draft.port.isEmpty)
    for fields: [String: Any] in [
      ["version": 2], ["session": 0], ["sequence": 0], ["windowNumber": 0],
      ["appearance": "system"], ["locale": "future"], ["error": ""],
      ["error": String(repeating: "x", count: 4097)], ["saving": "false"],
      ["acknowledgedSubmission": -1], ["acknowledgedSubmission": 9_007_199_254_740_992 as UInt64],
    ] {
      #expect(throws: (any Error).self) { try RuntimeSettingsFrame.decode(runtimePayload(fields)) }
    }
    for draft: [String: Any] in [
      ["level": "verbose"], ["port": String(repeating: "1", count: 33)],
      ["mtu": String(repeating: "1", count: 33)], ["lanPort": String(repeating: "1", count: 33)],
      ["lanAddress": String(repeating: "x", count: 256)],
      ["lanSources": String(repeating: "x", count: 8193)],
      ["ipv6DNSEdited": "false"], ["ipv6DNS": NSNull()],
    ] {
      #expect(throws: (any Error).self) {
        try RuntimeSettingsFrame.decode(runtimePayload(draft: draft))
      }
    }
    #expect(
      try RuntimeSettingsFrame.decode(
        runtimePayload(draft: ["lanSources": String(repeating: "x", count: 8192)])
      ).draft.lanSources.count == 8192)
    #expect(throws: (any Error).self) {
      try RuntimeSettingsFrame.decode(Data(repeating: 32, count: 16_385))
    }
    var missing = try #require(
      JSONSerialization.jsonObject(with: runtimePayload()) as? [String: Any])
    missing.removeValue(forKey: "appearance")
    #expect(throws: (any Error).self) {
      try RuntimeSettingsFrame.decode(JSONSerialization.data(withJSONObject: missing))
    }
  }

  @Test @MainActor func editsAreBoundedByScalarsAndIPv6TouchIsSticky() throws {
    let probe = RuntimeProbe()
    let model = RuntimeSettingsModel(
      try RuntimeSettingsFrame.decode(runtimePayload()),
      event: runtimeEvent, closed: runtimeClosed, context: probe.context)
    defer { model.finish() }
    #expect(model.edit(.port, text: "7891"))
    // These are 17 grapheme clusters, but 34 Unicode scalars, matching Rust
    // chars and JS Array.from rather than accepting an unbounded cluster.
    #expect(!model.edit(.port, text: String(repeating: "e\u{301}", count: 17)))
    #expect(model.draft.port == "7891")
    #expect(model.error == "Local proxy port must contain at most 32 characters")
    #expect(!model.edit(.lanSources, text: String(repeating: "x", count: 8193)))
    #expect(model.draft.lanSources == "192.168.1.0/24")
    #expect(model.edit(.ipv6DNS, enabled: false))
    #expect(model.edit(.ipv6DNS, enabled: true))
    #expect(model.draft.ipv6DNS)
    #expect(model.draft.ipv6DNSEdited)
    #expect(!model.edit(.level, text: "verbose"))
    #expect(model.draft.level == .info)
    model.setViewportHeight(400)
    #expect(model.textAreaHeight == 64)
    model.resizeTextArea(500)
    #expect(model.textAreaHeight == 192)
    model.resizeTextArea(10)
    #expect(model.textAreaHeight == 64)
  }

  @Test @MainActor func submitWaitsForHostAndFailurePreservesDraft() throws {
    let probe = RuntimeProbe()
    let model = RuntimeSettingsModel(
      try RuntimeSettingsFrame.decode(runtimePayload()),
      event: runtimeEvent, closed: runtimeClosed, context: probe.context)
    defer { model.finish() }
    #expect(model.edit(.port, text: "7892"))
    #expect(model.edit(.ipv6DNS, enabled: false))
    #expect(model.submit() == 1)
    #expect(model.busy)
    #expect(model.submit() == 0)
    #expect(!model.edit(.port, text: "7893"))
    #expect(probe.payloads.count == 1)
    let payload = try #require(
      JSONSerialization.jsonObject(with: probe.payloads[0]) as? [String: Any])
    let sent = try #require(payload["draft"] as? [String: Any])
    #expect(payload["action"] as? String == "submit")
    #expect(sent["port"] as? String == "7892")
    #expect(sent["ipv6DNSEdited"] as? Bool == true)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(runtimePayload(["sequence": 2, "appearance": "dark"]))) == 1
    )
    #expect(model.busy, "theme-only updates cannot release a pending submission")
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload(["sequence": 3, "saving": true, "acknowledgedSubmission": 1]))) == 1)
    #expect(model.pendingSubmissionId == nil)
    #expect(model.busy)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 4, "error": "Snapshot revision changed", "acknowledgedSubmission": 1,
          ]))) == 1)
    #expect(!model.busy)
    #expect(model.draft.port == "7892")
    #expect(!model.draft.ipv6DNS)
    #expect(model.error == "Snapshot revision changed")
    #expect(model.update(try RuntimeSettingsFrame.decode(runtimePayload(["sequence": 3]))) == 0)
    #expect(
      model.update(try RuntimeSettingsFrame.decode(runtimePayload(["session": 2, "sequence": 5])))
        == 2)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(runtimePayload(["windowNumber": 2, "sequence": 5]))) == 0)
  }

  @Test @MainActor func priorFailureAndThemeCannotAcknowledgeAnotherSubmission() throws {
    let probe = RuntimeProbe()
    let model = RuntimeSettingsModel(
      try RuntimeSettingsFrame.decode(runtimePayload()),
      event: runtimeEvent, closed: runtimeClosed, context: probe.context)
    defer { model.finish() }
    #expect(model.edit(.port, text: "7901"))
    #expect(model.submit() == 1)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 2, "acknowledgedSubmission": 1, "error": "Port occupied",
          ]))) == 1)
    #expect(!model.busy)
    #expect(model.draft.port == "7901")
    #expect(model.submit() == 1)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 3, "acknowledgedSubmission": 1, "error": "Port occupied",
            "appearance": "dark",
          ]))) == 1)
    #expect(model.busy, "The old failure is not an acknowledgement of submit 2")
    #expect(probe.payloads.count == 2)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 4, "acknowledgedSubmission": 2, "error": "Port occupied",
          ]))) == 1)
    #expect(!model.busy)
    #expect(model.draft.port == "7901")
    #expect(model.submit() == 1)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 5, "acknowledgedSubmission": 2, "error": "Port occupied",
            "appearance": "light",
          ]))) == 1)
    #expect(model.busy, "Identical error text needs the new submission's own acknowledgement")
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 6, "acknowledgedSubmission": 3, "error": "Port occupied",
          ]))) == 1)
    #expect(!model.busy)
    for (index, data) in probe.payloads.enumerated() {
      let value = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
      #expect(value["submissionId"] as? Int == index + 1)
    }
  }

  @Test @MainActor func transportRejectionNeverClosesOrDiscardsDraft() throws {
    let probe = RuntimeProbe()
    probe.accept = 0
    let model = RuntimeSettingsModel(
      try RuntimeSettingsFrame.decode(runtimePayload()),
      event: runtimeEvent, closed: runtimeClosed, context: probe.context)
    #expect(model.edit(.mtu, text: "9000"))
    #expect(model.submit() == 0)
    #expect(!model.busy)
    #expect(model.error == model.frame.labels.transportFailure)
    #expect(model.draft.mtu == "9000")
    #expect(probe.closedSessions.isEmpty)
    model.finish()
    model.finish()
    #expect(probe.closedSessions == [1])
    #expect(model.submit() == 2)
    #expect(!model.edit(.port, text: "1"))
  }

  @Test @MainActor func acknowledgementBoundsAndRejectedSubmissionCounterAreStrict() throws {
    let probe = RuntimeProbe()
    let model = RuntimeSettingsModel(
      try RuntimeSettingsFrame.decode(runtimePayload()),
      event: runtimeEvent, closed: runtimeClosed, context: probe.context)
    defer { model.finish() }
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 2, "acknowledgedSubmission": 1, "error": "Unsent submission",
          ]))) == 0)
    #expect(model.frame.sequence == 1)
    probe.accept = 0
    #expect(model.submit() == 0)
    #expect(model.submissionCount == 1)
    #expect(model.pendingSubmissionId == nil)
    #expect(model.error == model.frame.labels.transportFailure)
    probe.accept = 1
    #expect(model.submit() == 1)
    #expect(model.submissionCount == 2)
    #expect(model.pendingSubmissionId == 2)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 2, "acknowledgedSubmission": 2, "saving": true,
          ]))) == 1)
    #expect(model.pendingSubmissionId == nil)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 3, "acknowledgedSubmission": 1, "error": "Stale acknowledgement",
          ]))) == 0)
    #expect(model.frame.sequence == 2)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 3, "acknowledgedSubmission": 3, "error": "Future acknowledgement",
          ]))) == 0)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 3, "acknowledgedSubmission": 2, "error": "Apply failed",
          ]))) == 1)
    #expect(!model.busy)
    #expect(
      model.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "sequence": 3, "acknowledgedSubmission": 2, "error": "Duplicate sequence",
          ]))) == 0)
    #expect(RuntimeSettingsModel.nextSubmission(after: 0) == 1)
    #expect(
      RuntimeSettingsModel.nextSubmission(after: 9_007_199_254_740_990) == 9_007_199_254_740_991)
    #expect(RuntimeSettingsModel.nextSubmission(after: 9_007_199_254_740_991) == nil)
    var missing = try #require(
      JSONSerialization.jsonObject(with: runtimePayload()) as? [String: Any])
    missing.removeValue(forKey: "acknowledgedSubmission")
    #expect(throws: (any Error).self) {
      try RuntimeSettingsFrame.decode(JSONSerialization.data(withJSONObject: missing))
    }
    let ids = try probe.payloads.map { data -> Int? in
      let value = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
      return value["submissionId"] as? Int
    }
    #expect(ids == [1, 2])
  }

  @Test @MainActor func escapeKeyEquivalentClosesWithoutFieldFocusAndRefusesBusyCancel() throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    let parent = NSWindow(
      contentRect: NSRect(x: 100, y: 100, width: 850, height: 603),
      styleMask: [.titled, .closable], backing: .buffered, defer: false)
    parent.isReleasedWhenClosed = false
    parent.orderFront(nil)
    defer { parent.close() }
    let frame = try RuntimeSettingsFrame.decode(
      runtimePayload(["windowNumber": parent.windowNumber]))
    let probe = RuntimeProbe()
    let controller = RuntimeSettingsWindow(
      frame: frame, parent: parent, event: runtimeEvent,
      closed: runtimeClosed, context: probe.context)
    #expect(controller.show())
    defer { controller.finish() }
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
    #expect(controller.panel.makeFirstResponder(nil))
    let escape = try #require(
      NSEvent.keyEvent(
        with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
        windowNumber: controller.panel.windowNumber, context: nil,
        characters: "\u{1b}", charactersIgnoringModifiers: "\u{1b}", isARepeat: false, keyCode: 53))
    #expect(controller.model.submit() == 1)
    _ = controller.panel.performKeyEquivalent(with: escape)
    #expect(probe.closedSessions.isEmpty)
    #expect(controller.panel.isVisible)
    #expect(
      controller.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "windowNumber": parent.windowNumber, "sequence": 2, "error": "Port is occupied",
            "acknowledgedSubmission": 1,
          ]))) == 1)
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
    #expect(controller.panel.performKeyEquivalent(with: escape))
    #expect(probe.closedSessions == [1])
    #expect(!controller.panel.isVisible)
    #expect(probe.payloads.count == 1)
  }

  @Test @MainActor func actualDialogRetainsDraftWhileHiddenAndRefusesBusyCancel() throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    let parent = NSWindow(
      contentRect: NSRect(x: 100, y: 100, width: 850, height: 603),
      styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
    parent.isReleasedWhenClosed = false
    parent.orderFront(nil)
    defer { parent.close() }
    let frame = try RuntimeSettingsFrame.decode(
      runtimePayload(["windowNumber": parent.windowNumber]))
    let probe = RuntimeProbe()
    let controller = RuntimeSettingsWindow(
      frame: frame, parent: parent, event: runtimeEvent,
      closed: runtimeClosed, context: probe.context)
    #expect(controller.show())
    defer { controller.finish() }
    #expect(controller.panel.parent === parent)
    #expect(controller.panel.frame.width == 480)
    #expect(controller.panel.frame.height <= 555)
    let viewport = parent.convertToScreen(parent.contentLayoutRect)
    #expect(abs(controller.panel.frame.midX - viewport.midX) < 0.01)
    #expect(abs(controller.panel.frame.midY - viewport.midY) < 0.01)
    #expect(controller.panel.appearance?.name == .aqua)
    #expect(controller.model.edit(.lanPort, text: "7900"))
    parent.orderOut(nil)
    NotificationCenter.default.post(
      name: NSWindow.didChangeOcclusionStateNotification, object: parent)
    #expect(!controller.panel.isVisible)
    #expect(!controller.model.closed)
    #expect(controller.model.draft.lanPort == "7900")
    parent.orderFront(nil)
    NotificationCenter.default.post(
      name: NSWindow.didChangeOcclusionStateNotification, object: parent)
    #expect(controller.panel.isVisible)
    NotificationCenter.default.post(name: NSApplication.didResignActiveNotification, object: NSApp)
    #expect(probe.closedSessions.isEmpty)
    #expect(
      controller.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "windowNumber": parent.windowNumber, "sequence": 2, "appearance": "dark",
          ]))) == 1)
    #expect(controller.panel.appearance?.name == .darkAqua)
    #expect(controller.model.draft.lanPort == "7900")
    #expect(controller.model.submit() == 1)
    controller.cancel()
    #expect(controller.panel.isVisible)
    #expect(!controller.windowShouldClose(controller.panel))
    #expect(probe.closedSessions.isEmpty)
    #expect(
      controller.update(
        try RuntimeSettingsFrame.decode(
          runtimePayload([
            "windowNumber": parent.windowNumber, "sequence": 3, "error": "Port is occupied",
            "acknowledgedSubmission": 1,
          ]))) == 1)
    #expect(controller.model.draft.lanPort == "7900")
    controller.cancel()
    #expect(probe.closedSessions == [1])
    #expect(!controller.panel.isVisible)
  }

  @Test @MainActor func actualFormUsesOriginalFieldOrderAndScrollableBounds() throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    let parent = NSWindow(
      contentRect: NSRect(x: 100, y: 100, width: 850, height: 400),
      styleMask: [.titled, .closable], backing: .buffered, defer: false)
    parent.isReleasedWhenClosed = false
    parent.orderFront(nil)
    defer { parent.close() }
    let frame = try RuntimeSettingsFrame.decode(
      runtimePayload(["windowNumber": parent.windowNumber]))
    let probe = RuntimeProbe()
    let controller = RuntimeSettingsWindow(
      frame: frame, parent: parent, event: runtimeEvent,
      closed: runtimeClosed, context: probe.context)
    #expect(controller.show())
    defer { controller.finish() }
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
    let content = try #require(controller.panel.contentView)
    content.layoutSubtreeIfNeeded()
    @MainActor func descendants(_ view: NSView) -> [NSView] {
      [view] + view.subviews.flatMap { descendants($0) }
    }
    let views = descendants(content)
    let scroll = try #require(views.compactMap { $0 as? NSScrollView }.first)
    #expect(controller.panel.frame.height == 352)
    #expect(try #require(scroll.documentView).bounds.height > scroll.contentView.bounds.height)
    let textFields = views.compactMap { $0 as? NSTextField }.filter { $0.isEditable }
    #expect(textFields.count == 4, "Local port, MTU, LAN listener, LAN port remain text fields")
    let ordered = textFields.sorted { left, right in
      left.convert(left.bounds, to: content).minY < right.convert(right.bounds, to: content).minY
    }
    #expect(ordered.map(\.stringValue) == ["", "1500", "0.0.0.0", "7898"])
    #expect(
      RuntimeSettingsDraft.Field.allCases.map(\.rawValue) == [
        "port", "level", "mtu", "ipv6DNS", "allow", "lanAddress", "lanPort", "lanSources",
      ])
    if let path = ProcessInfo.processInfo.environment["CFM_RUNTIME_SETTINGS_RENDER_PATH"] {
      let renderer = ImageRenderer(
        content: RuntimeSettingsForm(model: controller.model, cancel: {})
          .frame(width: 480).background(Color.white).environment(\.colorScheme, .light))
      renderer.scale = 2
      let rendered = try #require(renderer.nsImage)
      let tiff = try #require(rendered.tiffRepresentation)
      let bitmap = try #require(NSBitmapImageRep(data: tiff))
      #expect(bitmap.pixelsWide >= 480)
      let png = try #require(bitmap.representation(using: .png, properties: [:]))
      try png.write(to: URL(fileURLWithPath: path))
    }
  }

  @Test @MainActor func abiOwnsContextUntilForcedDismissExactlyOnce() throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    let parent = NSWindow(
      contentRect: NSRect(x: 100, y: 100, width: 850, height: 603),
      styleMask: [.titled, .closable], backing: .buffered, defer: false)
    parent.isReleasedWhenClosed = false
    parent.orderFront(nil)
    defer { parent.close() }
    let probe = RuntimeProbe()
    @MainActor func wire(_ session: UInt64, _ sequence: UInt64 = 1, saving: Bool = false) throws
      -> Data
    {
      try runtimePayload([
        "windowNumber": parent.windowNumber, "session": session, "sequence": sequence,
        "saving": saving,
      ])
    }
    @MainActor func present(_ session: UInt64) throws -> Int32 {
      try wire(session).withUnsafeBytes {
        runtimeSettingsPresent(
          $0.bindMemory(to: UInt8.self).baseAddress, $0.count, runtimeEvent,
          runtimeClosed, probe.context)
      }
    }
    #expect(try present(90_001) == 1)
    #expect(try present(90_002) == 1)
    #expect(probe.closedSessions == [90_001])
    #expect(try present(90_001) == 2)
    #expect(
      try wire(90_002, 2, saving: true).withUnsafeBytes {
        runtimeSettingsUpdate($0.bindMemory(to: UInt8.self).baseAddress, $0.count)
      } == 1)
    #expect(runtimeSettingsDismiss(90_001) == 2)
    #expect(runtimeSettingsDismiss(90_002) == 1)
    #expect(runtimeSettingsDismiss(90_002) == 2)
    #expect(probe.closedSessions == [90_001, 90_002])
    #expect(runtimeSettingsPresent(nil, 16, runtimeEvent, runtimeClosed, probe.context) == 0)
    let acknowledged = try runtimePayload([
      "windowNumber": parent.windowNumber, "session": 90_003, "acknowledgedSubmission": 1,
    ])
    #expect(
      acknowledged.withUnsafeBytes {
        runtimeSettingsPresent(
          $0.bindMemory(to: UInt8.self).baseAddress, $0.count,
          runtimeEvent, runtimeClosed, probe.context)
      } == 0)
    #expect(probe.closedSessions == [90_001, 90_002])
  }

  @Test func wrongThreadNeverEntersAppKit() async {
    #expect(await Task.detached { runtimeSettingsDismiss(90_002) }.value == 3)
  }
}

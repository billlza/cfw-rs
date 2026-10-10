import AppKit
import Foundation
import Testing
import WebKit

@testable import CFMNativeDashboard

@MainActor private final class GeneralSwitchProbe {
  struct Event: Equatable {
    let session: UInt64
    let sequence: UInt64
    let submission: UInt64
    let key: UInt32
    let kind: UInt32
    let value: UInt8
  }
  var events: [Event] = []
  var closes = 0
  var accepted: Int32 = 1
  var reenter: (() -> Void)?
  var context: UInt { UInt(bitPattern: Unmanaged.passUnretained(self).toOpaque()) }
}

private func generalSwitchEvent(
  _ context: UInt, _ session: UInt64, _ sequence: UInt64,
  _ submission: UInt64, _ key: UInt32, _ kind: UInt32, _ value: UInt8
) -> Int32 {
  let pointer = UnsafeRawPointer(bitPattern: context)!
  let probe = Unmanaged<GeneralSwitchProbe>.fromOpaque(pointer).takeUnretainedValue()
  return MainActor.assumeIsolated {
    probe.events.append(
      .init(
        session: session, sequence: sequence, submission: submission,
        key: key, kind: kind, value: value))
    probe.reenter?()
    return probe.accepted
  }
}
private func generalSwitchClosed(_ context: UInt) {
  let probe = Unmanaged<GeneralSwitchProbe>.fromOpaque(UnsafeRawPointer(bitPattern: context)!)
    .takeUnretainedValue()
  MainActor.assumeIsolated {
    probe.closes += 1
    probe.reenter?()
  }
}

private func generalSwitchPayload(_ overrides: [String: Any] = [:]) throws -> Data {
  var object: [String: Any] = [
    "version": 1, "session": 1, "sequence": 1, "acknowledgedSubmission": 0,
    "locale": "en", "appearance": "light",
    "viewport": ["width": 800, "height": 500],
    "clip": ["x": 100, "y": 50, "width": 600, "height": 400],
    "items": (1...6).map { key in
      [
        "key": key, "label": "Switch \(key)", "help": "Reason \(key)",
        "enabled": key != 4, "checked": false,
        "rect": ["x": 620, "y": 80 + key * 35, "width": 54, "height": 24],
      ] as [String: Any]
    },
  ]
  for (key, value) in overrides { object[key] = value }
  return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

@MainActor private func generalSwitchHost() -> (NSWindow, WKWebView) {
  NSApplication.shared.setActivationPolicy(.prohibited)
  final class KeyboardPanel: NSPanel { override var canBecomeKey: Bool { true } }
  let parent = KeyboardPanel(
    contentRect: NSRect(x: 70, y: 100, width: 840, height: 560),
    styleMask: [.titled, .closable, .nonactivatingPanel], backing: .buffered, defer: false)
  parent.isReleasedWhenClosed = false
  let webview = WKWebView(frame: NSRect(x: 20, y: 30, width: 800, height: 500))
  parent.contentView?.addSubview(webview)
  parent.makeKeyAndOrderFront(nil)
  RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.03))
  return (parent, webview)
}

@MainActor private var generalSwitchTestSession: UInt64 = 80_000
@MainActor private func nextGeneralSwitchTestSession() -> UInt64 {
  generalSwitchTestSession += 1
  return generalSwitchTestSession
}

@Suite(.serialized) struct GeneralSwitchesTests {
  @Test func frameRejectsUnknownDuplicateAndUnboundedInput() throws {
    _ = try GeneralSwitchesFrame.decode(generalSwitchPayload())
    for changes: [String: Any] in [
      ["controls": []], ["locale": "de"], ["appearance": "system"], ["sequence": 0],
      ["viewport": ["width": 0, "height": 500]],
      ["clip": ["x": 0, "y": 0, "width": -1, "height": 2]],
    ] {
      #expect(throws: (any Error).self) {
        try GeneralSwitchesFrame.decode(generalSwitchPayload(changes))
      }
    }
    var object = try #require(
      JSONSerialization.jsonObject(with: generalSwitchPayload()) as? [String: Any])
    var items = try #require(object["items"] as? [[String: Any]])
    items[1]["key"] = 1
    object["items"] = items
    #expect(throws: (any Error).self) {
      try GeneralSwitchesFrame.decode(JSONSerialization.data(withJSONObject: object))
    }
    items[1]["key"] = 2
    items[0]["command"] = "set_tun_enabled"
    object["items"] = items
    #expect(throws: (any Error).self) {
      try GeneralSwitchesFrame.decode(JSONSerialization.data(withJSONObject: object))
    }
  }

  @Test(arguments: ["en", "zh-Hans", "zh-Hant", "ja"])
  @MainActor func actualMiniControlsFitFootprintAndTransparentAreasPassThrough(locale: String)
    throws
  {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    let probe = GeneralSwitchProbe()
    let controller = GeneralSwitchesController(
      frame: try .decode(generalSwitchPayload(["locale": locale])),
      webview: webview, callback: generalSwitchEvent, closed: generalSwitchClosed,
      context: probe.context)
    try #require(controller.attach())
    defer { controller.finish() }
    #expect(controller.hosts.count == 6)
    for (key, host) in controller.hosts.sorted(by: { $0.key < $1.key }) {
      let size = host.fittingSize
      print(
        "General switch \(key) actual mini fitting size: \(size.width)x\(size.height), footprint 54x24"
      )
      #expect(size.width > 0 && size.width <= 54)
      #expect(size.height > 0 && size.height <= 24)
      let center = host.convert(
        NSPoint(x: host.bounds.midX, y: host.bounds.midY), to: controller.overlay.superview)
      #expect(controller.overlay.hitTest(center) != nil)
    }
    let empty = controller.overlay.convert(NSPoint(x: 20, y: 20), to: controller.overlay.superview)
    #expect(controller.overlay.hitTest(empty) == nil)
    #expect(probe.events.isEmpty)
  }

  @Test @MainActor func layoutCannotAcknowledgeToggleAndIdentitySurvivesHideAndTheme() throws {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    let probe = GeneralSwitchProbe()
    let controller = GeneralSwitchesController(
      frame: try .decode(generalSwitchPayload()),
      webview: webview, callback: generalSwitchEvent, closed: generalSwitchClosed,
      context: probe.context)
    try #require(controller.attach())
    defer { controller.finish() }
    let original = try #require(controller.hosts[1])
    controller.toggle(1, value: true)
    #expect(probe.events.count == 1)
    #expect(try #require(probe.events.first).submission == 1)
    #expect(controller.pendingSubmission == 1)
    #expect(controller.models[1]?.item.checked == false)
    controller.toggle(2, value: true)
    #expect(probe.events.count == 1)
    #expect(
      controller.update(
        try .decode(
          generalSwitchPayload([
            "sequence": 2, "appearance": "dark", "items": [],
            "clip": ["x": 0, "y": 0, "width": 0, "height": 0],
          ])), webview: webview) == 1)
    #expect(controller.pendingSubmission == 1)
    #expect(controller.overlay.isHidden)
    #expect(probe.closes == 0)
    #expect(
      controller.update(
        try .decode(
          generalSwitchPayload([
            "sequence": 3, "appearance": "dark", "acknowledgedSubmission": 1,
          ])), webview: webview) == 1)
    #expect(controller.pendingSubmission == nil)
    #expect(controller.hosts[1] === original)
    #expect(controller.overlay.appearance?.name == .darkAqua)
    #expect(controller.models[1]?.item.checked == false)
    controller.toggle(4, value: true)
    #expect(probe.events.count == 1)
    NotificationCenter.default.post(name: NSWindow.didResizeNotification, object: parent)
    #expect(!controller.geometryValid)
    #expect(controller.overlay.isHidden)
    #expect(
      controller.update(
        try .decode(generalSwitchPayload(["sequence": 4, "acknowledgedSubmission": 1])),
        webview: webview) == 1)
    #expect(controller.geometryValid)
  }

  @Test @MainActor func swiftUIFocusTabsOnlyWithinItsOwnResponderAndReturnsToWebview() throws {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    let probe = GeneralSwitchProbe()
    let controller = GeneralSwitchesController(
      frame: try .decode(generalSwitchPayload()),
      webview: webview, callback: generalSwitchEvent, closed: generalSwitchClosed,
      context: probe.context)
    try #require(controller.attach())
    defer { controller.finish() }
    parent.makeKey()
    #expect(controller.focus(sequence: 1, key: 1) == 1)
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
    let host = try #require(controller.hosts[1])
    let responder = try #require(parent.firstResponder as? NSView)
    #expect(responder === host || responder.isDescendant(of: host))
    #expect(
      probe.events.contains { $0.key == 1 && $0.kind == 4 && $0.submission == 0 && $0.value == 0 })
    let event = try #require(
      NSEvent.keyEvent(
        with: .keyDown, location: .zero, modifierFlags: [.shift],
        timestamp: 0, windowNumber: parent.windowNumber, context: nil,
        characters: "\t", charactersIgnoringModifiers: "\t", isARepeat: false, keyCode: 48))
    #expect(controller.handle(event))
    #expect(probe.events.last?.kind == 3)
    #expect(probe.events.last?.submission == 0)
    #expect(parent.firstResponder === webview)
    #expect(!controller.handle(event))
    #expect(controller.focus(sequence: 1, key: 4) == 0)
  }

  @Test @MainActor func abiContextIsOwnedOnceAndRejectedUpdateCannotConsumeAnother() throws {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    let session = nextGeneralSwitchTestSession()
    let owner = GeneralSwitchProbe()
    let rejected = GeneralSwitchProbe()
    let pointer = Unmanaged.passUnretained(webview).toOpaque()
    let initial = try generalSwitchPayload(["session": session])
    #expect(
      initial.withUnsafeBytes {
        generalSwitchesSync(
          pointer, $0.bindMemory(to: UInt8.self).baseAddress, $0.count,
          generalSwitchEvent, generalSwitchClosed, owner.context)
      } == 1)
    defer { _ = generalSwitchesDismiss(session) }
    let updated = try generalSwitchPayload(["session": session, "sequence": 2])
    #expect(
      updated.withUnsafeBytes {
        generalSwitchesSync(
          pointer, $0.bindMemory(to: UInt8.self).baseAddress, $0.count,
          generalSwitchEvent, generalSwitchClosed, rejected.context)
      } == 0)
    #expect(
      updated.withUnsafeBytes {
        generalSwitchesSync(
          pointer, $0.bindMemory(to: UInt8.self).baseAddress, $0.count, nil, nil, 0)
      } == 1)
    owner.reenter = { #expect(generalSwitchesDismiss(session) == 2) }
    #expect(generalSwitchesDismiss(session) == 1)
    #expect(generalSwitchesDismiss(session) == 2)
    #expect(owner.closes == 1)
    #expect(rejected.closes == 0)
    #expect(owner.events.isEmpty)
  }
}

extension GeneralSwitchesTests {
  @Test @MainActor func spaceUsesTheNativeToggleAndRejectedDeliveryClosesExactlyOnce() throws {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    let probe = GeneralSwitchProbe()
    let controller = GeneralSwitchesController(
      frame: try .decode(generalSwitchPayload()),
      webview: webview, callback: generalSwitchEvent, closed: generalSwitchClosed,
      context: probe.context)
    try #require(controller.attach())
    defer { controller.finish() }
    #expect(controller.focus(sequence: 1, key: 1) == 1)
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
    print(
      "General switch Space responder: \(String(describing: parent.firstResponder.map { type(of: $0) })), keyWindow=\(parent.isKeyWindow)"
    )
    let space = try #require(
      NSEvent.keyEvent(
        with: .keyDown, location: .zero, modifierFlags: [],
        timestamp: 0, windowNumber: parent.windowNumber, context: nil,
        characters: " ", charactersIgnoringModifiers: " ", isARepeat: false, keyCode: 49))
    // A nonactivating panel has real key-window state without activating the test app.
    // Send through AppKit's event dispatch so SwiftUI's key-event routing also runs.
    try #require(parent.isKeyWindow)
    NSApp.sendEvent(space)
    let release = try #require(
      NSEvent.keyEvent(
        with: .keyUp, location: .zero, modifierFlags: [],
        timestamp: 0.01, windowNumber: parent.windowNumber, context: nil,
        characters: " ", charactersIgnoringModifiers: " ", isARepeat: false, keyCode: 49))
    NSApp.sendEvent(release)
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.03))
    #expect(probe.events.filter { $0.kind == 1 }.count == 1)
    #expect(controller.pendingSubmission == 1)
    #expect(controller.models[1]?.item.checked == false)
    #expect(
      controller.update(
        try .decode(
          generalSwitchPayload([
            "sequence": 2, "acknowledgedSubmission": 1,
          ])), webview: webview) == 1)
    probe.accepted = 0
    controller.toggle(2, value: true)
    #expect(controller.closed)
    #expect(controller.overlay.superview == nil)
    #expect(probe.closes == 1)
    controller.finish()
    #expect(probe.closes == 1)
  }

  @Test @MainActor func undersizedOrRejectedFramesCannotEmitNewFrameEvents() throws {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    let probe = GeneralSwitchProbe()
    let controller = GeneralSwitchesController(
      frame: try .decode(generalSwitchPayload()),
      webview: webview, callback: generalSwitchEvent, closed: generalSwitchClosed,
      context: probe.context)
    try #require(controller.attach())
    defer { controller.finish() }
    var object = try #require(
      JSONSerialization.jsonObject(with: generalSwitchPayload(["sequence": 2])) as? [String: Any])
    var items = try #require(object["items"] as? [[String: Any]])
    items[0]["rect"] = ["x": 620, "y": 115, "width": 34, "height": 20]
    object["items"] = items
    let undersized = try GeneralSwitchesFrame.decode(JSONSerialization.data(withJSONObject: object))
    #expect(controller.update(undersized, webview: webview) == 0)
    #expect(controller.frame.sequence == 1)
    #expect(controller.overlay.isHidden)
    controller.toggle(1, value: true)
    #expect(probe.events.isEmpty)
    #expect(probe.closes == 0)
  }
}

extension GeneralSwitchesTests {
  @Test @MainActor func geometryInvalidationNotifiesOnceAndLayoutReusesMeasurement() throws {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    let probe = GeneralSwitchProbe()
    let controller = GeneralSwitchesController(
      frame: try .decode(generalSwitchPayload()),
      webview: webview, callback: generalSwitchEvent, closed: generalSwitchClosed,
      context: probe.context)
    try #require(controller.attach())
    defer { controller.finish() }
    #expect(controller.measurementCount == 6)
    NotificationCenter.default.post(name: NSWindow.didMoveNotification, object: parent)
    NotificationCenter.default.post(name: NSWindow.didMoveNotification, object: parent)
    #expect(
      probe.events == [.init(session: 1, sequence: 1, submission: 0, key: 0, kind: 5, value: 0)])
    #expect(controller.overlay.isHidden)
    #expect(
      controller.update(try .decode(generalSwitchPayload(["sequence": 2])), webview: webview) == 1)
    #expect(controller.measurementCount == 6)
    #expect(!controller.overlay.isHidden)
    #expect(
      controller.update(
        try .decode(generalSwitchPayload(["sequence": 3, "locale": "ja"])), webview: webview) == 1)
    #expect(controller.measurementCount == 12)
    probe.accepted = 0
    controller.invalidateGeometry()
    #expect(controller.closed)
    #expect(probe.closes == 1)
  }

  @Test @MainActor func synchronousAcknowledgementAndHideRetainCorrectSubmission() throws {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    let probe = GeneralSwitchProbe()
    let controller = GeneralSwitchesController(
      frame: try .decode(generalSwitchPayload()),
      webview: webview, callback: generalSwitchEvent, closed: generalSwitchClosed,
      context: probe.context)
    try #require(controller.attach())
    defer { controller.finish() }
    let acknowledgement = try GeneralSwitchesFrame.decode(
      generalSwitchPayload([
        "sequence": 2, "acknowledgedSubmission": 1, "items": [],
      ]))
    probe.reenter = {
      #expect(controller.update(acknowledgement, webview: webview) == 1)
    }
    controller.toggle(1, value: true)
    probe.reenter = nil
    #expect(controller.pendingSubmission == nil)
    #expect(controller.frame.sequence == 2)
    #expect(controller.overlay.isHidden)
    #expect(!controller.closed)
    #expect(probe.closes == 0)
    #expect(probe.events.count == 1)
  }

  @Test func wrongThreadDoesNotInspectViewOrReleaseContext() async {
    #expect(await Task.detached { generalSwitchesDismiss(1) }.value == 3)
    #expect(await Task.detached { generalSwitchesFocus(1, 1, 1) }.value == 3)
    #expect(await Task.detached { generalSwitchesSync(nil, nil, 0, nil, nil, 0) }.value == 3)
  }
}

extension GeneralSwitchesTests {
  @Test @MainActor func hiddenHostAcceptsFramesWithoutActivatingUntilFreshVisibleGeometry() throws {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    parent.orderOut(nil)
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.02))
    let probe = GeneralSwitchProbe()
    let controller = GeneralSwitchesController(
      frame: try .decode(generalSwitchPayload()),
      webview: webview, callback: generalSwitchEvent, closed: generalSwitchClosed,
      context: probe.context)
    try #require(controller.attach())
    defer { controller.finish() }
    #expect(!parent.isVisible)
    #expect(controller.overlay.isHidden)
    #expect(controller.focus(sequence: 1, key: 1) == 0)
    controller.toggle(1, value: true)
    #expect(probe.events.isEmpty)
    #expect(
      controller.update(try .decode(generalSwitchPayload(["sequence": 2])), webview: webview) == 1)
    #expect(controller.overlay.isHidden)
    parent.makeKeyAndOrderFront(nil)
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.03))
    #expect(probe.events.contains { $0.kind == 5 && $0.sequence == 2 })
    #expect(controller.overlay.isHidden)
    #expect(
      controller.update(try .decode(generalSwitchPayload(["sequence": 3])), webview: webview) == 1)
    #expect(!controller.overlay.isHidden)
    #expect(probe.closes == 0)
    parent.close()
    #expect(controller.closed)
    #expect(probe.closes == 1)
  }
}

extension GeneralSwitchesTests {
  @Test @MainActor func resizedWebviewRejectsOldViewportWithoutConsumingSequenceOrAcknowledgement()
    throws
  {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    let probe = GeneralSwitchProbe()
    let controller = GeneralSwitchesController(
      frame: try .decode(generalSwitchPayload()),
      webview: webview, callback: generalSwitchEvent, closed: generalSwitchClosed,
      context: probe.context)
    try #require(controller.attach())
    defer { controller.finish() }
    let host = try #require(controller.hosts[1])
    controller.toggle(1, value: true)
    webview.setFrameSize(NSSize(width: 400, height: 300))
    let eventsBefore = probe.events
    let measurementsBefore = controller.measurementCount
    let stale = try GeneralSwitchesFrame.decode(
      generalSwitchPayload([
        "sequence": 2, "acknowledgedSubmission": 1,
      ]))
    #expect(controller.update(stale, webview: webview) == 2)
    #expect(controller.frame.sequence == 1)
    #expect(controller.frame.acknowledgedSubmission == 0)
    #expect(controller.pendingSubmission == 1)
    #expect(controller.measurementCount == measurementsBefore)
    #expect(controller.overlay.isHidden)
    #expect(probe.events == eventsBefore)
    #expect(probe.closes == 0)
    let fresh = try GeneralSwitchesFrame.decode(
      generalSwitchPayload([
        "sequence": 2, "acknowledgedSubmission": 1,
        "viewport": ["width": 400, "height": 300],
        "clip": ["x": 0, "y": 0, "width": 400, "height": 300],
        "items": [
          [
            "key": 1, "label": "LAN", "help": "", "enabled": true,
            "checked": false, "rect": ["x": 300, "y": 100, "width": 54, "height": 24],
          ]
        ],
      ]))
    #expect(controller.update(fresh, webview: webview) == 1)
    #expect(controller.frame.sequence == 2)
    #expect(controller.frame.acknowledgedSubmission == 1)
    #expect(controller.pendingSubmission == nil)
    #expect(controller.hosts[1] === host)
    #expect(!controller.overlay.isHidden)
    #expect(probe.closes == 0)
  }

  @Test(.timeLimit(.minutes(1))) @MainActor
  func webkitReportsCSSViewportAgainstPublicPageZoom() async throws {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    for zoom in [1.0, 2.0] {
      webview.pageZoom = zoom
      let viewport: [Double] = try await withCheckedThrowingContinuation { continuation in
        webview.evaluateJavaScript("[window.innerWidth, window.innerHeight]") { value, error in
          if let error {
            continuation.resume(throwing: error)
          } else if let value = value as? [Double] {
            continuation.resume(returning: value)
          } else {
            continuation.resume(throwing: GeneralSwitchesFrame.Invalid.frame)
          }
        }
      }
      print(
        "Public WK pageZoom=\(webview.pageZoom) bounds=\(webview.bounds.size) DOMviewport=\(viewport)"
      )
      #expect(viewport.count == 2)
      #expect(abs(viewport[0] * zoom - webview.bounds.width) <= zoom)
      #expect(abs(viewport[1] * zoom - webview.bounds.height) <= zoom)
    }
  }
}

extension GeneralSwitchesTests {
  @Test @MainActor func staleInitialLayoutDoesNotTakeContextAndSameSessionCanRetry() throws {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    let probe = GeneralSwitchProbe()
    let session = nextGeneralSwitchTestSession()
    let pointer = Unmanaged.passUnretained(webview).toOpaque()
    let data = try generalSwitchPayload(["session": session])
    func sync() -> Int32 {
      data.withUnsafeBytes {
        generalSwitchesSync(
          pointer, $0.bindMemory(to: UInt8.self).baseAddress, $0.count,
          generalSwitchEvent, generalSwitchClosed, probe.context)
      }
    }
    webview.setFrameSize(.zero)
    #expect(sync() == 2)
    #expect(probe.closes == 0)
    #expect(probe.events.isEmpty)
    #expect(generalSwitchesDismiss(session) == 2)
    webview.setFrameSize(NSSize(width: 400, height: 300))
    #expect(sync() == 2)
    #expect(probe.closes == 0)
    webview.setFrameSize(NSSize(width: 800, height: 500))
    #expect(sync() == 1)
    #expect(generalSwitchesDismiss(session) == 1)
    #expect(probe.closes == 1)
  }

  @Test @MainActor func pageZoomAndViewportQuantizationCannotShrinkTheControlFootprint() throws {
    let (parent, webview) = generalSwitchHost()
    defer { parent.close() }
    webview.setFrameSize(NSSize(width: 799.5, height: 499.5))
    let frame = try GeneralSwitchesFrame.decode(generalSwitchPayload())
    #expect(GeneralSwitchesController.viewportIsCurrent(frame, in: webview))
    let probe = GeneralSwitchProbe()
    let controller = GeneralSwitchesController(
      frame: frame, webview: webview,
      callback: generalSwitchEvent, closed: generalSwitchClosed, context: probe.context)
    try #require(controller.attach())
    defer { controller.finish() }
    #expect(controller.hosts[1]?.frame.size == NSSize(width: 54, height: 24))
    webview.setFrameSize(NSSize(width: 800, height: 500))
    webview.pageZoom = 2
    #expect(!GeneralSwitchesController.viewportIsCurrent(frame, in: webview))
    let scaled = try GeneralSwitchesFrame.decode(
      generalSwitchPayload([
        "viewport": ["width": 400, "height": 250]
      ]))
    #expect(GeneralSwitchesController.viewportIsCurrent(scaled, in: webview))
  }
}

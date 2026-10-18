import AppKit
import Foundation
import SwiftUI
import Testing

@testable import CFMNativeDashboard

private let promptButtons: [[String: String]] = [
  ["id": "cancel", "title": "No", "role": "cancel"],
  ["id": "confirm", "title": "Yes", "role": "destructive"],
]

private func promptPayload(_ fields: [String: Any] = [:]) throws -> Data {
  var value: [String: Any] = [
    "version": 1, "session": 1, "sequence": 1, "acknowledgedSubmission": 0, "windowNumber": 1,
    "locale": "en", "appearance": "light", "title": "Delete profile",
    "message": "Delete “Work”? This removes the managed profile from the repository.",
    "buttons": promptButtons,
    "transportFailure": "The native dialog could not deliver this action. Close it and try again.",
  ]
  for (key, field) in fields { value[key] = field }
  return try JSONSerialization.data(withJSONObject: value)
}

private func promptPayload(removing key: String) throws -> Data {
  var value = try #require(JSONSerialization.jsonObject(with: promptPayload()) as? [String: Any])
  value.removeValue(forKey: key)
  return try JSONSerialization.data(withJSONObject: value)
}

/// A message of four-byte scalars and ASCII that makes the encoded frame
/// exactly `bytes` long while staying inside the message's scalar bound.
private func promptMessage(fillingFrameTo bytes: Int) throws -> String {
  let scalar = "\u{1F600}"
  let empty = try promptPayload(["message": ""]).count
  let unit = try promptPayload(["message": scalar]).count - empty
  let room = bytes - empty
  let message =
    String(repeating: scalar, count: room / unit) + String(repeating: "x", count: room % unit)
  try #require(message.unicodeScalars.count <= 4096)
  return message
}

@MainActor private final class PromptProbe {
  var payloads: [Data] = []
  var closedSessions: [UInt64] = []
  var accept: Int32 = 1
  var context: UInt { UInt(bitPattern: Unmanaged.passUnretained(self).toOpaque()) }

  func activation(_ index: Int) throws -> [String: Any] {
    try #require(payloads.indices.contains(index), "activation \(index) was never delivered")
    return try #require(JSONSerialization.jsonObject(with: payloads[index]) as? [String: Any])
  }
}

private let promptEvent: PromptDialogEventCallback = { context, _, bytes, count in
  guard let pointer = UnsafeRawPointer(bitPattern: context), let bytes, count > 0 else { return 0 }
  let payload = Data(bytes: bytes, count: count)
  let probe = Unmanaged<PromptProbe>.fromOpaque(pointer).takeUnretainedValue()
  return MainActor.assumeIsolated {
    probe.payloads.append(payload)
    return probe.accept
  }
}

private let promptClosed: PromptDialogClosedCallback = { context, session in
  guard let pointer = UnsafeRawPointer(bitPattern: context) else { return }
  let probe = Unmanaged<PromptProbe>.fromOpaque(pointer).takeUnretainedValue()
  MainActor.assumeIsolated { probe.closedSessions.append(session) }
}

@MainActor private func promptParent(width: CGFloat = 850, height: CGFloat = 603) -> NSWindow {
  NSApplication.shared.setActivationPolicy(.prohibited)
  let parent = NSWindow(
    contentRect: NSRect(x: 100, y: 100, width: width, height: height),
    styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
  parent.isReleasedWhenClosed = false
  parent.orderFront(nil)
  return parent
}

@MainActor private func promptKey(
  _ characters: String, code: UInt16, in window: NSWindow
) throws -> NSEvent {
  try #require(
    NSEvent.keyEvent(
      with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
      windowNumber: window.windowNumber, context: nil,
      characters: characters, charactersIgnoringModifiers: characters, isARepeat: false,
      keyCode: code))
}

@Suite(.serialized)
struct PromptDialogTests {
  @Test func strictFramesAndResourceBounds() throws {
    let frame = try PromptDialogFrame.decode(promptPayload())
    #expect(frame.buttons.map(\.id) == ["cancel", "confirm"])
    #expect(frame.buttons.map(\.role) == [.cancel, .destructive])
    for fields: [String: Any] in [
      ["version": 2], ["session": 0], ["sequence": 0], ["windowNumber": 0],
      ["sequence": 9_007_199_254_740_992 as UInt64],
      ["appearance": "system"], ["locale": "future"],
      ["acknowledgedSubmission": -1], ["acknowledgedSubmission": 9_007_199_254_740_992 as UInt64],
      ["title": ""], ["title": " \n"], ["title": String(repeating: "x", count: 161)],
      ["message": String(repeating: "x", count: 4097)], ["message": NSNull()],
      ["transportFailure": " "], ["transportFailure": String(repeating: "x", count: 1025)],
      // The host decides nothing through the frame, and states no result in it.
      ["command": "delete_profile"], ["busy": false], ["error": NSNull()], ["error": "Refused"],
    ] {
      #expect(throws: (any Error).self, "\(fields.keys.sorted())") {
        try PromptDialogFrame.decode(promptPayload(fields))
      }
    }
    for key in [
      "version", "session", "sequence", "acknowledgedSubmission", "windowNumber", "locale",
      "appearance", "title", "message", "buttons", "transportFailure",
    ] {
      #expect(throws: (any Error).self, "\(key)") {
        try PromptDialogFrame.decode(promptPayload(removing: key))
      }
    }
    #expect(try PromptDialogFrame.decode(promptPayload(["message": ""])).message.isEmpty)
    // Bounds count Unicode scalars, matching Rust chars and JS Array.from.
    let bounded = try PromptDialogFrame.decode(
      promptPayload([
        "title": String(repeating: "字", count: 160),
        "message": String(repeating: "x", count: 4096),
      ]))
    #expect(bounded.title.unicodeScalars.count == 160)
    #expect(bounded.message.unicodeScalars.count == 4096)
    #expect(throws: (any Error).self) {
      try PromptDialogFrame.decode(
        promptPayload(["title": String(repeating: "e\u{301}", count: 81)]))
    }
    #expect(throws: (any Error).self) { try PromptDialogFrame.decode(Data()) }
  }

  @Test func aWellFormedFrameIsRefusedAboveTheByteLimit() throws {
    // Every text stays inside its scalar bound, so only the size can refuse it.
    let limit = PromptDialogFrame.maximumBytes
    let exact = try promptPayload(["message": promptMessage(fillingFrameTo: limit)])
    #expect(exact.count == limit)
    #expect(try PromptDialogFrame.decode(exact).message.unicodeScalars.count <= 4096)
    let over = try promptPayload(["message": promptMessage(fillingFrameTo: limit + 1)])
    #expect(over.count == limit + 1)
    #expect(throws: (any Error).self) { try PromptDialogFrame.decode(over) }
  }

  @Test func buttonsAreAClosedOrderedContract() throws {
    let close = try PromptDialogFrame.decode(
      promptPayload(["buttons": [["id": "cancel", "title": "Close", "role": "cancel"]]]))
    #expect(close.buttons.count == 1)
    let three = try PromptDialogFrame.decode(
      promptPayload([
        "buttons": [
          ["id": "cancel", "title": "Cancel", "role": "cancel"],
          ["id": "a" + String(repeating: "0", count: 31), "title": "Keep", "role": "default"],
          ["id": "discard-all", "title": "Discard", "role": "destructive"],
        ]
      ]))
    #expect(three.buttons.map(\.role) == [.cancel, .default, .destructive])
    let invalid: [[[String: String]]] = [
      [],
      promptButtons + [
        ["id": "third", "title": "Third", "role": "default"],
        ["id": "fourth", "title": "Fourth", "role": "default"],
      ],
      [["id": "confirm", "title": "Yes", "role": "destructive"]],
      [promptButtons[1], promptButtons[0]],
      [promptButtons[0], ["id": "close", "title": "Close", "role": "cancel"]],
      [promptButtons[0], ["id": "cancel", "title": "Yes", "role": "destructive"]],
      [promptButtons[0], ["id": "confirm", "title": "Yes", "role": "primary"]],
      [promptButtons[0], ["id": "confirm", "title": "", "role": "destructive"]],
      [
        promptButtons[0],
        ["id": "confirm", "title": String(repeating: "x", count: 161), "role": "destructive"],
      ],
      [
        promptButtons[0],
        ["id": "confirm", "title": "Yes", "role": "destructive", "command": "delete_profile"],
      ],
      [promptButtons[0], ["id": "confirm", "title": "Yes"]],
    ]
    for buttons in invalid {
      #expect(throws: (any Error).self, "\(buttons)") {
        try PromptDialogFrame.decode(promptPayload(["buttons": buttons]))
      }
    }
    for id in [
      "", "Confirm", "1st", "a_b", "confirm ", "é", "a" + String(repeating: "0", count: 32),
      "a\u{301}",
    ] {
      #expect(throws: (any Error).self, "\(id.unicodeScalars.map(\.value))") {
        try PromptDialogFrame.decode(
          promptPayload([
            "buttons": [promptButtons[0], ["id": id, "title": "Yes", "role": "destructive"]]
          ]))
      }
    }
  }

  @Test @MainActor func activationWaitsForItsOwnAcknowledgement() throws {
    let probe = PromptProbe()
    let model = PromptDialogModel(
      try PromptDialogFrame.decode(promptPayload()),
      event: promptEvent, closed: promptClosed, context: probe.context)
    defer { model.finish() }
    let cancel = model.frame.buttons[0]
    let confirm = model.frame.buttons[1]
    #expect(!model.pending)
    #expect(model.available(cancel) && model.available(confirm))
    #expect(model.activate("confirm") == 1)
    #expect(model.pending)
    #expect(!model.available(confirm), "the action is unavailable until it is acknowledged")
    #expect(model.available(cancel), "cancelling stays available while the action runs")
    #expect(model.activate("confirm") == 0, "a pending activation cannot be repeated")
    #expect(probe.payloads.count == 1)
    let first = try probe.activation(0)
    #expect(Set(first.keys) == ["action", "submissionId", "buttonId"])
    #expect(first["action"] as? String == "activate")
    #expect(first["submissionId"] as? Int == 1)
    #expect(first["buttonId"] as? String == "confirm")
    #expect(
      model.update(
        try PromptDialogFrame.decode(promptPayload(["sequence": 2, "appearance": "dark"]))) == 1)
    #expect(model.pending, "theme-only updates cannot release a pending activation")
    #expect(
      model.update(
        try PromptDialogFrame.decode(
          promptPayload(["sequence": 3, "acknowledgedSubmission": 1]))) == 1)
    #expect(model.pendingSubmissionId == nil)
    #expect(!model.pending, "the host refused the action, so the prompt is usable again")
    #expect(model.available(cancel) && model.available(confirm))
    #expect(probe.closedSessions.isEmpty)
    #expect(model.activate("confirm") == 1)
    #expect(
      model.update(
        try PromptDialogFrame.decode(
          promptPayload(["sequence": 4, "acknowledgedSubmission": 1, "appearance": "light"])))
        == 1)
    #expect(model.pending, "the first acknowledgement is not an acknowledgement of the second")
    #expect(
      model.update(
        try PromptDialogFrame.decode(
          promptPayload(["sequence": 5, "acknowledgedSubmission": 2]))) == 1)
    #expect(!model.pending)
    #expect(try probe.activation(1)["submissionId"] as? Int == 2)
    #expect(probe.payloads.count == 2)
  }

  @Test @MainActor func staleFramesAndUnsentAcknowledgementsAreRejected() throws {
    let probe = PromptProbe()
    let model = PromptDialogModel(
      try PromptDialogFrame.decode(promptPayload()),
      event: promptEvent, closed: promptClosed, context: probe.context)
    defer { model.finish() }
    #expect(
      model.update(
        try PromptDialogFrame.decode(
          promptPayload(["sequence": 2, "acknowledgedSubmission": 1]))) == 0,
      "an activation the prompt never emitted cannot be acknowledged")
    #expect(model.frame.sequence == 1)
    #expect(model.activate("confirm") == 1)
    #expect(
      model.update(
        try PromptDialogFrame.decode(
          promptPayload(["sequence": 2, "acknowledgedSubmission": 1]))) == 1)
    #expect(
      model.update(
        try PromptDialogFrame.decode(
          promptPayload(["sequence": 2, "acknowledgedSubmission": 1, "title": "Replay"]))) == 0)
    #expect(
      model.update(
        try PromptDialogFrame.decode(
          promptPayload(["sequence": 3, "acknowledgedSubmission": 0]))) == 0,
      "an acknowledgement cannot decrease")
    #expect(
      model.update(
        try PromptDialogFrame.decode(
          promptPayload(["sequence": 3, "acknowledgedSubmission": 1, "windowNumber": 2]))) == 0)
    #expect(
      model.update(
        try PromptDialogFrame.decode(
          promptPayload(["session": 2, "sequence": 3, "acknowledgedSubmission": 1]))) == 2)
    #expect(model.frame.sequence == 2)
    #expect(model.frame.title == "Delete profile")
    #expect(PromptDialogModel.nextSubmission(after: 0) == 1)
    #expect(
      PromptDialogModel.nextSubmission(after: 9_007_199_254_740_990) == 9_007_199_254_740_991)
    #expect(PromptDialogModel.nextSubmission(after: 9_007_199_254_740_991) == nil)
  }

  @Test @MainActor func rejectedDeliveryShowsTheTransportFailureAndReEnables() throws {
    let probe = PromptProbe()
    probe.accept = 0
    let model = PromptDialogModel(
      try PromptDialogFrame.decode(promptPayload()),
      event: promptEvent, closed: promptClosed, context: probe.context)
    #expect(model.failure == nil)
    #expect(model.activate("confirm") == 0)
    #expect(!model.pending)
    #expect(model.failure == model.frame.transportFailure)
    #expect(model.submissionCount == 1, "a rejected callback consumes its ID")
    #expect(probe.closedSessions.isEmpty)
    probe.accept = 1
    #expect(model.activate("confirm") == 1)
    #expect(model.failure == nil)
    #expect(try probe.activation(1)["submissionId"] as? Int == 2)
    probe.accept = 0
    #expect(
      model.update(
        try PromptDialogFrame.decode(
          promptPayload(["sequence": 2, "acknowledgedSubmission": 2]))) == 1)
    #expect(model.activate("confirm") == 0)
    #expect(model.failure == model.frame.transportFailure)
    #expect(
      model.update(
        try PromptDialogFrame.decode(
          promptPayload(["sequence": 3, "acknowledgedSubmission": 2, "appearance": "dark"])))
        == 1)
    #expect(
      model.failure == model.frame.transportFailure,
      "a frame that acknowledges nothing new leaves the failure on screen")
    model.finish()
    model.finish()
    #expect(probe.closedSessions == [1])
    #expect(model.frame.buttons.allSatisfy { !model.available($0) }, "a closed prompt is inert")
    #expect(model.activate("confirm") == 2)
    #expect(probe.payloads.count == 3)
  }

  @Test @MainActor func cancelAndUnknownButtonsNeverActivateAndOneActionRunsAtATime() throws {
    let probe = PromptProbe()
    let model = PromptDialogModel(
      try PromptDialogFrame.decode(
        promptPayload([
          "buttons": [
            ["id": "cancel", "title": "Cancel", "role": "cancel"],
            ["id": "keep", "title": "Keep", "role": "default"],
            ["id": "discard", "title": "Discard", "role": "destructive"],
          ]
        ])),
      event: promptEvent, closed: promptClosed, context: probe.context)
    defer { model.finish() }
    #expect(model.activate("cancel") == 0)
    #expect(model.activate("confirm") == 0, "a button of another frame is unknown")
    #expect(model.submissionCount == 0)
    #expect(model.activate("keep") == 1)
    #expect(model.activate("discard") == 0, "a pending action holds every other action back")
    #expect(model.frame.buttons.map { model.available($0) } == [true, false, false])
    #expect(probe.payloads.count == 1)
    #expect(try probe.activation(0)["buttonId"] as? String == "keep")
  }

  @Test @MainActor func actualPanelIsAnActivatingCenteredChildWithTheWebWidthRule() throws {
    let parent = promptParent()
    defer { parent.close() }
    let probe = PromptProbe()
    let controller = PromptDialogWindow(
      frame: try PromptDialogFrame.decode(promptPayload(["windowNumber": parent.windowNumber])),
      parent: parent, event: promptEvent, closed: promptClosed, context: probe.context)
    #expect(controller.show())
    defer { controller.finish() }
    #expect(
      !controller.panel.styleMask.contains(.nonactivatingPanel),
      "a nonactivating panel can leave the parent inactive after dismissal")
    #expect(controller.panel.styleMask.contains(.borderless))
    #expect(controller.panel.canBecomeKey)
    #expect(!controller.panel.canBecomeMain)
    #expect(controller.panel.level == .normal)
    #expect(!controller.panel.hidesOnDeactivate)
    #expect(controller.panel.parent === parent)
    #expect(controller.panel.isVisible)
    #expect(controller.panel.frame.width == 360)
    let viewport = parent.convertToScreen(parent.contentLayoutRect)
    // AppKit places a window on whole points, so a content-sized height can
    // sit half a point off the exact center of an odd viewport.
    #expect(abs(controller.panel.frame.midX - viewport.midX) <= 0.5)
    #expect(abs(controller.panel.frame.midY - viewport.midY) <= 0.5)
    #expect(viewport.contains(controller.panel.frame))
    #expect(controller.panel.frame.height < 200, "a short confirmation is sized by its content")
    #expect(controller.panel.appearance?.name == .aqua)
    #expect(controller.panel.accessibilitySubrole() == .dialog)
    #expect(controller.panel.title == "Delete profile")
    #expect(
      controller.update(
        try PromptDialogFrame.decode(
          promptPayload([
            "windowNumber": parent.windowNumber, "sequence": 2, "appearance": "dark",
            "title": "Reset all settings",
          ]))) == 1)
    #expect(controller.panel.appearance?.name == .darkAqua)
    #expect(controller.panel.title == "Reset all settings")
    #expect(
      controller.update(
        try PromptDialogFrame.decode(
          promptPayload(["windowNumber": parent.windowNumber, "sequence": 2]))) == 0)
    #expect(controller.panel.appearance?.name == .darkAqua, "a stale frame cannot recolor it")
    #expect(probe.payloads.isEmpty)
    #expect(probe.closedSessions.isEmpty)
  }

  @Test @MainActor func narrowAndShortParentsBoundThePanelAndScrollItsMessage() throws {
    let parent = promptParent(width: 300, height: 260)
    defer { parent.close() }
    let probe = PromptProbe()
    let controller = PromptDialogWindow(
      frame: try PromptDialogFrame.decode(
        promptPayload([
          "windowNumber": parent.windowNumber,
          "message": String(repeating: "The engine refused this request. ", count: 120),
        ])),
      parent: parent, event: promptEvent, closed: promptClosed, context: probe.context)
    #expect(controller.show())
    defer { controller.finish() }
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
    let viewport = parent.convertToScreen(parent.contentLayoutRect)
    #expect(controller.panel.frame.width == viewport.width - 32)
    #expect(controller.panel.frame.height == viewport.height - 32)
    #expect(abs(controller.panel.frame.midX - viewport.midX) < 0.01)
    #expect(abs(controller.panel.frame.midY - viewport.midY) < 0.01)
    let content = try #require(controller.panel.contentView)
    content.layoutSubtreeIfNeeded()
    @MainActor func descendants(_ view: NSView) -> [NSView] {
      [view] + view.subviews.flatMap { descendants($0) }
    }
    let scroll = try #require(descendants(content).compactMap { $0 as? NSScrollView }.first)
    #expect(try #require(scroll.documentView).bounds.height > scroll.contentView.bounds.height)
    parent.setContentSize(NSSize(width: 850, height: 603))
    NotificationCenter.default.post(name: NSWindow.didResizeNotification, object: parent)
    #expect(controller.panel.frame.width == 360)
    let resized = parent.convertToScreen(parent.contentLayoutRect)
    #expect(abs(controller.panel.frame.midX - resized.midX) < 0.01)
    #expect(abs(controller.panel.frame.midY - resized.midY) < 0.01)
  }

  @Test @MainActor func escapeClosesOnceWithoutActivationAndReturnIsNeverADefault() throws {
    let parent = promptParent()
    defer { parent.close() }
    let probe = PromptProbe()
    let controller = PromptDialogWindow(
      frame: try PromptDialogFrame.decode(promptPayload(["windowNumber": parent.windowNumber])),
      parent: parent, event: promptEvent, closed: promptClosed, context: probe.context)
    #expect(controller.show())
    defer { controller.finish() }
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
    let escape = try promptKey("\u{1b}", code: 53, in: controller.panel)
    let enter = try promptKey("\r", code: 36, in: controller.panel)
    _ = controller.panel.performKeyEquivalent(with: enter)
    #expect(probe.payloads.isEmpty, "a destructive button must not answer Return")
    #expect(probe.closedSessions.isEmpty)
    #expect(controller.panel.isVisible)
    #expect(controller.windowShouldClose(controller.panel))
    #expect(controller.panel.performKeyEquivalent(with: escape))
    #expect(probe.closedSessions == [1])
    #expect(!controller.panel.isVisible)
    #expect(controller.panel.parent == nil)
    controller.cancel()
    controller.finish()
    #expect(probe.closedSessions == [1])
    #expect(probe.payloads.isEmpty, "closing never emits an activation")
  }

  @Test @MainActor func cancelAndEscapeStayAvailableWhileAnActivationIsPending() throws {
    let parent = promptParent()
    defer { parent.close() }
    let probe = PromptProbe()
    let controller = PromptDialogWindow(
      frame: try PromptDialogFrame.decode(promptPayload(["windowNumber": parent.windowNumber])),
      parent: parent, event: promptEvent, closed: promptClosed, context: probe.context)
    #expect(controller.show())
    defer { controller.finish() }
    #expect(controller.model.activate("confirm") == 1)
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
    #expect(controller.model.pending)
    #expect(
      controller.windowShouldClose(controller.panel),
      "the page left its dialog closable while the confirmed action ran")
    #expect(probe.closedSessions.isEmpty)
    // The key equivalent belongs to the cancel button, so it answers only
    // while that button is enabled.
    #expect(
      controller.panel.performKeyEquivalent(
        with: try promptKey("\u{1b}", code: 53, in: controller.panel)))
    #expect(probe.closedSessions == [1])
    #expect(!controller.panel.isVisible)
    #expect(
      controller.update(
        try PromptDialogFrame.decode(
          promptPayload([
            "windowNumber": parent.windowNumber, "sequence": 2, "acknowledgedSubmission": 1,
          ]))) == 2, "the acknowledgement of the running action finds the prompt closed")
    #expect(probe.payloads.count == 1, "closing neither repeats nor withdraws the activation")
  }

  @Test @MainActor func hiddenParentHidesThePanelWithoutClosingIt() throws {
    let parent = promptParent()
    defer { parent.close() }
    let probe = PromptProbe()
    let controller = PromptDialogWindow(
      frame: try PromptDialogFrame.decode(promptPayload(["windowNumber": parent.windowNumber])),
      parent: parent, event: promptEvent, closed: promptClosed, context: probe.context)
    #expect(controller.show())
    parent.orderOut(nil)
    NotificationCenter.default.post(
      name: NSWindow.didChangeOcclusionStateNotification, object: parent)
    #expect(!controller.panel.isVisible)
    #expect(!controller.model.closed)
    parent.orderFront(nil)
    NotificationCenter.default.post(
      name: NSWindow.didChangeOcclusionStateNotification, object: parent)
    #expect(controller.panel.isVisible)
    #expect(
      controller.panel.parent === parent,
      "a restored panel is attached again, so a click on the parent cannot cover it")
    NotificationCenter.default.post(name: NSApplication.didResignActiveNotification, object: NSApp)
    #expect(probe.closedSessions.isEmpty)
    parent.close()
    #expect(probe.closedSessions == [1], "closing the parent ends its prompt exactly once")
    #expect(!controller.panel.isVisible)
    controller.finish()
    #expect(probe.closedSessions == [1])
    #expect(probe.payloads.isEmpty)
  }

  @Test @MainActor func focusReturnsToThePriorResponderOfAVisibleParentOnly() throws {
    final class Focusable: NSView { override var acceptsFirstResponder: Bool { true } }
    let parent = promptParent()
    defer { parent.close() }
    let prior = Focusable(frame: NSRect(x: 20, y: 20, width: 80, height: 24))
    parent.contentView?.addSubview(prior)
    #expect(parent.makeFirstResponder(prior))
    let probe = PromptProbe()
    let controller = PromptDialogWindow(
      frame: try PromptDialogFrame.decode(promptPayload(["windowNumber": parent.windowNumber])),
      parent: parent, event: promptEvent, closed: promptClosed, context: probe.context)
    #expect(controller.show())
    #expect(parent.makeFirstResponder(nil))
    #expect(parent.firstResponder === parent)
    controller.finish()
    #expect(probe.closedSessions == [1])
    // This process is never the active application, so closing the prompt
    // must not move anyone's keyboard focus.
    #expect(!NSApp.isActive)
    #expect(parent.firstResponder === parent)
    controller.returnFocusToParent()
    #expect(parent.firstResponder === prior)
    #expect(parent.makeFirstResponder(nil))
    parent.orderOut(nil)
    controller.returnFocusToParent()
    #expect(parent.firstResponder === parent, "a hidden parent is left alone")
  }

  @Test @MainActor func abiOwnsContextUntilForcedDismissExactlyOnce() throws {
    // Declared first, so it outlives the parent's close, which ends any
    // prompt a failed expectation left presented.
    let probe = PromptProbe()
    let parent = promptParent()
    defer { parent.close() }
    @MainActor func wire(
      _ session: UInt64, _ sequence: UInt64 = 1, acknowledged: UInt64 = 0, window: Int? = nil
    ) throws -> Data {
      try promptPayload([
        "windowNumber": window ?? parent.windowNumber, "session": session, "sequence": sequence,
        "acknowledgedSubmission": acknowledged,
      ])
    }
    @MainActor func present(_ data: Data) -> Int32 {
      data.withUnsafeBytes {
        promptDialogPresent(
          $0.bindMemory(to: UInt8.self).baseAddress, $0.count, promptEvent,
          promptClosed, probe.context)
      }
    }
    @MainActor func update(_ data: Data) -> Int32 {
      data.withUnsafeBytes {
        promptDialogUpdate($0.bindMemory(to: UInt8.self).baseAddress, $0.count)
      }
    }
    #expect(try present(wire(70_001)) == 1)
    #expect(try present(wire(70_002)) == 1)
    #expect(probe.closedSessions == [70_001])
    #expect(try present(wire(70_001)) == 2)
    #expect(try update(wire(70_001, 2)) == 2, "a superseded session cannot update its successor")
    #expect(try update(wire(70_002, 2)) == 1)
    #expect(try update(wire(70_002, 2)) == 0, "a replayed sequence is rejected")
    #expect(try update(wire(70_002, 3, window: parent.windowNumber + 1)) == 0)
    #expect(try update(wire(70_002, 3, acknowledged: 1)) == 0)
    #expect(promptDialogDismiss(70_001) == 2)
    #expect(promptDialogDismiss(70_002) == 1)
    #expect(promptDialogDismiss(70_002) == 2)
    #expect(try update(wire(70_002, 3)) == 2)
    #expect(probe.closedSessions == [70_001, 70_002])
    #expect(promptDialogPresent(nil, 16, promptEvent, promptClosed, probe.context) == 0)
    #expect(try present(wire(70_003, acknowledged: 1)) == 0)
    #expect(try present(wire(70_003, window: parent.windowNumber + 1)) == 0)
    let oversized = try promptPayload([
      "windowNumber": parent.windowNumber, "session": 70_003,
      "message": promptMessage(fillingFrameTo: PromptDialogFrame.maximumBytes + 1),
    ])
    #expect(oversized.count > PromptDialogFrame.maximumBytes)
    #expect(present(oversized) == 0, "a well-formed frame above the byte limit is refused")
    #expect(probe.closedSessions == [70_001, 70_002], "a rejected present retains nothing")
    #expect(probe.payloads.isEmpty)
  }

  @Test @MainActor func messageKeepsThePageLineHeight() throws {
    let probe = PromptProbe()
    @MainActor func height(_ message: String) throws -> CGFloat {
      let model = PromptDialogModel(
        try PromptDialogFrame.decode(promptPayload(["message": message])),
        event: promptEvent, closed: promptClosed, context: probe.context)
      defer { model.finish() }
      let host = NSHostingView(
        rootView: PromptDialogContent(model: model, cancel: {}).frame(width: 360))
      host.appearance = NSAppearance(named: .aqua)
      return host.fittingSize.height
    }
    let none = try height("")
    let one = try height("One")
    let many = try height(Array(repeating: "Line", count: 41).joined(separator: "\n"))
    // `.glass-dialog-copy` is 13px text at `line-height: 1.45`, one 12px gap
    // below the title; forty further lines make the pitch exact to a pixel.
    #expect(abs((many - one) / 40 - 18.85) <= 0.05, "line pitch \((many - one) / 40)")
    #expect(abs((one - none) - (12 + 18.85)) <= 0.5, "one line adds \(one - none)")
    // The page leading is added to the system's own 16 pt line, which is the
    // pitch of the same text without it.
    @MainActor func unstyled(_ lines: Int) -> CGFloat {
      let text = Array(repeating: "Line", count: lines).joined(separator: "\n")
      return NSHostingView(rootView: Text(text).font(.system(size: 13, weight: .medium)))
        .fittingSize.height
    }
    #expect((unstyled(11) - unstyled(1)) / 10 == 16)
  }

  @Test @MainActor func hostDismissClosesAPendingPromptExactlyOnce() throws {
    let parent = promptParent()
    defer { parent.close() }
    let probe = PromptProbe()
    let controller = PromptDialogWindow(
      frame: try PromptDialogFrame.decode(
        promptPayload(["windowNumber": parent.windowNumber, "session": 9])),
      parent: parent, event: promptEvent, closed: promptClosed, context: probe.context)
    #expect(controller.show())
    #expect(controller.model.activate("confirm") == 1)
    #expect(probe.closedSessions.isEmpty, "an activation alone never closes the prompt")
    controller.finish()
    #expect(probe.closedSessions == [9], "the host may dismiss while its action is pending")
    #expect(!controller.panel.isVisible)
    controller.finish()
    #expect(probe.closedSessions == [9])
    #expect(controller.model.activate("confirm") == 2)
    #expect(
      controller.update(
        try PromptDialogFrame.decode(
          promptPayload([
            "windowNumber": parent.windowNumber, "session": 9, "sequence": 2,
            "acknowledgedSubmission": 1,
          ]))) == 2)
    #expect(probe.payloads.count == 1)
  }

  @Test func wrongThreadNeverEntersAppKit() async throws {
    // The frame is well formed, so status 3 can only come from the thread check.
    let frame = try promptPayload()
    let presented = await Task.detached {
      frame.withUnsafeBytes {
        promptDialogPresent(
          $0.bindMemory(to: UInt8.self).baseAddress, $0.count, promptEvent, promptClosed, 0)
      }
    }.value
    #expect(presented == 3)
    let updated = await Task.detached {
      frame.withUnsafeBytes {
        promptDialogUpdate($0.bindMemory(to: UInt8.self).baseAddress, $0.count)
      }
    }.value
    #expect(updated == 3)
    #expect(await Task.detached { promptDialogDismiss(70_002) }.value == 3)
  }
}

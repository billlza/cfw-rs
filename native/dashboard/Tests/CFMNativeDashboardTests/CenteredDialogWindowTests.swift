import AppKit
import SwiftUI
import Testing

@testable import CFMNativeDashboard

struct CenteredDialogWindowTests {
  @MainActor private func fitting(_ view: some View) -> NSSize {
    let host = NSHostingView(rootView: view)
    host.appearance = NSAppearance(named: .aqua)
    return host.fittingSize
  }

  @MainActor private func button(_ kind: DialogButton.Kind, _ size: ControlSize) -> NSSize {
    fitting(DialogButton(title: "No", kind: kind, action: {}).controlSize(size))
  }

  @Test @MainActor func buttonsUseTheSystemSizeNearestThePagePill() {
    // `.glass-btn` is `padding: 7px 14px` around one line of 13px text: about
    // 30px high, with 14px beside the label.
    let page: CGFloat = 30
    let chosen = button(.cancel, DialogButton.controlSize)
    #expect(chosen.height == 28)
    for size in ControlSize.allCases {
      let height = button(.cancel, size).height
      #expect(
        abs(chosen.height - page) <= abs(height - page), "\(size) at \(height) is nearer the pill")
    }
    let label = fitting(Text("No").font(.system(size: 13, weight: .semibold)))
    #expect((chosen.width - label.width) / 2 == 14)
    for kind in [DialogButton.Kind.action, .destructive] {
      #expect(button(kind, DialogButton.controlSize) == chosen, "\(kind)")
    }
    // Both dialog families lay their buttons out through this row.
    let row = fitting(DialogActions { DialogButton(title: "No", kind: .cancel, action: {}) })
    #expect(row.height == chosen.height + 4)
  }
}

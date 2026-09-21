import SwiftUI

struct OverviewView: View {
  let model: OverviewModel
  let onClose: () -> Void
  @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
  @Environment(\.colorSchemeContrast) private var contrast

  private func text(_ key: String) -> String {
    DashboardStrings.text(key, locale: model.frame?.locale ?? "en")
  }

  var body: some View {
    NavigationSplitView {
      VStack(alignment: .leading) {
        Label(text("overview"), systemImage: "network")
          .fontWeight(.semibold)
          .foregroundStyle(.primary)
          .padding(.horizontal, 16).padding(.vertical, 12)
          .accessibilityAddTraits(.isHeader)
        Spacer()
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 240)
      .safeAreaInset(edge: .bottom) {
        VStack(alignment: .leading, spacing: 4) {
          Text("Clash for Mac").font(.headline)
          Text("0.5 · SwiftUI").font(.caption).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading).padding()
      }
    } detail: {
      ScrollView {
        VStack(alignment: .leading, spacing: 28) {
          connectionHeading
          if let frame = model.frame {
            VStack(spacing: 0) {
              integration("core", symbol: "cpu", status: frame.core)
              Divider()
              integration("proxy", symbol: "arrow.triangle.branch", status: frame.systemProxy)
              Divider()
              integration("tunnel", symbol: "shield.lefthalf.filled", status: frame.tunnel)
            }
            .padding(.horizontal, 20)
            .background(.background, in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(.separator, lineWidth: 0.5))
            if let failure = frame.failure {
              VStack(alignment: .leading, spacing: 8) {
                Label(text("needsAttention"), systemImage: "exclamationmark.triangle")
                  .font(.headline).foregroundStyle(.orange)
                Text(failure).font(.callout).textSelection(.enabled)
              }.frame(maxWidth: .infinity, alignment: .leading)
            }
          }
          if model.deliveryFailure {
            Label(text("deliveryFailed"), systemImage: "exclamationmark.triangle.fill")
              .foregroundStyle(.red).accessibilityAddTraits(.updatesFrequently)
          }
          Text(text("observationOnly")).font(.callout).foregroundStyle(.secondary)
        }
        .padding(32)
        .frame(maxWidth: 860, alignment: .leading)
        .frame(maxWidth: .infinity)
      }
      .contentMargins(.top, 24, for: .scrollContent)
      .background(Color(nsColor: .windowBackgroundColor))
      .navigationTitle(text("overview"))
      .toolbar {
        ToolbarItem {
          if #available(macOS 26, *), !reduceTransparency, contrast != .increased {
            GlassEffectContainer {
              Button(action: onClose) {
                Label(text("closeOverview"), systemImage: "xmark")
              }.buttonStyle(.glass)
            }
          } else {
            Button(action: onClose) {
              Label(text("closeOverview"), systemImage: "xmark")
            }.buttonStyle(.bordered)
          }
        }
      }
    }
    .frame(minWidth: 850, minHeight: 603)
  }

  private var connectionHeading: some View {
    HStack(alignment: .center, spacing: 20) {
      Image(systemName: model.frame?.phase == .active ? "shield.lefthalf.filled" : "network")
        .font(.system(size: 40, weight: .light))
        .foregroundStyle(model.frame?.phase == .active ? Color.accentColor : .secondary)
        .frame(width: 76, height: 76)
        .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 22))
        .accessibilityHidden(true)
      VStack(alignment: .leading, spacing: 7) {
        Text(
          text(
            model.frame?.phase == .active ? "connected" : model.frame?.phase.rawValue ?? "loading")
        )
        .font(.largeTitle.weight(.semibold))
        Text(text("connectionDetail")).font(.callout).foregroundStyle(.secondary)
      }
    }
    .accessibilityElement(children: .combine)
  }

  private func integration(_ key: String, symbol: String, status: IntegrationStatus) -> some View {
    HStack(spacing: 14) {
      Image(systemName: symbol).font(.title3).frame(width: 28).foregroundStyle(.secondary)
      Text(text(key)).font(.body.weight(.medium))
      Spacer()
      Label(
        text(status.rawValue), systemImage: status == .active ? "checkmark.circle.fill" : "circle"
      )
      .foregroundStyle(status == .active ? Color.accentColor : .secondary)
    }.padding(.vertical, 20).accessibilityElement(children: .combine)
  }
}

enum DashboardStrings {
  static func text(_ key: String, locale: String) -> String {
    guard
      let url = Bundle.module.url(
        forResource: "Localizable", withExtension: "strings", subdirectory: nil,
        localization: locale),
      let bundle = Bundle(url: url.deletingLastPathComponent())
    else { return key }
    return bundle.localizedString(forKey: key, value: nil, table: nil)
  }
}

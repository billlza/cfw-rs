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
          Text("0.5 · " + text("developmentPreview")).font(.caption).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading).padding()
      }
    } detail: {
      ScrollView {
        VStack(alignment: .leading, spacing: 28) {
          connectionHeading
          if let frame = model.frame {
            VStack(spacing: 0) {
              integration("core", symbol: "cpu", status: frame.core, control: .core)
              Divider()
              integration(
                "proxy", symbol: "arrow.triangle.branch", status: frame.systemProxy,
                control: .systemProxy)
              Divider()
              integration(
                "tunnel", symbol: "shield.lefthalf.filled", status: frame.tunnel, control: .tunnel)
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
          if model.frame?.phase == .approval {
            Text(text("approvalHelp")).font(.callout).foregroundStyle(.secondary)
          }
          if model.pendingRequest != nil || model.frame?.command?.pending == true {
            HStack {
              ProgressView().controlSize(.small)
              Text(text("applyingChange"))
            }
            .accessibilityElement(children: .combine)
          }
          if let error = model.actionError {
            VStack(alignment: .leading, spacing: 6) {
              Label(text("changeFailed"), systemImage: "exclamationmark.triangle")
                .foregroundStyle(.orange)
              Text(error).textSelection(.enabled)
            }.font(.callout)
          }
          if model.deliveryFailure {
            Label(text("deliveryFailed"), systemImage: "exclamationmark.triangle.fill")
              .foregroundStyle(.red).accessibilityAddTraits(.updatesFrequently)
          }
          Text(text("controlsHelp")).font(.callout).foregroundStyle(.secondary)
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
              HStack {
                Button(action: toggleCore) {
                  Label(
                    text(model.frame?.controls.core.enabled == true ? "stopCore" : "startCore"),
                    systemImage: "power")
                }.buttonStyle(.glassProminent).disabled(!model.canSubmit(.core))
                Button(action: onClose) {
                  Label(text("closeOverview"), systemImage: "xmark")
                }.buttonStyle(.glass)
              }
            }
          } else {
            HStack {
              Button(action: toggleCore) {
                Label(
                  text(model.frame?.controls.core.enabled == true ? "stopCore" : "startCore"),
                  systemImage: "power")
              }.buttonStyle(.borderedProminent).disabled(!model.canSubmit(.core))
              Button(action: onClose) {
                Label(text("closeOverview"), systemImage: "xmark")
              }.buttonStyle(.bordered)
            }
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

  private func toggleCore() {
    model.request(.core, enabled: model.frame?.controls.core.enabled != true)
  }

  private func integration(
    _ key: String, symbol: String, status: IntegrationStatus, control: NativeControl
  ) -> some View {
    VStack(alignment: .leading, spacing: 8) {
      HStack(spacing: 14) {
        Image(systemName: symbol).font(.title3).frame(width: 28).foregroundStyle(.secondary)
        Text(text(key)).font(.body.weight(.medium))
        Spacer()
        Label(
          text(status.rawValue), systemImage: status == .active ? "checkmark.circle.fill" : "circle"
        )
        .foregroundStyle(status == .active ? Color.accentColor : .secondary)
        if model.frame?.controls.value(for: control).retry == true {
          Button(text(model.frame?.phase == .approval ? "continueApproval" : "retryChange")) {
            model.request(control, enabled: true)
          }
          .disabled(!model.canSubmit(control))
          .accessibilityLabel(
            text(model.frame?.phase == .approval ? "continueApproval" : "retryChange") + " · "
              + text(key))
        }
        Toggle(
          text(key),
          isOn: Binding(
            get: { model.frame?.controls.value(for: control).enabled == true },
            set: { model.request(control, enabled: $0) }
          )
        ).labelsHidden().toggleStyle(.switch).disabled(!model.canSubmit(control))
          .accessibilityLabel(text(key))
      }
      if let reason = model.frame?.controls.value(for: control).reason {
        Text(reason).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
      }
    }.padding(.vertical, 20).accessibilityElement(children: .contain)
  }

}

enum DashboardStrings {
  private static let resourceBundleName = "CFMNativeDashboard_CFMNativeDashboard"
  private static let libraryName = "libCFMNativeDashboard.dylib"

  /// Where the resource bundle is, by the kind of host this code runs in.
  enum ResourceLocation: Equatable {
    /// A packaged app carries the bundle inside Contents/Resources.
    case applicationResources
    /// An unbundled development or test executable loads this code from the
    /// dashboard library, and the bundle sits beside that library. A bundle
    /// beside the executable is never read: where the build tool puts an
    /// executable is its own business, and nothing keeps a copy there current.
    case besideLibrary(URL)
    /// SwiftPM's own products compile this code in and keep its lookup.
    case package
  }

  static func resourceLocation(mainBundle: URL, image: String?) -> ResourceLocation {
    if mainBundle.pathExtension == "app" { return .applicationResources }
    guard let image else { return .package }
    let library = URL(fileURLWithPath: image)
    guard library.lastPathComponent == libraryName else { return .package }
    return .besideLibrary(
      library.deletingLastPathComponent().appendingPathComponent(
        resourceBundleName + ".bundle", isDirectory: true))
  }

  /// The file this code was loaded from.
  private static var imagePath: String? {
    var info = Dl_info()
    guard dladdr(#dsohandle, &info) != 0, let name = info.dli_fname else { return nil }
    return String(cString: name)
  }

  private static var resourceBundle: Bundle? {
    switch resourceLocation(mainBundle: Bundle.main.bundleURL, image: imagePath) {
    case .applicationResources:
      guard let url = Bundle.main.url(forResource: resourceBundleName, withExtension: "bundle")
      else { return nil }
      return Bundle(url: url)
    case .besideLibrary(let url): return Bundle(url: url)
    case .package: return Bundle.module
    }
  }

  static func text(_ key: String, locale: String) -> String {
    guard
      let resources = resourceBundle,
      let url = resources.url(
        forResource: "Localizable", withExtension: "strings", subdirectory: nil,
        localization: locale),
      let bundle = Bundle(url: url.deletingLastPathComponent())
    else { return key }
    return bundle.localizedString(forKey: key, value: nil, table: nil)
  }
}

import CFWSharedProtocol
import Foundation

#if canImport(Libbox)
  import Libbox
#endif

enum LibboxConfigurationDocument {
  private static let maximumBytes = Int(NativeProtocolConstants.maximumConfigurationBytes)

  static func text(from data: Data) throws -> String {
    guard !data.isEmpty, data.count <= maximumBytes else {
      throw LibboxRuntimeError.invalidConfigurationSize(data.count)
    }
    guard let text = String(data: data, encoding: .utf8) else {
      throw LibboxRuntimeError.invalidConfigurationEncoding
    }
    let object: Any
    do {
      object = try JSONSerialization.jsonObject(with: data)
    } catch {
      throw LibboxRuntimeError.invalidConfigurationJSON
    }
    guard object is [String: Any] else {
      throw LibboxRuntimeError.invalidConfigurationJSON
    }
    return text
  }
}

public protocol LibboxConfigurationChecking: Sendable {
  /// Parses and validates a complete in-memory configuration. Implementations
  /// must not create or start a service, bind listeners, or apply networking
  /// state.
  func check(configuration: Data) throws
}

public struct SourceBuiltLibboxConfigurationChecker: LibboxConfigurationChecking, Sendable {
  public init() {}

  public func check(configuration: Data) throws {
    let configurationText = try LibboxConfigurationDocument.text(from: configuration)
    #if canImport(Libbox)
      // gomobile's public CheckConfig API accepts NSString, so Swift creates a
      // transient immutable String that cannot be explicitly zeroized. Its
      // scope ends at this call; the caller owns and erases the source Data.
      var error: NSError?
      guard LibboxCheckConfig(configurationText, &error) else {
        throw LibboxRuntimeError.configurationCheckFailed(
          error?.localizedDescription ?? "libbox rejected the configuration without a diagnostic"
        )
      }
    #else
      _ = configurationText
      throw LibboxRuntimeError.libboxUnavailable
    #endif
  }
}

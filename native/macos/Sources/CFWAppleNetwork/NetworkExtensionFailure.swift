import Foundation

public enum NetworkExtensionFailureDisposition: Equatable, Sendable {
  case permissionDenied
  case unavailable
}

/// Stable, bounded provenance for an NSError returned by NetworkExtension.
/// Policy is derived only from the official domain/code pair; localized text is
/// retained solely as a bounded diagnostic and never drives classification.
public struct NetworkExtensionOperationFailure: Codable, Equatable, Sendable {
  public static let maximumDomainLength = 128
  public static let maximumDiagnosticLength = 256

  public let domain: String
  public let code: Int
  public let diagnostic: String

  public init(_ error: Error) {
    let error = error as NSError
    self.init(
      domain: error.domain,
      code: error.code,
      diagnostic: error.localizedDescription
    )
  }

  public init(domain: String, code: Int, diagnostic: String) {
    self.domain = Self.bounded(domain, maximumLength: Self.maximumDomainLength)
    self.code = code
    self.diagnostic = Self.bounded(
      diagnostic,
      maximumLength: Self.maximumDiagnosticLength
    )
  }

  public var disposition: NetworkExtensionFailureDisposition {
    if domain == NSPOSIXErrorDomain,
      code == Int(POSIXErrorCode.EACCES.rawValue)
        || code == Int(POSIXErrorCode.EPERM.rawValue)
    {
      return .permissionDenied
    }
    if domain == NSCocoaErrorDomain,
      code == CocoaError.Code.fileReadNoPermission.rawValue
        || code == CocoaError.Code.fileWriteNoPermission.rawValue
    {
      return .permissionDenied
    }
    return .unavailable
  }

  private static func bounded(_ value: String, maximumLength: Int) -> String {
    var result = ""
    var byteCount = 0
    for scalar in value.unicodeScalars {
      let output: Unicode.Scalar =
        CharacterSet.controlCharacters.contains(scalar) ? " " : scalar
      let scalarBytes = String(output).utf8.count
      guard byteCount + scalarBytes <= maximumLength else { break }
      result.unicodeScalars.append(output)
      byteCount += scalarBytes
    }
    return result
  }
}

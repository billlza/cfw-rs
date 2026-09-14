import Foundation

public enum ProfileProbeServiceFailure: Int, Sendable {
  case busy = 1
  case invalidRequest = 2
  case executionFailed = 3

  public static let domain = "com.bill.clashformac.profile-probe"

  public var error: NSError { NSError(domain: Self.domain, code: rawValue) }

  public var failure: EngineFailure {
    switch self {
    case .busy:
      EngineFailure(
        code: "profile-probe-busy",
        message: "The previous latency batch is finishing. Retry shortly.", isRetryable: true)
    case .invalidRequest:
      EngineFailure(
        code: "profile-probe-invalid", message: "The latency request is invalid.",
        isRetryable: false)
    case .executionFailed:
      EngineFailure(
        code: "profile-probe-failed",
        message: "The temporary latency runtime could not start or finish its cleanup.",
        isRetryable: true)
    }
  }
}

/// Explicit application traffic, independent of System Proxy/TUN ownership.
public struct ProfileDelayTestRequest: Codable, Equatable, Sendable {
  public let audience: CredentialAudience
  public let configJSON: String
  public let credentialSlots: [CredentialSlot]
  public let proxies: [String]
  public let timeoutMS: UInt16
  public let targetURL: String?
  public let expectedStatus: String?

  public init(
    audience: CredentialAudience, configJSON: String, credentialSlots: [CredentialSlot],
    proxies: [String], timeoutMS: UInt16, targetURL: String? = nil, expectedStatus: String? = nil
  ) throws {
    guard !configJSON.isEmpty,
      configJSON.utf8.count <= Int(NativeProtocolConstants.maximumConfigurationBytes),
      let root = try JSONSerialization.jsonObject(with: Data(configJSON.utf8)) as? [String: Any],
      Set(root.keys).isSubset(of: ["outbounds", "endpoints", "dns", "route"])
    else { throw NativeBridgeProtocolError.invalidConfiguration }
    try ConfigurationCredentialSlots.validate(credentialSlots, root: root)
    try Self.validateTargets(proxies, timeoutMS: timeoutMS)
    try Self.validateTargetURL(targetURL ?? "", expectedStatus: expectedStatus ?? "")
    self.audience = audience
    self.configJSON = configJSON
    self.credentialSlots = credentialSlots
    self.proxies = proxies
    self.timeoutMS = timeoutMS
    self.targetURL = targetURL
    self.expectedStatus = expectedStatus
  }

  public static func validateTargetURL(_ target: String, expectedStatus: String) throws {
    if !target.isEmpty {
      guard target.utf8.count <= 2048,
        !target.contains(where: {
          $0.isWhitespace || $0.asciiValue.map({ $0 < 32 || $0 == 127 }) == true
        }),
        let url = URLComponents(string: target), ["http", "https"].contains(url.scheme),
        let host = url.host, !host.isEmpty, url.user == nil, url.password == nil,
        url.fragment == nil, url.port != 0
      else { throw NativeBridgeProtocolError.invalidCommand }
    }
    guard expectedStatus.utf8.count <= 128 else { throw NativeBridgeProtocolError.invalidCommand }
    if expectedStatus.isEmpty { return }
    for item in expectedStatus.split(separator: "/", omittingEmptySubsequences: false) {
      let parts = item.split(separator: "-", omittingEmptySubsequences: false)
      guard (1...2).contains(parts.count) else { throw NativeBridgeProtocolError.invalidCommand }
      var codes: [UInt16] = []
      for part in parts {
        guard part.utf8.count == 3, part.utf8.allSatisfy({ (48...57).contains($0) }),
          let code = UInt16(part), (100...599).contains(code)
        else { throw NativeBridgeProtocolError.invalidCommand }
        codes.append(code)
      }
      if codes.count == 2, codes[0] > codes[1] { throw NativeBridgeProtocolError.invalidCommand }
    }
  }

  public static func validateTargets(_ proxies: [String], timeoutMS: UInt16) throws {
    guard (1...32).contains(proxies.count), Set(proxies).count == proxies.count,
      proxies.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 512 }),
      (100...10_000).contains(timeoutMS)
    else { throw NativeBridgeProtocolError.invalidCommand }
  }

  private enum CodingKeys: String, CodingKey {
    case audience, proxies
    case configJSON = "config_json"
    case credentialSlots = "credential_slots"
    case timeoutMS = "timeout_ms"
    case targetURL = "target_url"
    case expectedStatus = "expected_status"
  }

  public init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      audience: values.decode(CredentialAudience.self, forKey: .audience),
      configJSON: values.decode(String.self, forKey: .configJSON),
      credentialSlots: values.decode([CredentialSlot].self, forKey: .credentialSlots),
      proxies: values.decode([String].self, forKey: .proxies),
      timeoutMS: values.decode(UInt16.self, forKey: .timeoutMS),
      targetURL: values.decodeIfPresent(String.self, forKey: .targetURL),
      expectedStatus: values.decodeIfPresent(String.self, forKey: .expectedStatus))
  }
}

public enum ProfileProbeFailure: String, Codable, Sendable {
  case timeout
  case notFound = "not_found"
  case probeFailed = "probe_failed"
}

public struct ProfileProxyDelay: Codable, Equatable, Sendable {
  public let name: String
  public let delay: UInt32?
  public let errorKind: ProfileProbeFailure?

  public init(name: String, delay: UInt32?, errorKind: ProfileProbeFailure?) throws {
    guard !name.isEmpty, name.utf8.count <= 512,
      (delay != nil) != (errorKind != nil), delay.map({ $0 > 0 }) ?? true
    else { throw NativeBridgeProtocolError.invalidCommand }
    self.name = name
    self.delay = delay
    self.errorKind = errorKind
  }

  private enum CodingKeys: String, CodingKey {
    case name, delay
    case errorKind = "error_kind"
  }

  public init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      name: values.decode(String.self, forKey: .name),
      delay: values.decodeIfPresent(UInt32.self, forKey: .delay),
      errorKind: values.decodeIfPresent(ProfileProbeFailure.self, forKey: .errorKind))
  }
}

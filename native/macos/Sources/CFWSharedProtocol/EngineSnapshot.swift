import Foundation

public enum EngineMode: String, Codable, CaseIterable, Sendable {
  case off
  case localProxy
  case systemProxy
  case tunnel
}

public enum EngineStateKind: String, Codable, CaseIterable, Sendable {
  case off
  case proxyStarting
  case proxyActive
  case proxyStopping
  case tunnelInstalling
  case awaitingApproval
  case tunnelStarting
  case tunnelActive
  case tunnelStopping
  case failed
}

public struct EngineFailure: Codable, Equatable, Sendable {
  public let code: String
  public let message: String
  public let isRetryable: Bool

  /// A failure under a raw code. Owners report through the typed codes
  /// (`ProxyAgentFailure`, `PacketTunnelFailureCode`), which fix each code's
  /// retry flag; this one is for decoding and tests.
  package init(code: String, message: String, isRetryable: Bool) {
    self.code = code
    self.message = message
    self.isRetryable = isRetryable
  }

  private enum CodingKeys: String, CodingKey {
    case code
    case message
    case isRetryable
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let code = try container.decode(String.self, forKey: .code)
    let message = try container.decode(String.self, forKey: .message)
    guard Self.isValidCode(code), Self.isValidMessage(message) else {
      throw ProtocolValidationError.invalidResponse
    }
    self.code = code
    self.message = message
    isRetryable = try container.decode(Bool.self, forKey: .isRetryable)
  }

  public func encode(to encoder: Encoder) throws {
    guard Self.isValidCode(code), Self.isValidMessage(message) else {
      throw ProtocolValidationError.invalidResponse
    }
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(code, forKey: .code)
    try container.encode(message, forKey: .message)
    try container.encode(isRetryable, forKey: .isRetryable)
  }

  private static func isValidCode(_ code: String) -> Bool {
    !code.isEmpty && code.utf8.count <= 64
      && code.utf8.allSatisfy {
        (97...122).contains($0) || (48...57).contains($0) || $0 == 45
      }
  }

  private static func isValidMessage(_ message: String) -> Bool {
    !message.isEmpty
      && message.utf8.count <= NativeProtocolConstants.maximumFailureMessageBytes
      && !message.unicodeScalars.contains {
        CharacterSet.controlCharacters.contains($0)
      }
  }
}

public struct EngineState: Codable, Equatable, Sendable {
  public let kind: EngineStateKind
  public let failure: EngineFailure?

  public init(kind: EngineStateKind, failure: EngineFailure? = nil) throws {
    guard (kind == .failed) == (failure != nil) else {
      throw ProtocolValidationError.invalidState
    }
    self.kind = kind
    self.failure = failure
  }

  fileprivate init(validatedKind kind: EngineStateKind, failure: EngineFailure?) {
    self.kind = kind
    self.failure = failure
  }

  public static let off = EngineState(validatedKind: .off, failure: nil)

  public static func failed(_ failure: EngineFailure) -> EngineState {
    EngineState(validatedKind: .failed, failure: failure)
  }

  private enum CodingKeys: String, CodingKey {
    case kind
    case failure
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let kind = try container.decode(EngineStateKind.self, forKey: .kind)
    let failure = try container.decodeIfPresent(EngineFailure.self, forKey: .failure)
    try self.init(kind: kind, failure: failure)
  }
}

public struct EngineSnapshot: Codable, Equatable, Sendable {
  public let mode: EngineMode
  public let state: EngineState
  public let configuration: ConfigurationDescriptor?
  public let sequence: UInt64

  public init(
    mode: EngineMode,
    state: EngineState,
    configuration: ConfigurationDescriptor?,
    sequence: UInt64
  ) throws {
    switch (mode, state.kind, configuration) {
    case (.off, .off, nil),
      (.off, .failed, _),
      (.localProxy, .proxyStarting, .some),
      (.localProxy, .proxyActive, .some),
      (.localProxy, .proxyStopping, .some),
      (.localProxy, .failed, _),
      (.systemProxy, .proxyStarting, .some),
      (.systemProxy, .proxyActive, .some),
      (.systemProxy, .proxyStopping, .some),
      (.systemProxy, .failed, _),
      (.tunnel, .tunnelInstalling, _),
      (.tunnel, .awaitingApproval, _),
      (.tunnel, .tunnelStarting, .some),
      (.tunnel, .tunnelActive, .some),
      (.tunnel, .tunnelStopping, .some),
      (.tunnel, .failed, _):
      break
    default:
      throw ProtocolValidationError.invalidState
    }
    if mode != .off, let configuration, configuration.slot.engineMode != mode {
      throw ProtocolValidationError.invalidState
    }
    self.mode = mode
    self.state = state
    self.configuration = configuration
    self.sequence = sequence
  }

  private init(
    validatedMode mode: EngineMode,
    state: EngineState,
    configuration: ConfigurationDescriptor?,
    sequence: UInt64
  ) {
    self.mode = mode
    self.state = state
    self.configuration = configuration
    self.sequence = sequence
  }

  private enum CodingKeys: String, CodingKey {
    case mode
    case state
    case configuration
    case sequence
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      mode: container.decode(EngineMode.self, forKey: .mode),
      state: container.decode(EngineState.self, forKey: .state),
      configuration: container.decodeIfPresent(
        ConfigurationDescriptor.self, forKey: .configuration),
      sequence: container.decode(UInt64.self, forKey: .sequence)
    )
  }

  public static let off = EngineSnapshot(
    validatedMode: .off,
    state: .off,
    configuration: nil,
    sequence: 0
  )

  public static func off(sequence: UInt64) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .off,
      state: .off,
      configuration: nil,
      sequence: sequence
    )
  }

  public static func proxyFailed(
    _ failure: EngineFailure,
    configuration: ConfigurationDescriptor?,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: configuration?.slot.engineMode ?? .systemProxy,
      state: .failed(failure),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func proxyStarting(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: configuration.slot.engineMode,
      state: EngineState(validatedKind: .proxyStarting, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func proxyActive(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: configuration.slot.engineMode,
      state: EngineState(validatedKind: .proxyActive, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func proxyStopping(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: configuration.slot.engineMode,
      state: EngineState(validatedKind: .proxyStopping, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func tunnelStarting(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .tunnel,
      state: EngineState(validatedKind: .tunnelStarting, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func tunnelActive(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .tunnel,
      state: EngineState(validatedKind: .tunnelActive, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func tunnelStopping(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .tunnel,
      state: EngineState(validatedKind: .tunnelStopping, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func tunnelFailed(
    _ failure: EngineFailure,
    configuration: ConfigurationDescriptor?,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .tunnel,
      state: .failed(failure),
      configuration: configuration,
      sequence: sequence
    )
  }
}

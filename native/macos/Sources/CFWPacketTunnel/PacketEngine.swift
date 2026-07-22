import CFWLibboxRuntime
import Foundation

public protocol PacketEngine: AnyObject {
  /// Takes ownership of packetFileDescriptor before returning, including when
  /// startup throws. Implementations must close it exactly once during failure
  /// cleanup or stop.
  func start(configuration: Data, packetFileDescriptor: Int32) throws
  func stop() throws
  func healthCheck() throws
}

public protocol PacketEngineFactory: Sendable {
  func makeEngine() throws -> any PacketEngine
}

public enum PacketEngineError: Error, Equatable, Sendable {
  case runtime(String)
}

public struct LibboxPacketEngineFactory: PacketEngineFactory {
  private let runtimeFactory: any LibboxServiceRuntimeFactory

  public init(
    runtimeFactory: any LibboxServiceRuntimeFactory = SourceBuiltLibboxRuntimeFactory()
  ) {
    self.runtimeFactory = runtimeFactory
  }

  public func makeEngine() throws -> any PacketEngine {
    do {
      return LibboxPacketEngine(
        runtime: try runtimeFactory.makeRuntime(role: .packetTunnel)
      )
    } catch {
      throw PacketEngineError.runtime(error.localizedDescription)
    }
  }
}

private final class LibboxPacketEngine: PacketEngine {
  private let runtime: any LibboxServiceRuntime

  init(runtime: any LibboxServiceRuntime) {
    self.runtime = runtime
  }

  func start(configuration: Data, packetFileDescriptor: Int32) throws {
    do {
      try runtime.start(
        configuration: configuration,
        packetFileDescriptor: packetFileDescriptor
      )
    } catch {
      throw PacketEngineError.runtime(error.localizedDescription)
    }
  }

  func stop() throws {
    do {
      try runtime.stop()
    } catch {
      throw PacketEngineError.runtime(error.localizedDescription)
    }
  }

  func healthCheck() throws {
    do {
      try runtime.healthCheck()
    } catch {
      throw PacketEngineError.runtime(error.localizedDescription)
    }
  }
}

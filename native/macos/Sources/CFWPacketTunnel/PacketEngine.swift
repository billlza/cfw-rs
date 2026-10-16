import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation

public protocol PacketEngine: AnyObject {
  /// Takes ownership of packetFileDescriptor before returning, including when
  /// startup throws. Implementations must close it exactly once during failure
  /// cleanup or stop, and must return by `deadline`.
  func start(configuration: Data, packetFileDescriptor: Int32, deadline: EngineStartDeadline)
    throws
  /// Stops the engine. It throws only when libbox could not close its instance;
  /// the engine is then spent, every later stop throws the same failure, and
  /// what the close left open is released only when the process ends.
  func stop() throws(LibboxInstanceUnclosable)
  func healthCheck() throws
}

public protocol PacketEngineFactory: Sendable {
  func makeEngine() throws -> any PacketEngine
}

public enum PacketEngineError: Error, Equatable, Sendable {
  case runtime(String)
  /// libbox did not finish starting by the start deadline and was interrupted.
  case startTimedOut
  case controllerEndpointConflict(port: UInt16)
  case mixedEndpointConflict(port: UInt16)
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

  func start(configuration: Data, packetFileDescriptor: Int32, deadline: EngineStartDeadline)
    throws
  {
    do {
      try runtime.start(
        configuration: configuration,
        packetFileDescriptor: packetFileDescriptor,
        deadline: deadline
      )
    } catch let error as LibboxRuntimeError {
      if error == .serviceStartTimedOut {
        throw PacketEngineError.startTimedOut
      }
      if case .endpointConflict(.mixed, let port) = error {
        throw PacketEngineError.mixedEndpointConflict(port: port)
      }
      if case .endpointConflict(.controller, let port) = error {
        throw PacketEngineError.controllerEndpointConflict(port: port)
      }
      throw PacketEngineError.runtime(error.localizedDescription)
    } catch {
      throw PacketEngineError.runtime(error.localizedDescription)
    }
  }

  func stop() throws(LibboxInstanceUnclosable) {
    try runtime.stop()
  }

  func healthCheck() throws {
    do {
      try runtime.healthCheck()
    } catch {
      throw PacketEngineError.runtime(error.localizedDescription)
    }
  }
}

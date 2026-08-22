import Darwin
import Foundation
import TransportPeerCore
import TransportPeerMacProbeSupport

#if !os(macOS) || !arch(arm64)
  #error("TransportPeerMacProbe supports only macOS arm64")
#endif

@main
struct TransportPeerMacProbeCommand {
  static func main() {
    guard CommandLine.arguments.count == 2 else {
      fail("usage: TransportPeerMacProbe /absolute/private/run-directory")
    }

    do {
      let inputs = try MacProbeRunDirectory.load(path: CommandLine.arguments[1])
      let result = try MacTransportProbe.run(inputs: inputs)
      FileHandle.standardOutput.write(try ExactJSON.encode(result))
    } catch {
      fail(error.localizedDescription)
    }
  }

  private static func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("TransportPeerMacProbe: \(message)\n".utf8))
    exit(EXIT_FAILURE)
  }
}

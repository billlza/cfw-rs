import CFWProxyAgentCore
import Foundation

do {
  try ProxyAgentExecutable.run()
} catch {
  let message = "ProxyAgent startup failed: \(String(describing: error))\n"
  FileHandle.standardError.write(Data(message.utf8))
  exit(EXIT_FAILURE)
}

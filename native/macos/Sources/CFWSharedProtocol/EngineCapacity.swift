/// Cross-language capacity contract. The node/group/edge stress fixture and
/// protocol tests bind these values to the Rust projection and vault boundary.
public enum EngineCapacity {
  public static let maximumProxyNodes = 1_024
  public static let maximumProxyGroups = 128
  public static let maximumOutbounds = maximumProxyNodes + maximumProxyGroups + 2
  public static let maximumCredentialSlots = 2 * maximumProxyNodes
  public static let maximumVaultBindings = 8_192
  public static let maximumConfigurationBytes = 4 * 1_024 * 1_024
  public static let maximumBridgeBytes = 8 * 1_024 * 1_024
}

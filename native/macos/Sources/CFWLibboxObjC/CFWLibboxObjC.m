#import "CFWLibboxObjC.h"
#import "CFWConnectionOwnerResolver.h"
#include <unistd.h>

static NSString *const CFWLibboxPlatformErrorDomain =
    @"com.bill.clashformac.libbox-platform";

static NSError *CFWUnsupportedOperation(NSString *operation) {
  return [NSError
      errorWithDomain:CFWLibboxPlatformErrorDomain
                 code:1
             userInfo:@{
               NSLocalizedDescriptionKey :
                   [NSString stringWithFormat:
                                 @"Unsupported libbox platform operation: %@",
                                 operation]
             }];
}

@interface CFWLibboxPlatformAdapter ()
@property(nonatomic, readonly) BOOL packetTunnel;
@property(nonatomic, strong, readonly) id<CFWLibboxPlatformDelegate> delegate;
@property(nonatomic, copy, readonly) NSSet<NSString *> *processNames;
@property(nonatomic, copy, readonly) NSSet<NSString *> *processPaths;
@end

@implementation CFWLibboxPlatformAdapter

+ (BOOL)startOrReloadService:(LibboxCommandServer *)server
              configuration:(NSString *)configuration
                    options:(LibboxOverrideOptions *)options
           reportedConflict:(LibboxRuntimeStartConflict *_Nullable *_Nonnull)conflict
                      error:(NSError *_Nullable *_Nullable)error {
  NSError *startError = nil;
  LibboxRuntimeStartConflict *result =
      [server startOrReloadServiceReportingConflict:configuration
                                           options:options
                                             error:&startError];
  *conflict = nil;
  if (startError != nil) {
    if (error != NULL) {
      *error = startError;
    }
    return NO;
  }
  *conflict = result;
  return YES;
}

- (instancetype)initWithPacketTunnel:(BOOL)packetTunnel
                             delegate:(id<CFWLibboxPlatformDelegate>)delegate
                         processNames:(NSArray<NSString *> *)processNames
                         processPaths:(NSArray<NSString *> *)processPaths {
  self = [super init];
  if (self != nil) {
    _packetTunnel = packetTunnel;
    _delegate = delegate;
    _processNames = [NSSet setWithArray:processNames];
    _processPaths = [NSSet setWithArray:processPaths];
  }
  return self;
}

- (BOOL)autoDetectInterfaceControl:(int32_t)fileDescriptor
                             error:(NSError **)error {
  (void)fileDescriptor;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"autoDetectInterfaceControl");
  }
  return NO;
}

- (void)clearDNSCache {
  [self.delegate clearDNSCache];
}

- (BOOL)cancelNotification:(NSString *)identifier
                   typeID:(int32_t)typeID
                    error:(NSError **)error {
  (void)identifier;
  (void)typeID;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"cancelNotification");
  }
  return NO;
}

- (BOOL)checkPlatformShell:(NSError **)error {
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"checkPlatformShell");
  }
  return NO;
}

- (BOOL)closeDefaultInterfaceMonitor:
            (id<LibboxInterfaceUpdateListener>)listener
                                  error:(NSError **)error {
  return [self.delegate closeDefaultInterfaceMonitor:listener error:error];
}

- (BOOL)closeNeighborMonitor:(id<LibboxNeighborUpdateListener>)listener
                      error:(NSError **)error {
  (void)listener;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"closeNeighborMonitor");
  }
  return NO;
}

- (id<LibboxBridgeSession>)createBridge:(LibboxBridgeOptions *)options
                                error:(NSError **)error {
  (void)options;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"createBridge");
  }
  return nil;
}

- (LibboxConnectionOwner *)
    findConnectionOwner:(int32_t)ipProtocol
           sourceAddress:(NSString *)sourceAddress
              sourcePort:(int32_t)sourcePort
      destinationAddress:(NSString *)destinationAddress
         destinationPort:(int32_t)destinationPort
                   error:(NSError **)error {
  // The root NetworkExtension can use the kernel socket inventory. Ordinary
  // user processes on current macOS receive only their own sockets from that
  // API, so resolve configured process matchers through public libproc instead.
  if (geteuid() == 0) {
    return LibboxFindConnectionOwner(ipProtocol, sourceAddress, sourcePort,
                                    destinationAddress, destinationPort, error);
  }
  return CFWFindConfiguredConnectionOwner(self.processNames, self.processPaths,
      ipProtocol, sourceAddress, sourcePort, destinationAddress, destinationPort,
      error);
}

- (id<LibboxNetworkInterfaceIterator>)getInterfaces:(NSError **)error {
  return [self.delegate getInterfaces:error];
}

- (BOOL)includeAllNetworks {
  return NO;
}

- (id<LibboxLocalDNSTransport>)localDNSTransport {
  return nil;
}

- (NSString *)lookupSFTPServer:(NSError **)error {
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"lookupSFTPServer");
  }
  return nil;
}

- (LibboxPlatformUser *)lookupUser:(NSString *)username
                            error:(NSError **)error {
  (void)username;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"lookupUser");
  }
  return nil;
}

- (BOOL)openRawPacketTun:(id<LibboxTunOptions>)options
                    ret0_:(int32_t *)descriptor
                    error:(NSError **)error {
  if (!self.packetTunnel || options == nil || descriptor == NULL) {
    if (error != NULL) {
      *error = CFWUnsupportedOperation(@"openRawPacketTun");
    }
    return NO;
  }
  return [self.delegate takeRawPacketDescriptor:descriptor error:error];
}

- (id<LibboxShellSession>)openShellSession:(LibboxPlatformUser *)user
                                  command:(NSString *)command
                                  environ:(id<LibboxStringIterator>)environ
                                     term:(NSString *)term
                                     rows:(int32_t)rows
                                     cols:(int32_t)cols
                                    error:(NSError **)error {
  (void)user;
  (void)command;
  (void)environ;
  (void)term;
  (void)rows;
  (void)cols;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"openShellSession");
  }
  return nil;
}

- (BOOL)openTun:(id<LibboxTunOptions>)options
          ret0_:(int32_t *)descriptor
          error:(NSError **)error {
  (void)options;
  (void)descriptor;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"openTun");
  }
  return NO;
}

- (NSString *)readSystemSSHHostKey:(NSError **)error {
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"readSystemSSHHostKey");
  }
  return nil;
}

- (LibboxWIFIState *)readWIFIState {
  return nil;
}

- (void)registerMyInterface:(NSString *)name {
  [self.delegate registerMyInterface:name];
}

- (BOOL)sendNotification:(LibboxNotification *)notification
                    error:(NSError **)error {
  (void)notification;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"sendNotification");
  }
  return NO;
}

- (BOOL)startDefaultInterfaceMonitor:
            (id<LibboxInterfaceUpdateListener>)listener
                                  error:(NSError **)error {
  return [self.delegate startDefaultInterfaceMonitor:listener error:error];
}

- (BOOL)startNeighborMonitor:(id<LibboxNeighborUpdateListener>)listener
                      error:(NSError **)error {
  (void)listener;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"startNeighborMonitor");
  }
  return NO;
}

- (NSString *)tailscaleHostname {
  // An empty name explicitly requests the upstream system-hostname default.
  // CFM's typed configuration does not currently admit Tailscale endpoints.
  return @"";
}

- (BOOL)underNetworkExtension {
  return self.packetTunnel;
}

- (BOOL)usePlatformAutoDetectInterfaceControl {
  return NO;
}

- (BOOL)usePlatformBridge {
  return NO;
}

- (BOOL)usePlatformShell {
  return NO;
}

- (BOOL)useProcFS {
  return NO;
}

- (BOOL)useRawPacketTun {
  return self.packetTunnel;
}

- (LibboxSystemProxyStatus *)getSystemProxyStatus:(NSError **)error {
  (void)error;
  return [[LibboxSystemProxyStatus alloc] init];
}

- (BOOL)connectSSHAgent:(int32_t *)descriptor error:(NSError **)error {
  (void)descriptor;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"connectSSHAgent");
  }
  return NO;
}

- (BOOL)serviceReload:(NSError **)error {
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"serviceReload");
  }
  return NO;
}

- (BOOL)serviceStop:(NSError **)error {
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"serviceStop");
  }
  return NO;
}

- (BOOL)setSystemProxyEnabled:(BOOL)enabled error:(NSError **)error {
  (void)enabled;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"setSystemProxyEnabled");
  }
  return NO;
}

- (BOOL)triggerNativeCrash:(NSError **)error {
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"triggerNativeCrash");
  }
  return NO;
}

- (void)writeDebugMessage:(NSString *)message {
  // Profile-derived debug text is intentionally not forwarded to unified logs.
  (void)message;
}

@end

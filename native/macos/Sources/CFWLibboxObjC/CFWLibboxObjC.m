#import "CFWLibboxObjC.h"

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
@end

@implementation CFWLibboxPlatformAdapter

- (instancetype)initWithPacketTunnel:(BOOL)packetTunnel
                             delegate:(id<CFWLibboxPlatformDelegate>)delegate {
  self = [super init];
  if (self != nil) {
    _packetTunnel = packetTunnel;
    _delegate = delegate;
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

- (BOOL)closeDefaultInterfaceMonitor:
            (id<LibboxInterfaceUpdateListener>)listener
                                  error:(NSError **)error {
  return [self.delegate closeDefaultInterfaceMonitor:listener error:error];
}

- (LibboxConnectionOwner *)
    findConnectionOwner:(int32_t)ipProtocol
           sourceAddress:(NSString *)sourceAddress
              sourcePort:(int32_t)sourcePort
      destinationAddress:(NSString *)destinationAddress
         destinationPort:(int32_t)destinationPort
                   error:(NSError **)error {
  (void)ipProtocol;
  (void)sourceAddress;
  (void)sourcePort;
  (void)destinationAddress;
  (void)destinationPort;
  if (error != NULL) {
    *error = CFWUnsupportedOperation(@"findConnectionOwner");
  }
  return nil;
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

- (LibboxWIFIState *)readWIFIState {
  return nil;
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

- (id<LibboxStringIterator>)systemCertificates {
  return nil;
}

- (BOOL)underNetworkExtension {
  return self.packetTunnel;
}

- (BOOL)usePlatformAutoDetectInterfaceControl {
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

- (void)writeDebugMessage:(NSString *)message {
  // Profile-derived debug text is intentionally not forwarded to unified logs.
  (void)message;
}

@end


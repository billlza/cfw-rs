#import <Foundation/Foundation.h>
#import <Libbox/Libbox.h>

NS_ASSUME_NONNULL_BEGIN

@protocol CFWLibboxPlatformDelegate <NSObject>
- (BOOL)takeRawPacketDescriptor:(int32_t *_Nullable)descriptor
                          error:(NSError *_Nullable *_Nullable)error;
- (BOOL)startDefaultInterfaceMonitor:
            (id<LibboxInterfaceUpdateListener> _Nullable)listener
                                  error:(NSError *_Nullable *_Nullable)error;
- (BOOL)closeDefaultInterfaceMonitor:
            (id<LibboxInterfaceUpdateListener> _Nullable)listener
                                  error:(NSError *_Nullable *_Nullable)error;
- (id<LibboxNetworkInterfaceIterator> _Nullable)getInterfaces:
    (NSError *_Nullable *_Nullable)error;
- (void)clearDNSCache;
@end

/// Objective-C owns the raw gomobile selectors so the Swift implementation is
/// not forced to expose generator-specific labels such as `ret0_`.
@interface CFWLibboxPlatformAdapter
    : NSObject <LibboxPlatformInterface, LibboxCommandServerHandler>

- (instancetype)initWithPacketTunnel:(BOOL)packetTunnel
                             delegate:(id<CFWLibboxPlatformDelegate>)delegate
    NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END


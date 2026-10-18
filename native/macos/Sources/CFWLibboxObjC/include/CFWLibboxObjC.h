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
- (void)registerMyInterface:(NSString *)name;
- (void)clearDNSCache;
@end

/// Objective-C owns the raw gomobile selectors so the Swift implementation is
/// not forced to expose generator-specific labels such as `ret0_`.
@interface CFWLibboxPlatformAdapter
    : NSObject <LibboxPlatformInterface, LibboxCommandServerHandler>

- (instancetype)initWithPacketTunnel:(BOOL)packetTunnel
                             delegate:(id<CFWLibboxPlatformDelegate>)delegate
                         processNames:(NSArray<NSString *> *)processNames
                         processPaths:(NSArray<NSString *> *)processPaths
    NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

/// A successful Go call may return no conflict and no error. Keep that nullable
/// result separate from NSError so Swift does not import it as nonoptional.
+ (BOOL)startOrReloadService:(LibboxCommandServer *)server
              configuration:(NSString *)configuration
                    options:(LibboxOverrideOptions *)options
           reportedConflict:(LibboxRuntimeStartConflict *_Nullable *_Nonnull)conflict
                      error:(NSError *_Nullable *_Nullable)error;

@end

NS_ASSUME_NONNULL_END

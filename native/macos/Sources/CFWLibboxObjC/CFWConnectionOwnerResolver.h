#import <Foundation/Foundation.h>
#import <Libbox/Libbox.h>

NS_ASSUME_NONNULL_BEGIN

/// Resolves a socket only among process identities used by the routing policy.
/// Uses public libproc queries; it neither requests privileges nor executes code.
LibboxConnectionOwner *_Nullable CFWFindConfiguredConnectionOwner(
    NSSet<NSString *> *processNames, NSSet<NSString *> *processPaths,
    int32_t ipProtocol, NSString *sourceAddress, int32_t sourcePort,
    NSString *destinationAddress, int32_t destinationPort,
    NSError *_Nullable *_Nullable error);

NS_ASSUME_NONNULL_END

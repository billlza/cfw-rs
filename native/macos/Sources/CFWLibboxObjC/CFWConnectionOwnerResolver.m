#import "CFWConnectionOwnerResolver.h"
#include <arpa/inet.h>
#include <errno.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <time.h>
#include <unistd.h>

static const NSUInteger CFWMaximumProcesses = 16384;
static const NSUInteger CFWMaximumDescriptors = 65536;

static void CFWOwnerError(NSError **error, NSInteger code, NSString *message) {
  if (error != NULL) {
    *error = [NSError errorWithDomain:@"com.bill.clashformac.connection-owner"
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey : message}];
  }
}

static BOOL CFWProcessDisappeared(int code) {
  return code == ESRCH || code == ENOENT || code == EBADF || code == ENOTSOCK;
}

static BOOL CFWAddress(NSString *text, struct in6_addr *address) {
  struct in_addr v4;
  if (inet_pton(AF_INET, text.UTF8String, &v4) == 1) {
    memset(address, 0, sizeof(*address));
    address->s6_addr[10] = 0xff;
    address->s6_addr[11] = 0xff;
    memcpy(&address->s6_addr[12], &v4, sizeof(v4));
    return YES;
  }
  return inet_pton(AF_INET6, text.UTF8String, address) == 1;
}

static struct in6_addr CFWSocketAddress(const struct in_sockinfo *info, BOOL local) {
  struct in6_addr address;
  if ((info->insi_vflag & INI_IPV4) != 0) {
    memset(&address, 0, sizeof(address));
    address.s6_addr[10] = 0xff;
    address.s6_addr[11] = 0xff;
    struct in_addr v4 = local ? info->insi_laddr.ina_46.i46a_addr4
                             : info->insi_faddr.ina_46.i46a_addr4;
    memcpy(&address.s6_addr[12], &v4, sizeof(v4));
  } else {
    address = local ? info->insi_laddr.ina_6 : info->insi_faddr.ina_6;
  }
  return address;
}

static BOOL CFWUnspecified(const struct in6_addr *address) {
  static const struct in6_addr zero;
  return memcmp(address, &zero, sizeof(*address)) == 0 ||
         (IN6_IS_ADDR_V4MAPPED(address) &&
          memcmp(&address->s6_addr[12], &zero, 4) == 0);
}

static BOOL CFWSocketMatches(const struct socket_fdinfo *socket, int32_t protocol,
                             const struct in6_addr *source, uint16_t sourcePort,
                             const struct in6_addr *destination, uint16_t destinationPort) {
  if (socket->psi.soi_protocol != protocol ||
      (protocol == IPPROTO_TCP && socket->psi.soi_kind != SOCKINFO_TCP) ||
      (protocol == IPPROTO_UDP && socket->psi.soi_kind != SOCKINFO_IN)) return NO;
  const struct in_sockinfo *info = protocol == IPPROTO_TCP
      ? &socket->psi.soi_proto.pri_tcp.tcpsi_ini : &socket->psi.soi_proto.pri_in;
  if (ntohs((uint16_t)info->insi_lport) != sourcePort) return NO;
  struct in6_addr local = CFWSocketAddress(info, YES);
  struct in6_addr remote = CFWSocketAddress(info, NO);
  BOOL sameLocal = memcmp(&local, source, sizeof(local)) == 0;
  if (!sameLocal && !(protocol == IPPROTO_UDP && CFWUnspecified(&local))) return NO;
  uint16_t remotePort = ntohs((uint16_t)info->insi_fport);
  // An unconnected UDP socket has no foreign endpoint. Multiple matching
  // processes are rejected by the caller instead of assigning an arbitrary one.
  if (protocol == IPPROTO_UDP && remotePort == 0 && CFWUnspecified(&remote)) return YES;
  return remotePort == destinationPort && memcmp(&remote, destination, sizeof(remote)) == 0;
}

typedef struct {
  int32_t protocol;
  struct in6_addr source;
  struct in6_addr destination;
  uint16_t sourcePort;
  uint16_t destinationPort;
  struct timespec deadline;
} CFWConnectionQuery;

static BOOL CFWWithinLookupDeadline(const CFWConnectionQuery *query, NSError **error) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
      now.tv_sec > query->deadline.tv_sec ||
      (now.tv_sec == query->deadline.tv_sec && now.tv_nsec >= query->deadline.tv_nsec)) {
    CFWOwnerError(error, 4, @"Process lookup exceeded its work deadline.");
    return NO;
  }
  return YES;
}

static BOOL CFWConfiguredProcess(pid_t pid, NSSet<NSString *> *names,
                                  NSSet<NSString *> *paths, struct proc_bsdinfo *identity,
                                  NSString **matchedPath, NSError **error) {
  errno = 0;
  int read = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, identity, sizeof(*identity));
  if (read != sizeof(*identity)) {
    if (CFWProcessDisappeared(errno) || errno == EPERM || errno == EACCES) return NO;
    CFWOwnerError(error, 3, @"Process identity could not be read completely.");
    return NO;
  }
  if (geteuid() != 0 && identity->pbi_uid != geteuid()) return NO;
  char pathBytes[PROC_PIDPATHINFO_MAXSIZE];
  errno = 0;
  int pathLength = proc_pidpath(pid, pathBytes, sizeof(pathBytes));
  if (pathLength <= 0) {
    if (CFWProcessDisappeared(errno) || errno == EPERM || errno == EACCES) return NO;
    CFWOwnerError(error, 3, @"Process path query failed.");
    return NO;
  }
  NSString *path = [[NSString alloc] initWithBytes:pathBytes length:(NSUInteger)pathLength
                                        encoding:NSUTF8StringEncoding];
  if (path == nil || (![names containsObject:path.lastPathComponent] &&
                      ![paths containsObject:path])) return NO;
  *matchedPath = path;
  return YES;
}

static BOOL CFWProcessOwnsSocket(pid_t pid, const struct proc_bsdinfo *before,
                                  const CFWConnectionQuery *query, NSError **error) {
  errno = 0;
  int required = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
  if (required <= 0) {
    if ((required == 0 && errno == 0) || CFWProcessDisappeared(errno)) return NO;
    CFWOwnerError(error, 5, @"Configured process socket inventory could not be read.");
    return NO;
  }
  NSUInteger capacity = (NSUInteger)required / sizeof(struct proc_fdinfo) + 32;
  if (capacity > CFWMaximumDescriptors) {
    CFWOwnerError(error, 4, @"Configured process descriptor inventory exceeds its bound.");
    return NO;
  }
  NSMutableData *data = [NSMutableData dataWithLength:capacity * sizeof(struct proc_fdinfo)];
  struct proc_fdinfo *fds = data.mutableBytes;
  errno = 0;
  int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, (int)data.length);
  if (bytes <= 0 || (NSUInteger)bytes >= data.length || bytes % sizeof(*fds) != 0) {
    if (CFWProcessDisappeared(errno)) return NO;
    CFWOwnerError(error, 3, @"Configured process descriptor inventory changed during lookup.");
    return NO;
  }
  for (NSUInteger i = 0; i < (NSUInteger)bytes / sizeof(*fds); i++) {
    if (i % 128 == 0 && !CFWWithinLookupDeadline(query, error)) return NO;
    if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
    struct socket_fdinfo socket;
    errno = 0;
    int count = proc_pidfdinfo(pid, (int)fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket));
    if (count != sizeof(socket)) {
      if (CFWProcessDisappeared(errno)) continue;
      CFWOwnerError(error, 5, @"Configured process socket could not be inspected.");
      return NO;
    }
    if (!CFWSocketMatches(&socket, query->protocol, &query->source, query->sourcePort,
                         &query->destination, query->destinationPort)) continue;
    struct proc_bsdinfo after;
    struct socket_fdinfo repeated;
    errno = 0;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after)) != sizeof(after)) {
      if (CFWProcessDisappeared(errno)) continue;
      CFWOwnerError(error, 5, @"Matched process identity could not be rechecked.");
      return NO;
    }
    if (before->pbi_start_tvsec != after.pbi_start_tvsec ||
        before->pbi_start_tvusec != after.pbi_start_tvusec || before->pbi_uid != after.pbi_uid) continue;
    errno = 0;
    if (proc_pidfdinfo(pid, (int)fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &repeated, sizeof(repeated)) != sizeof(repeated)) {
      if (CFWProcessDisappeared(errno)) continue;
      CFWOwnerError(error, 5, @"Matched process socket could not be rechecked.");
      return NO;
    }
    if (
        repeated.psi.soi_so != socket.psi.soi_so ||
        !CFWSocketMatches(&repeated, query->protocol, &query->source, query->sourcePort,
                          &query->destination, query->destinationPort)) continue;
    return YES;
  }
  return NO;
}

LibboxConnectionOwner *CFWFindConfiguredConnectionOwner(
    NSSet<NSString *> *processNames, NSSet<NSString *> *processPaths,
    int32_t ipProtocol, NSString *sourceAddress, int32_t sourcePort,
    NSString *destinationAddress, int32_t destinationPort, NSError **error) {
  if (error != NULL) *error = nil;
  CFWConnectionQuery query = {.protocol = ipProtocol};
  if ((ipProtocol != IPPROTO_TCP && ipProtocol != IPPROTO_UDP) ||
      sourcePort <= 0 || sourcePort > UINT16_MAX || destinationPort < 0 ||
      destinationPort > UINT16_MAX || !CFWAddress(sourceAddress, &query.source) ||
      !CFWAddress(destinationAddress, &query.destination)) {
    CFWOwnerError(error, 1, @"Connection owner query has an invalid socket tuple.");
    return nil;
  }
  query.sourcePort = (uint16_t)sourcePort;
  query.destinationPort = (uint16_t)destinationPort;
  if (clock_gettime(CLOCK_MONOTONIC, &query.deadline) != 0) {
    CFWOwnerError(error, 3, @"Process lookup clock is unavailable.");
    return nil;
  }
  query.deadline.tv_sec += 1;
  if (processNames.count == 0 && processPaths.count == 0) {
    CFWOwnerError(error, 2, @"No configured process matcher requires this connection.");
    return nil;
  }
  int count = proc_listallpids(NULL, 0);
  if (count <= 0 || (NSUInteger)count + 32 > CFWMaximumProcesses) {
    CFWOwnerError(error, 3, @"Process inventory is unavailable or exceeds its bound.");
    return nil;
  }
  NSUInteger capacity = (NSUInteger)count + 32;
  NSMutableData *data = [NSMutableData dataWithLength:capacity * sizeof(pid_t)];
  pid_t *pids = data.mutableBytes;
  count = proc_listallpids(pids, (int)data.length);
  if (count <= 0 || (NSUInteger)count >= capacity) {
    CFWOwnerError(error, 3, @"Process inventory changed beyond its bounded allocation.");
    return nil;
  }
  LibboxConnectionOwner *result = nil;
  pid_t resultPID = 0;
  for (int index = 0; index < count; index++) {
    pid_t pid = pids[index];
    if (pid <= 0) continue;
    if (!CFWWithinLookupDeadline(&query, error)) return nil;
    NSError *queryError = nil;
    struct proc_bsdinfo identity;
    NSString *path = nil;
    BOOL candidate = CFWConfiguredProcess(pid, processNames, processPaths, &identity, &path, &queryError);
    BOOL ownsSocket = candidate && CFWProcessOwnsSocket(pid, &identity, &query, &queryError);
    if (queryError != nil) {
      if (error != NULL) *error = queryError;
      return nil;
    }
    if (!ownsSocket) continue;
    if (result != nil && resultPID != pid) {
      CFWOwnerError(error, 6, @"Connection matches more than one configured process.");
      return nil;
    }
    result = [[LibboxConnectionOwner alloc] init];
    result.userId = (int32_t)identity.pbi_uid;
    result.processPath = path;
    resultPID = pid;
  }
  if (result == nil) CFWOwnerError(error, 2, @"Connection does not belong to a configured process matcher.");
  return result;
}

#include <os/log.h>

__attribute__((visibility("hidden"))) void
cfw_release_observation_log(os_log_t log, const char *message) {
    os_log_with_type(log, OS_LOG_TYPE_INFO, "%{public}s", message);
}

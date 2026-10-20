use super::*;
use cfw_engine_api::{ProfileDelayBackend, ProfileDelayTestRequest, ProfileProxyDelay};

struct PendingProbe(Option<ProfileDelayTestRequest>);
impl Drop for PendingProbe {
    fn drop(&mut self) {
        if let Some(request) = &mut self.0 {
            request.config_json.zeroize();
        }
    }
}
impl ProfileDelayBackend for WindowsEngineBackend {
    fn test_profile_delays(
        &self,
        request: ProfileDelayTestRequest,
    ) -> BackendFuture<'_, Vec<ProfileProxyDelay>> {
        let mut pending = PendingProbe(Some(request));
        // Separate capacity keeps explicit latency batches from occupying the
        // runtime state mutex or queuing ahead of a stop. Cancellation reaches
        // the isolated process owner's 25ms control wait; the worker retains
        // its permit through confirmed child/control-I/O retirement.
        Box::pin(self.worker(
            &self.shared.probes,
            move |shared, cancellation, deadline| {
                let request = pending
                    .0
                    .take()
                    .ok_or_else(|| fail(Kind::Internal, "probe already consumed"))?;
                shared
                    .desktop
                    .test_profile_delays(request, cancellation, deadline)
                    .map_err(host_error)
            },
        ))
    }
}

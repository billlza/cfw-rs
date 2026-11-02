//! Service maintenance and profile delay probes sent through the bridge.

use cfw_engine_api::{
    NativeBridgeCommand, NativeBridgeResult, NativeServiceMaintenanceAction,
    NativeServiceMaintenanceResult,
};

use crate::{NativeBridgeError, NativeBridgeErrorCode, NativeBridgeFuture, NativeFrameworkBridge};

impl NativeFrameworkBridge {
    pub fn maintain_current_services(
        &self,
        action: NativeServiceMaintenanceAction,
    ) -> NativeBridgeFuture<'_, NativeServiceMaintenanceResult> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::MaintainCurrentServices { action })
                .await?
            {
                NativeBridgeResult::ServiceMaintenance(result) if result.action == action => {
                    Ok(result)
                }
                NativeBridgeResult::ServiceMaintenance(_) => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::IdentityRejected,
                    "native service maintenance response action does not match the request",
                )),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native service maintenance returned the wrong result kind",
                )),
            }
        })
    }

    pub fn test_profile_delays(
        &self,
        request: cfw_engine_api::ProfileDelayTestRequest,
    ) -> NativeBridgeFuture<'_, Vec<cfw_engine_api::ProfileProxyDelay>> {
        Box::pin(async move {
            let expected = request.proxies.clone();
            match self
                .invoke(NativeBridgeCommand::TestProfileDelays { request })
                .await?
            {
                NativeBridgeResult::ProfileDelays(results)
                    if results.len() == expected.len()
                        && results.iter().zip(&expected).all(|(result, name)| {
                            &result.name == name
                                && matches!(
                                    (result.delay, result.error_kind),
                                    (Some(1..), None) | (None, Some(_))
                                )
                        }) =>
                {
                    Ok(results)
                }
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native profile probe response does not match the request",
                )),
            }
        })
    }
}

impl cfw_engine_api::ProfileDelayBackend for NativeFrameworkBridge {
    fn test_profile_delays(
        &self,
        request: cfw_engine_api::ProfileDelayTestRequest,
    ) -> cfw_engine_api::BackendFuture<'_, Vec<cfw_engine_api::ProfileProxyDelay>> {
        Box::pin(async move {
            NativeFrameworkBridge::test_profile_delays(self, request)
                .await
                .map_err(|error| {
                    cfw_engine_api::BackendError::new(error.code.into(), error.message)
                })
        })
    }
}

#[cfg(test)]
mod tests;

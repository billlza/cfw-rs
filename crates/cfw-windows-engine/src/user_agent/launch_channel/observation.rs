use super::*;
use crate::{RunningChild, authority::LeaseContext};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use windows_sys::Win32::System::Pipes::PeekNamedPipe;

const PROTOCOL: &str = "cfw.windows.runtime-observation";
const VERSION: u16 = 1;
const MAX_BYTES: usize = 4096;
const IO_WAIT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObservationRequest {
    protocol: String,
    version: u16,
    nonce: Uuid,
    context: LeaseContext,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationReply {
    protocol: String,
    version: u16,
    nonce: Uuid,
    context: LeaseContext,
    engine_process_id: u32,
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; MAX_BYTES];
    let length = {
        let mut remaining = bytes.as_mut_slice();
        serde_json::to_writer(&mut remaining, value)
            .map_err(|_| LaunchChannelError::Observation)?;
        MAX_BYTES - remaining.len()
    };
    bytes.truncate(length);
    Ok(bytes)
}
fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(LaunchChannelError::Observation);
    }
    serde_json::from_slice(bytes).map_err(|_| LaunchChannelError::Observation)
}
fn reply(request: &ObservationRequest, bytes: &[u8]) -> Result<RunningChild> {
    let observed: ObservationReply = decode(bytes)?;
    if observed.protocol != PROTOCOL
        || observed.version != VERSION
        || observed.nonce != request.nonce
        || observed.context != request.context
        || observed.engine_process_id == 0
    {
        return Err(LaunchChannelError::Observation);
    }
    Ok(RunningChild {
        process_id: observed.engine_process_id,
        configuration_digest: crate::user_agent::plan::hex(
            &observed.context.operation.identity_sha256,
        ),
    })
}

/// Constructed only after the original inherited-channel launch acknowledgement.
/// The launcher checks its retained native Agent identity before and after each
/// exchange. The caller consumes this endpoint on any failed/uncertain request.
pub(crate) struct ObservationClient {
    pipe: OwnedHandle,
}
impl ObservationClient {
    pub(super) fn new(pipe: OwnedHandle) -> Self {
        Self { pipe }
    }
    pub(crate) fn observe(
        &mut self,
        context: &LeaseContext,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<RunningChild> {
        let request = ObservationRequest {
            protocol: PROTOCOL.into(),
            version: VERSION,
            nonce: Uuid::new_v4(),
            context: context.clone(),
        };
        let bytes = encode(&request)?;
        native_io::write_bounded(&self.pipe, &bytes, deadline, MAX_BYTES, Some(cancel))?;
        let received = native_io::read_bounded(&self.pipe, deadline, MAX_BYTES, Some(cancel))?;
        reply(&request, received.as_bytes())
    }
}
pub(crate) struct ObservationServer {
    endpoint: LaunchReceiver,
}
impl ObservationServer {
    pub(super) fn new(endpoint: LaunchReceiver) -> Self {
        Self { endpoint }
    }
    fn authenticate(&self) -> Result<()> {
        self.endpoint
            .parent
            .verify_pipe_server(&self.endpoint.pipe)?;
        self.endpoint
            .parent
            .verify_executable(&self.endpoint.expected_parent)?;
        Ok(())
    }
    /// This is the same overlapped handle created by the trusted launcher.
    /// Peek reads no payload and avoids blocking the runtime's control loop.
    pub(crate) fn poll(
        &mut self,
        context: &LeaseContext,
        cancel: &AtomicBool,
    ) -> Result<Option<ObservationRequest>> {
        let mut available = 0;
        if unsafe {
            PeekNamedPipe(
                self.endpoint.pipe.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if available == 0 {
            return Ok(None);
        }
        if available as usize > MAX_BYTES {
            return Err(LaunchChannelError::Observation);
        }
        self.authenticate()?;
        let bytes = native_io::read_bounded(
            &self.endpoint.pipe,
            Instant::now() + IO_WAIT,
            MAX_BYTES,
            Some(cancel),
        )?;
        let request: ObservationRequest = decode(bytes.as_bytes())?;
        if request.protocol != PROTOCOL
            || request.version != VERSION
            || request.nonce.is_nil()
            || request.context != *context
        {
            return Err(LaunchChannelError::Observation);
        }
        self.authenticate()?;
        Ok(Some(request))
    }
    /// Only the runtime owner calls this after a new native engine/listener and
    /// (when relevant) WinINet observation made after accepting this request.
    pub(crate) fn report(
        &mut self,
        request: ObservationRequest,
        engine_process_id: u32,
        cancel: &AtomicBool,
    ) -> Result<()> {
        if engine_process_id == 0 {
            return Err(LaunchChannelError::Observation);
        }
        self.authenticate()?;
        let bytes = encode(&ObservationReply {
            protocol: PROTOCOL.into(),
            version: VERSION,
            nonce: request.nonce,
            context: request.context,
            engine_process_id,
        })?;
        native_io::write_bounded(
            &self.endpoint.pipe,
            &bytes,
            Instant::now() + IO_WAIT,
            MAX_BYTES,
            Some(cancel),
        )?;
        self.authenticate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observation_cannot_reuse_another_probe_context_or_unbounded_frame() {
        let (binding, _) =
            crate::user_agent::tests::inputs(cfw_singbox_config::ProjectionMode::LocalProxy);
        let request = ObservationRequest {
            protocol: PROTOCOL.into(),
            version: VERSION,
            nonce: Uuid::new_v4(),
            context: binding.context,
        };
        let value = ObservationReply {
            protocol: PROTOCOL.into(),
            version: VERSION,
            nonce: request.nonce,
            context: request.context.clone(),
            engine_process_id: 123,
        };
        let original = serde_json::to_value(value).unwrap();
        assert_eq!(
            reply(&request, &encode(&original).unwrap())
                .unwrap()
                .process_id,
            123
        );
        for index in 0..6 {
            let mut invalid = original.clone();
            match index {
                0 => invalid["nonce"] = Uuid::new_v4().to_string().into(),
                1 => invalid["context"]["operation"]["root"]["generation"] = 2.into(),
                2 => {
                    invalid["context"]["operation"]["identity_sha256"][0] =
                        (original["context"]["operation"]["identity_sha256"][0]
                            .as_u64()
                            .unwrap()
                            ^ 1)
                        .into()
                }
                3 => invalid["version"] = 2.into(),
                4 => invalid["engine_process_id"] = 0.into(),
                _ => invalid["cached"] = true.into(),
            }
            assert!(reply(&request, &encode(&invalid).unwrap()).is_err());
        }
        assert!(reply(&request, &vec![b' '; MAX_BYTES + 1]).is_err());
    }
}

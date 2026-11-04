use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cfw_application::EngineControllerAccess;
use cfw_engine_api::{
    EngineCommandContext, EngineMode, EngineOwner, EngineSettings, RuntimeIdentity,
};

use super::stream_messages::{
    LogFieldPayload, LogLinePayload, is_transient_controller_disconnect, stream_error_payload,
    stream_error_to_report,
};
use super::streams::{attach_stream, release_stream, reserve_stream};
use super::*;

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn runtime_for(owner: EngineOwner, generation: u64, digest: &str, ready: bool) -> RuntimeIdentity {
    RuntimeIdentity {
        owner,
        context: EngineCommandContext {
            installation_id: "installation".into(),
            config_epoch: 1,
            generation,
        },
        config_digest: digest.into(),
        ready,
    }
}

fn runtime(ready: bool) -> RuntimeIdentity {
    runtime_for(EngineOwner::ProxyAgent, 7, "digest", ready)
}

fn snapshot(state: EngineState) -> EngineSnapshot {
    let (desired_mode, generation, config_digest) = match &state {
        EngineState::LocalProxyActive { runtime } | EngineState::ProxyActive { runtime } => (
            state.active_mode(),
            runtime.context.generation,
            Some(runtime.config_digest.clone()),
        ),
        EngineState::TunnelActive { runtime }
        | EngineState::TunnelSystemProxyActive { runtime } => (
            state.active_mode(),
            runtime.context.generation,
            Some(runtime.config_digest.clone()),
        ),
        _ => (EngineMode::Off, 7, None),
    };
    EngineSnapshot {
        desired_mode,
        state,
        generation,
        config_digest,
    }
}

/// The endpoint of the engine this process would start, including the
/// per-run secret. Only tests read it back, and only to prove it never
/// escapes.
fn process_endpoint() -> (ControllerEndpoint, String) {
    let access = EngineControllerAccess::resolve(EngineSettings::default())
        .expect("default engine settings resolve a controller");
    let endpoint = access.client_endpoint();
    let secret = endpoint
        .secret
        .clone()
        .expect("the app-owned controller is authenticated");
    assert!(!secret.is_empty());
    (endpoint, secret)
}

#[test]
fn windows_controller_commands_accept_the_ready_user_agent() {
    let active = snapshot(EngineState::ProxyActive {
        runtime: runtime_for(EngineOwner::WindowsUserAgent, 7, "digest", true),
    });
    running_runtime_identity(EngineRuntimePlatform::Windows, &active)
        .expect("Windows controller commands are reachable");
}

#[test]
fn controller_identity_checks_platform_mode_readiness_generation_and_digest() {
    for platform in [EngineRuntimePlatform::MacOs, EngineRuntimePlatform::Windows] {
        for mode in [
            EngineMode::LocalProxy,
            EngineMode::SystemProxy,
            EngineMode::Tunnel,
            EngineMode::TunnelSystemProxy,
        ] {
            for mismatch in 0..6 {
                let owner = if mode.tunnel_enabled() {
                    platform.tunnel_owner()
                } else {
                    platform.proxy_owner()
                };
                let mut runtime = runtime_for(owner, 7, "digest", true);
                match mismatch {
                    1 => {
                        runtime.owner = match platform {
                            EngineRuntimePlatform::MacOs => {
                                if mode.tunnel_enabled() {
                                    EngineOwner::WindowsTunnelService
                                } else {
                                    EngineOwner::WindowsUserAgent
                                }
                            }
                            EngineRuntimePlatform::Windows => {
                                if mode.tunnel_enabled() {
                                    EngineOwner::PacketTunnelSystemExtension
                                } else {
                                    EngineOwner::ProxyAgent
                                }
                            }
                        }
                    }
                    2 => runtime.ready = false,
                    _ => {}
                }
                let state = match mode {
                    EngineMode::LocalProxy => EngineState::LocalProxyActive { runtime },
                    EngineMode::SystemProxy => EngineState::ProxyActive { runtime },
                    EngineMode::Tunnel => EngineState::TunnelActive { runtime },
                    EngineMode::TunnelSystemProxy => {
                        EngineState::TunnelSystemProxyActive { runtime }
                    }
                    EngineMode::Off => unreachable!(),
                };
                let mut active = snapshot(state);
                match mismatch {
                    3 => active.generation += 1,
                    4 => active.config_digest = Some("other-digest".into()),
                    5 => active.desired_mode = EngineMode::Off,
                    _ => {}
                }
                assert_eq!(
                    running_runtime_identity(platform, &active).is_ok(),
                    mismatch == 0,
                    "{platform:?} {mode:?} mismatch {mismatch}"
                );
            }
        }
    }
}

#[test]
fn controller_access_requires_a_running_ready_engine() {
    for state in [
        EngineState::Off,
        EngineState::ProxyStarting { generation: 1 },
        EngineState::ProxyStopping { generation: 1 },
        EngineState::TunnelInstalling { generation: 1 },
        EngineState::AwaitingApproval { generation: 1 },
        EngineState::TunnelStarting { generation: 1 },
        EngineState::TunnelStopping { generation: 1 },
        EngineState::Failed {
            generation: 1,
            target: EngineMode::Tunnel,
            error: "native failure".into(),
            recheck_pending: false,
        },
        EngineState::ProxyActive {
            runtime: runtime(false),
        },
        EngineState::TunnelActive {
            runtime: runtime_for(EngineOwner::PacketTunnelSystemExtension, 7, "digest", false),
        },
    ] {
        let error =
            running_runtime_identity(EngineRuntimePlatform::MacOs, &snapshot(state.clone()))
                .expect_err("a controller must not be reachable without a ready engine");
        assert!(
            matches!(error, ControllerCommandError::EngineNotRunning),
            "unexpected error for {state:?}: {error:?}"
        );
    }

    for state in [
        EngineState::ProxyActive {
            runtime: runtime(true),
        },
        EngineState::TunnelActive {
            runtime: runtime_for(EngineOwner::PacketTunnelSystemExtension, 7, "digest", true),
        },
    ] {
        running_runtime_identity(EngineRuntimePlatform::MacOs, &snapshot(state))
            .expect("a ready engine exposes its loopback controller");
    }
}

#[test]
fn controller_websocket_buffers_and_messages_are_bounded() {
    let config = controller_websocket_config();
    assert_eq!(config.read_buffer_size, STREAM_READ_BUFFER_BYTES);
    assert_eq!(config.write_buffer_size, STREAM_WRITE_BUFFER_BYTES);
    assert_eq!(config.max_write_buffer_size, STREAM_MAX_WRITE_BUFFER_BYTES);
    assert_eq!(config.max_message_size, Some(STREAM_MAX_MESSAGE_BYTES));
    assert_eq!(config.max_frame_size, Some(STREAM_MAX_FRAME_BYTES));
    assert!(!config.accept_unmasked_frames);
}

#[test]
fn engine_not_running_keeps_the_unreachable_controller_error_shape() {
    let rendered = ControllerCommandError::EngineNotRunning.to_ipc();
    assert!(
        rendered.starts_with("controller HTTP request failed: "),
        "unexpected shape: {rendered}"
    );
    assert!(is_transient_controller_disconnect(&rendered));
}

#[test]
fn command_errors_never_carry_the_controller_secret() {
    let (endpoint, secret) = process_endpoint();
    let client = client_for_endpoint(endpoint).expect("loopback client");
    let websocket_url = client
        .logs_stream_url(LOG_STREAM_LEVEL)
        .expect("loopback log stream url");
    assert!(
        websocket_url.contains(&secret),
        "the handshake url is expected to authenticate with the token"
    );

    // Every message shape that could quote the handshake url.
    let quoted = format!("unable to connect to {websocket_url}");
    for rendered in [
        redact_controller_secret(&quoted),
        ipc_error(ControllerError::InvalidEndpoint(quoted.clone())),
        ControllerCommandError::ClientUnavailable(quoted.clone()).to_ipc(),
        transport_error(tokio_tungstenite::tungstenite::Error::Url(
            tokio_tungstenite::tungstenite::error::UrlError::UnableToConnect(quoted.clone()),
        )),
        stream_error_payload(CONNECTIONS_STREAM, quoted.clone()).message,
        serde_json::to_string(&stream_error_payload(CONNECTIONS_STREAM, quoted.clone()))
            .expect("serialize stream error payload"),
    ] {
        assert!(!rendered.contains(&secret), "leaked secret: {rendered}");
        assert!(
            rendered.contains("token=[REDACTED]"),
            "not redacted: {rendered}"
        );
        assert!(rendered.contains("level=info"), "lost context: {rendered}");
    }
}

#[test]
fn debug_output_never_carries_the_controller_secret() {
    let (endpoint, secret) = process_endpoint();
    let access = EngineControllerAccess::resolve(EngineSettings::default())
        .expect("default engine settings resolve a controller");
    let client = client_for_endpoint(endpoint.clone()).expect("loopback client");
    for rendered in [
        format!("{endpoint:?}"),
        format!("{access:?}"),
        format!("{client:?}"),
        format!("{:?}", ControllerCommandError::EngineNotRunning),
        format!(
            "{:?}",
            ControllerCommandError::Controller(ControllerError::InvalidEndpoint(
                "host is empty".into()
            ))
        ),
    ] {
        assert!(!rendered.contains(&secret), "leaked secret: {rendered}");
    }
}

#[test]
fn redaction_preserves_messages_without_a_token() {
    assert_eq!(
        redact_controller_secret("controller rejected request with HTTP 404: not found"),
        "controller rejected request with HTTP 404: not found"
    );
    assert_eq!(
        redact_controller_secret("ws://127.0.0.1:9090/connections?token=abc"),
        "ws://127.0.0.1:9090/connections?token=[REDACTED]"
    );
    assert_eq!(
        redact_controller_secret("first token=a&x=1 second token=b"),
        "first token=[REDACTED]&x=1 second token=[REDACTED]"
    );
}

#[test]
fn log_lines_normalize_both_controller_log_shapes() {
    let clash = ControllerClient::decode_log_stream_message(
        r#"{"type":"warn","payload":"inbound/mixed: started"}"#,
    )
    .expect("clash-compatible log entry");
    assert_eq!(
        log_line_from_structured(clash),
        LogLinePayload {
            time: "live".into(),
            level: "warning".into(),
            source: "request".into(),
            message: "inbound/mixed: started".into(),
            fields: Vec::new(),
        }
    );

    let structured = ControllerClient::decode_log_stream_message(
            r#"{"time":"2026-05-13T04:05:06Z","level":"ERR","msg":"dns failed","fields":[{"key":"host","value":"example.com"},{"key":"attempt","value":2}]}"#,
        )
        .expect("structured log entry");
    assert_eq!(
        log_line_from_structured(structured),
        LogLinePayload {
            time: "04:05:06".into(),
            level: "error".into(),
            source: "request".into(),
            message: "dns failed".into(),
            fields: vec![
                LogFieldPayload {
                    key: "host".into(),
                    value: "example.com".into(),
                },
                LogFieldPayload {
                    key: "attempt".into(),
                    value: "2".into(),
                },
            ],
        }
    );
}

#[test]
fn each_stream_can_be_stopped_and_started_again() {
    let streams = LiveStreams::default();
    let connections = streams.slot(StreamKind::Connections);
    let logs = streams.slot(StreamKind::Logs);

    let first =
        reserve_stream(connections, StreamKind::Connections, runtime(true)).expect("first claim");
    assert!(first.start_new);
    let duplicate = reserve_stream(connections, StreamKind::Connections, runtime(true))
        .expect("duplicate claim");
    assert!(!duplicate.start_new);
    assert_eq!(duplicate.binding, first.binding);
    assert!(
        reserve_stream(logs, StreamKind::Logs, runtime(true))
            .expect("independent claim")
            .start_new
    );

    stop_stream(connections, &first.binding).expect("stop connections reservation");
    let restarted = reserve_stream(connections, StreamKind::Connections, runtime(true))
        .expect("restart after stop");
    assert!(restarted.start_new);
    assert_eq!(
        restarted.binding.stream_id,
        first.binding.stream_id + 1,
        "same-runtime restart must rotate provenance instead of reusing a stopped stream id"
    );
}

#[test]
fn stale_stream_completion_cannot_release_a_new_owner() {
    let streams = LiveStreams::default();
    let slot = streams.slot(StreamKind::Connections);
    let stale_id = reserve_stream(slot, StreamKind::Connections, runtime(true))
        .expect("stale reservation")
        .binding
        .stream_id;
    let replacement_runtime = runtime_for(EngineOwner::ProxyAgent, 8, "replacement", true);
    let current = reserve_stream(slot, StreamKind::Connections, replacement_runtime)
        .expect("current reservation");
    let current_id = current.binding.stream_id;
    assert_ne!(stale_id, current_id);

    release_stream(slot, stale_id);
    let duplicate = reserve_stream(
        slot,
        StreamKind::Connections,
        current.binding.runtime.clone(),
    )
    .expect("current ownership check");
    assert!(!duplicate.start_new);
    assert_eq!(duplicate.binding, current.binding);
}

#[test]
fn stale_stop_cannot_abort_a_replacement_owner() {
    let streams = LiveStreams::default();
    let slot = streams.slot(StreamKind::Connections);
    let runtime_a = reserve_stream(slot, StreamKind::Connections, runtime(true))
        .expect("runtime A reservation")
        .binding;
    let runtime_b = reserve_stream(
        slot,
        StreamKind::Connections,
        runtime_for(EngineOwner::ProxyAgent, 8, "replacement", true),
    )
    .expect("runtime B reservation")
    .binding;

    stop_stream(slot, &runtime_a).expect("stale runtime A stop");
    let duplicate_b = reserve_stream(slot, StreamKind::Connections, runtime_b.runtime.clone())
        .expect("runtime B ownership check");

    assert!(!duplicate_b.start_new);
    assert_eq!(duplicate_b.binding, runtime_b);
}

#[test]
fn active_runtime_replacement_allocates_new_provenance() {
    let streams = LiveStreams::default();
    let slot = streams.slot(StreamKind::Connections);
    let first = reserve_stream(slot, StreamKind::Connections, runtime(true))
        .expect("runtime A reservation");
    let second = reserve_stream(
        slot,
        StreamKind::Connections,
        runtime_for(EngineOwner::ProxyAgent, 8, "replacement", true),
    )
    .expect("runtime B reservation");

    assert!(first.start_new);
    assert!(second.start_new);
    assert_ne!(first.binding.stream_id, second.binding.stream_id);
    assert_ne!(first.binding.runtime, second.binding.runtime);

    let delayed_a = StreamEvent {
        provenance: first.binding,
        payload: "delayed-a",
    };
    let live_b = StreamEvent {
        provenance: second.binding,
        payload: "live-b",
    };
    assert_ne!(delayed_a.provenance, live_b.provenance);

    let serialized = serde_json::to_value(live_b).expect("serialize live event");
    assert_eq!(serialized["provenance"]["stream"], CONNECTIONS_STREAM);
    assert_eq!(serialized["provenance"]["stream_id"], 2);
    assert_eq!(
        serialized["provenance"]["runtime"]["context"]["generation"],
        8
    );
    assert_eq!(serialized["payload"], "live-b");
}

#[tokio::test]
async fn active_runtime_replacement_aborts_the_running_task() {
    let streams = LiveStreams::default();
    let slot = streams.slot(StreamKind::Connections);
    let runtime_a = reserve_stream(slot, StreamKind::Connections, runtime(true))
        .expect("runtime A reservation")
        .binding;
    let dropped = Arc::new(AtomicBool::new(false));
    let task_dropped = Arc::clone(&dropped);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let handle = tauri::async_runtime::spawn(async move {
        let _drop_flag = DropFlag(task_dropped);
        let _started = started_tx.send(());
        std::future::pending::<()>().await;
    });
    attach_stream(slot, runtime_a.stream_id, handle).expect("attach runtime A task");
    started_rx.await.expect("runtime A task started");

    let replacement = reserve_stream(
        slot,
        StreamKind::Connections,
        runtime_for(EngineOwner::ProxyAgent, 8, "replacement", true),
    )
    .expect("runtime B reservation");
    assert!(replacement.start_new);

    tokio::time::timeout(Duration::from_secs(1), async {
        while !dropped.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("runtime A task was not aborted");
}

#[test]
fn delay_test_target_is_https_and_fixed() {
    assert_eq!(
        resolve_delay_test_url(None).expect("default target"),
        DEFAULT_DELAY_TEST_URL
    );
    assert_eq!(
        resolve_delay_test_url(Some(DEFAULT_DELAY_TEST_URL.into()))
            .expect("explicit pinned target"),
        DEFAULT_DELAY_TEST_URL
    );
    for rejected in [
        "http://www.gstatic.com/generate_204",
        "https://127.0.0.1/private",
        "https://example.com/",
    ] {
        assert!(matches!(
            resolve_delay_test_url(Some(rejected.into())),
            Err(ControllerCommandError::DelayTargetNotAllowed)
        ));
    }
}

#[test]
fn stream_errors_report_only_unexpected_failures_once() {
    let mut last_error = None;
    let reported = [
        ControllerCommandError::EngineNotRunning.to_ipc(),
        "controller rejected request with HTTP 401: unauthorized".to_owned(),
        "controller rejected request with HTTP 401: unauthorized".to_owned(),
        "Connection refused (os error 61)".to_owned(),
    ]
    .into_iter()
    .filter_map(|message| stream_error_to_report(&mut last_error, message))
    .collect::<Vec<_>>();
    assert_eq!(
        reported,
        vec!["controller rejected request with HTTP 401: unauthorized".to_owned()]
    );
}

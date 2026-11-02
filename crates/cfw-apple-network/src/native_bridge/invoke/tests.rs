use std::{sync::Arc, time::Duration};

use super::*;
use crate::{
    NativeBridgeErrorCode, NativeFrameworkBridge,
    native_bridge::{
        BridgeState,
        budget::InvocationTiming,
        fake_native::{
            FakeCancelCompletion, complete_fake_native_late, fake_bridge, fake_native_state,
            ffi_test_serialization, query_request, reset_fake_native,
        },
    },
};

#[tokio::test]
async fn ffi_request_bound_accepts_exact_maximum_and_rejects_maximum_plus_one() {
    let bridge = NativeFrameworkBridge {
        state: Arc::new(BridgeState::Unavailable("test bridge unavailable".into())),
    };
    let request_id = uuid::Uuid::nil();

    let exact_error = bridge
        .invoke_bytes(request_id, vec![b' '; MAXIMUM_REQUEST_BYTES])
        .await
        .expect_err("exact maximum must pass the size admission check");
    assert_eq!(exact_error.code, NativeBridgeErrorCode::Unavailable);

    let oversized_error = bridge
        .invoke_bytes(request_id, vec![b' '; MAXIMUM_REQUEST_BYTES + 1])
        .await
        .expect_err("maximum plus one must fail before bridge invocation");
    assert_eq!(
        oversized_error.code,
        NativeBridgeErrorCode::ConfigurationRejected
    );
}

#[tokio::test]
async fn watchdog_cancels_the_exact_request_and_never_returns_racing_success() {
    let _serial = ffi_test_serialization().lock().await;
    reset_fake_native(FakeCancelCompletion::QueryStatusSuccess, false, 0);
    let bridge = fake_bridge();
    let request_id = uuid::Uuid::new_v4();

    let error = bridge
        .invoke_bytes_with_timing(
            request_id,
            query_request(request_id),
            InvocationTiming {
                operation_budget: Duration::ZERO,
                cleanup_grace: Duration::from_millis(100),
            },
        )
        .await
        .expect_err("watchdog owns the terminal result");

    assert_eq!(error.code, NativeBridgeErrorCode::Timeout);
    assert_eq!(
        error.message,
        "native bridge operation exceeded its bounded execution budget"
    );
    let state = fake_native_state().lock().expect("fake native lock");
    assert_eq!(
        state.cancel_request_ids,
        [request_id.hyphenated().to_string()]
    );
    assert_eq!(state.callback_count, 1);
    assert!(state.context.is_none());
}

#[tokio::test]
async fn dropping_future_cancels_exact_request_and_retains_framework_until_late_callback() {
    let _serial = ffi_test_serialization().lock().await;
    reset_fake_native(FakeCancelCompletion::None, false, 0);
    let bridge = fake_bridge();
    let weak_state = Arc::downgrade(&bridge.state);
    let request_id = uuid::Uuid::new_v4();
    let mut invocation = bridge.invoke_bytes_with_timing(
        request_id,
        query_request(request_id),
        InvocationTiming {
            operation_budget: Duration::from_secs(60),
            cleanup_grace: Duration::from_secs(1),
        },
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(1), &mut invocation)
            .await
            .is_err()
    );
    drop(invocation);
    {
        let state = fake_native_state().lock().expect("fake native lock");
        assert_eq!(
            state.cancel_request_ids,
            [request_id.hyphenated().to_string()]
        );
        assert_eq!(state.callback_count, 0);
        assert!(state.context.is_some());
    }

    drop(bridge);
    assert!(weak_state.upgrade().is_some());
    complete_fake_native_late();
    assert!(weak_state.upgrade().is_none());
    assert_eq!(
        fake_native_state()
            .lock()
            .expect("fake native lock")
            .callback_count,
        1
    );
}

#[tokio::test]
async fn callback_channel_close_is_internal_and_still_cancels_exact_request() {
    let _serial = ffi_test_serialization().lock().await;
    reset_fake_native(FakeCancelCompletion::None, true, 0);
    let bridge = fake_bridge();
    let request_id = uuid::Uuid::new_v4();

    let error = bridge
        .invoke_bytes_with_timing(
            request_id,
            query_request(request_id),
            InvocationTiming {
                operation_budget: Duration::from_secs(1),
                cleanup_grace: Duration::from_millis(1),
            },
        )
        .await
        .expect_err("closed callback owner must fail");

    assert_eq!(error.code, NativeBridgeErrorCode::Internal);
    let state = fake_native_state().lock().expect("fake native lock");
    assert_eq!(
        state.cancel_request_ids,
        [request_id.hyphenated().to_string()]
    );
    assert_eq!(state.callback_count, 0);
}

#[tokio::test]
async fn unexpected_cancel_status_is_internal_and_late_callback_still_releases_context() {
    let _serial = ffi_test_serialization().lock().await;
    reset_fake_native(FakeCancelCompletion::None, false, 2);
    let bridge = fake_bridge();
    let weak_state = Arc::downgrade(&bridge.state);
    let request_id = uuid::Uuid::new_v4();

    let error = bridge
        .invoke_bytes_with_timing(
            request_id,
            query_request(request_id),
            InvocationTiming {
                operation_budget: Duration::from_millis(1),
                cleanup_grace: Duration::from_millis(1),
            },
        )
        .await
        .expect_err("unexpected cancel status must fail");

    assert_eq!(error.code, NativeBridgeErrorCode::Internal);
    {
        let state = fake_native_state().lock().expect("fake native lock");
        assert_eq!(
            state.cancel_request_ids,
            [
                request_id.hyphenated().to_string(),
                request_id.hyphenated().to_string()
            ]
        );
        assert_eq!(state.callback_count, 0);
        assert!(state.context.is_some());
    }
    drop(bridge);
    assert!(weak_state.upgrade().is_some());
    complete_fake_native_late();
    assert!(weak_state.upgrade().is_none());
}

#[tokio::test]
async fn cleanup_grace_expiry_is_bounded_and_late_callback_releases_framework() {
    let _serial = ffi_test_serialization().lock().await;
    reset_fake_native(FakeCancelCompletion::None, false, 0);
    let bridge = fake_bridge();
    let weak_state = Arc::downgrade(&bridge.state);
    let request_id = uuid::Uuid::new_v4();

    let error = bridge
        .invoke_bytes_with_timing(
            request_id,
            query_request(request_id),
            InvocationTiming {
                operation_budget: Duration::ZERO,
                cleanup_grace: Duration::ZERO,
            },
        )
        .await
        .expect_err("cleanup grace expiry must return its bounded timeout");

    assert_eq!(error.code, NativeBridgeErrorCode::Timeout);
    assert_eq!(
        error.message,
        "native bridge operation exceeded its bounded execution budget"
    );
    {
        let state = fake_native_state().lock().expect("fake native lock");
        assert_eq!(
            state.cancel_request_ids,
            [request_id.hyphenated().to_string()]
        );
        assert_eq!(state.callback_count, 0);
        assert!(state.context.is_some());
    }

    drop(bridge);
    assert!(weak_state.upgrade().is_some());
    complete_fake_native_late();
    assert!(weak_state.upgrade().is_none());
    assert_eq!(
        fake_native_state()
            .lock()
            .expect("fake native lock")
            .callback_count,
        1
    );
}

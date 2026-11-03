//! The native callback: it keeps the bridge state alive after its future is
//! cancelled, refuses a negative, empty, oversized or missing response without
//! reading it, and ignores a call without its context.

use super::*;

#[tokio::test]
async fn callback_keeps_dynamic_bridge_state_alive_after_future_cancellation() {
    let bridge = Arc::new(BridgeState::Unavailable("test".into()));
    let weak = Arc::downgrade(&bridge);
    let (sender, receiver) = oneshot::channel();
    let callback = Box::new(CallbackState {
        sender: Some(sender),
        _bridge: Arc::clone(&bridge),
    });
    let context = Box::into_raw(callback).cast::<c_void>();
    drop(bridge);
    assert!(weak.upgrade().is_some());
    let bytes = b"{}";
    // SAFETY: context is one live CallbackState allocation and bytes stay
    // readable for the callback duration.
    unsafe {
        bridge_completion(context, bytes.as_ptr(), bytes.len() as isize);
    }
    assert_eq!(
        receiver.await.expect("callback result").expect("bytes"),
        bytes
    );
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn callback_rejects_negative_response_length_without_reading_memory() {
    let bridge = Arc::new(BridgeState::Unavailable("test".into()));
    let (sender, receiver) = oneshot::channel();
    let callback = Box::new(CallbackState {
        sender: Some(sender),
        _bridge: bridge,
    });
    let context = Box::into_raw(callback).cast::<c_void>();

    // SAFETY: context is one live CallbackState allocation. A negative
    // length must be rejected before the null byte pointer is inspected.
    unsafe {
        bridge_completion(context, std::ptr::null(), -1);
    }

    let error = receiver
        .await
        .expect("callback result")
        .expect_err("negative length must fail closed");
    assert_eq!(error.code, NativeBridgeErrorCode::Internal);
}

#[tokio::test]
async fn the_callback_refuses_an_empty_oversized_or_missing_response_without_reading_it() {
    let bytes = b"{}";
    for (pointer, length, message) in [
        (
            bytes.as_ptr(),
            0,
            "native bridge returned an empty response",
        ),
        (
            bytes.as_ptr(),
            MAXIMUM_RESPONSE_BYTES as isize + 1,
            "native bridge response exceeds the fixed bound",
        ),
        (
            std::ptr::null(),
            bytes.len() as isize,
            "native bridge returned a null response pointer",
        ),
    ] {
        let (sender, receiver) = oneshot::channel();
        let context = Box::into_raw(Box::new(CallbackState {
            sender: Some(sender),
            _bridge: Arc::new(BridgeState::Unavailable("test".into())),
        }))
        .cast::<c_void>();
        // SAFETY: context is one live CallbackState allocation; the length is
        // checked before any byte is read.
        unsafe {
            bridge_completion(context, pointer, length);
        }
        assert_eq!(
            receiver.await.expect("callback result"),
            Err(NativeBridgeError::new(
                NativeBridgeErrorCode::Internal,
                message
            ))
        );
    }
}

#[test]
fn a_callback_without_its_context_is_ignored() {
    let bytes = b"{}";
    // SAFETY: a null context is the one input the callback must ignore.
    unsafe {
        bridge_completion(std::ptr::null_mut(), bytes.as_ptr(), bytes.len() as isize);
    }
}

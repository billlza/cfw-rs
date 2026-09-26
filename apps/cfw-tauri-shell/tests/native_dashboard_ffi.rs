//! Actual Rust -> Swift -> AppKit ABI/resource/lifecycle integration. Uses an
//! explicit presentation fixture; never registers or invokes network services.
use std::sync::atomic::{AtomicUsize, Ordering};

unsafe extern "C" {
    fn cfm_dashboard_present_v2(
        bytes: *const u8,
        count: usize,
        closed: extern "C" fn(usize),
        control: extern "C" fn(usize, u64, u64, u64, u32, u8) -> i32,
        context: usize,
    ) -> i32;
    fn cfm_dashboard_publish_v2(bytes: *const u8, count: usize) -> i32;
    fn cfm_dashboard_close_v2(session: u64) -> i32;
    fn cfm_dashboard_invalidate_v2(session: u64) -> i32;
    fn cfm_dashboard_request_v2(session: u64, control: u32, enabled: u8) -> i32;
}
static RELEASES: AtomicUsize = AtomicUsize::new(0);
static REQUESTS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn closed(context: usize) {
    assert_eq!(context, 1);
    RELEASES.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn control(
    context: usize,
    session: u64,
    revision: u64,
    request: u64,
    control: u32,
    enabled: u8,
) -> i32 {
    if context != 1
        || session != 2
        || enabled != 1
        || !matches!(
            (revision, request, control),
            (2, 1, 1) | (3, 2, 2) | (4, 3, 3)
        )
    {
        return 0;
    }
    REQUESTS.fetch_add(1, Ordering::SeqCst);
    1
}

fn main() {
    let first =
        include_bytes!("../../../native/dashboard/Tests/CFMNativeDashboardTests/Fixtures/off.json");
    // SAFETY: this harness runs AppKit on the process main thread, lends live
    // buffers for synchronous calls and uses a static, scalar callback context.
    unsafe {
        assert_eq!(
            cfm_dashboard_present_v2(first.as_ptr(), first.len(), closed, control, 1),
            1
        );
        assert_eq!(
            cfm_dashboard_publish_v2(first.as_ptr(), first.len()),
            0,
            "replay must fail"
        );
        let mut next: serde_json::Value = serde_json::from_slice(first).unwrap();
        next["sequence"] = 10.into();
        let prior_late_frame = serde_json::to_vec(&next).unwrap();
        assert_eq!(
            cfm_dashboard_publish_v2(prior_late_frame.as_ptr(), prior_late_frame.len()),
            1
        );
        next["sequence"] = 2.into();
        next["session"] = 2.into();
        next["locale"] = "zh-Hans".into();
        for name in ["core", "systemProxy", "tunnel"] {
            next["controls"][name]["available"] = true.into();
            next["controls"][name]["reason"] = serde_json::Value::Null;
        }
        let mut result = next.clone();
        let next = serde_json::to_vec(&next).unwrap();
        assert_eq!(
            cfm_dashboard_present_v2(next.as_ptr(), next.len(), closed, control, 1),
            1
        );
        assert_eq!(
            RELEASES.load(Ordering::SeqCst),
            1,
            "replacement releases the prior observer"
        );
        assert_eq!(
            cfm_dashboard_publish_v2(first.as_ptr(), first.len()),
            2,
            "old session cannot update a reopened window"
        );
        assert_eq!(cfm_dashboard_invalidate_v2(1), 2);
        assert_eq!(cfm_dashboard_request_v2(1, 1, 1), 2);
        assert_eq!(cfm_dashboard_request_v2(2, 99, 1), 0);
        assert_eq!(cfm_dashboard_request_v2(2, 1, 2), 0);
        assert_eq!(REQUESTS.load(Ordering::SeqCst), 0);
        assert_eq!(cfm_dashboard_request_v2(2, 1, 1), 1);
        assert_eq!(REQUESTS.load(Ordering::SeqCst), 1);
        assert_eq!(
            cfm_dashboard_request_v2(2, 3, 1),
            4,
            "a pending action cannot be duplicated"
        );
        result["sequence"] = 3.into();
        result["command"] =
            serde_json::json!({"requestId":1,"pending":false,"error":"Approval denied"});
        let completed = serde_json::to_vec(&result).unwrap();
        assert_eq!(
            cfm_dashboard_publish_v2(completed.as_ptr(), completed.len()),
            1
        );
        assert_eq!(
            cfm_dashboard_request_v2(2, 2, 1),
            1,
            "rejection must leave controls usable"
        );
        assert_eq!(REQUESTS.load(Ordering::SeqCst), 2);
        result["sequence"] = 4.into();
        result["phase"] = "approval".into();
        for name in ["core", "systemProxy", "tunnel"] {
            result[name] = "pending".into();
        }
        for name in ["core", "tunnel"] {
            result["controls"][name]["enabled"] = true.into();
            result["controls"][name]["retry"] = true.into();
        }
        result["command"] = serde_json::json!({"requestId":2,"pending":false,"error":null});
        let approval = serde_json::to_vec(&result).unwrap();
        assert_eq!(
            cfm_dashboard_publish_v2(approval.as_ptr(), approval.len()),
            1
        );
        assert_eq!(
            cfm_dashboard_request_v2(2, 3, 1),
            1,
            "approval can continue without an off transition"
        );
        assert_eq!(REQUESTS.load(Ordering::SeqCst), 3);
        assert_eq!(cfm_dashboard_close_v2(1), 2);
        assert_eq!(cfm_dashboard_close_v2(2), 1);
        assert_eq!(RELEASES.load(Ordering::SeqCst), 2);
        assert_eq!(
            cfm_dashboard_request_v2(2, 1, 1),
            2,
            "closed window cannot invoke its released callback"
        );
        assert_eq!(REQUESTS.load(Ordering::SeqCst), 3);
        assert_eq!(cfm_dashboard_close_v2(2), 2);
        assert_eq!(RELEASES.load(Ordering::SeqCst), 2);
    }
    println!(
        "Native dashboard ABI v2: actual window/resources, Rust-Swift-Rust command roundtrip, matching failed completion, same-mode approval retry, duplicate/stale rejection and exactly-once close callbacks passed; fixture callbacks performed no network operations."
    );
}

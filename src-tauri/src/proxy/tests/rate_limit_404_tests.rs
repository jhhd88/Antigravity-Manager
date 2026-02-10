//! Tests for 404 status code handling:
//! After security fix, 404 is NOT retryable and NOT tracked by RateLimitTracker.
//! parse_from_error should return None for 404.

use crate::proxy::rate_limit::RateLimitTracker;

#[test]
fn test_parse_from_error_404_returns_none() {
    let tracker = RateLimitTracker::new();
    let backoff_steps = vec![60, 300, 1800, 7200];

    // 404 should NOT be tracked as a rate limit event
    let info = tracker.parse_from_error("acc_404", 404, None, "Not Found", None, &backoff_steps);
    assert!(info.is_none(), "404 should return None — not a retryable/rate-limit error");
}

#[test]
fn test_404_does_not_lock_account() {
    let tracker = RateLimitTracker::new();
    let backoff_steps = vec![60, 300, 1800, 7200];

    // Attempt to mark 404 — should be ignored
    tracker.parse_from_error("acc_404_no_lock", 404, None, "Not Found", None, &backoff_steps);

    // Account should NOT be rate limited
    assert!(
        !tracker.is_rate_limited("acc_404_no_lock", None),
        "Account should not be locked after 404"
    );
    assert_eq!(
        tracker.get_remaining_wait("acc_404_no_lock", None),
        0,
        "No wait time after 404"
    );
}

#[test]
fn test_503_still_locks_account() {
    let tracker = RateLimitTracker::new();
    let backoff_steps = vec![60, 300, 1800, 7200];

    // 503 should still work as before
    let info_503 = tracker.parse_from_error(
        "acc_cmp_503", 503, None, "Service Unavailable", None, &backoff_steps,
    );
    assert!(info_503.is_some(), "503 should still return Some");
    assert_eq!(info_503.unwrap().retry_after_sec, 8, "503 should lock for 8s");
}

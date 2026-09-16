//! Injectable wall clock. Python passes `clock: Callable[[], float]` returning
//! `time.time()` seconds; the Rust port uses the same float-seconds contract.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch as `f64`, like Python's `time.time()`.
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn system() -> Clock {
    Arc::new(now)
}

/// A clock frozen at `ts`, for tests.
pub fn fixed(ts: f64) -> Clock {
    Arc::new(move || ts)
}

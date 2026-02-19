use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Computes rolling bytes/sec over a sliding time window.
pub struct RateTracker {
    window: Duration,
    samples: VecDeque<(Instant, u64)>,
    window_sum: u64,
}

impl RateTracker {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            samples: VecDeque::new(),
            window_sum: 0,
        }
    }

    pub fn record(&mut self, bytes: u64) {
        let now = Instant::now();
        self.samples.push_back((now, bytes));
        self.window_sum += bytes;
        self.expire(now);
    }

    #[allow(dead_code)]
    pub fn rate_bps(&mut self) -> f64 {
        let now = Instant::now();
        self.expire(now);
        let elapsed = self.window.as_secs_f64();
        if elapsed == 0.0 {
            return 0.0;
        }
        self.window_sum as f64 / elapsed
    }

    /// Get the current rate without needing &mut self.
    /// (Computes approximate rate using current window_sum.)
    pub fn clone_rate(&self) -> f64 {
        let elapsed = self.window.as_secs_f64();
        if elapsed == 0.0 {
            return 0.0;
        }
        self.window_sum as f64 / elapsed
    }

    pub fn reset(&mut self) {
        self.samples.clear();
        self.window_sum = 0;
    }

    fn expire(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        while let Some(&(ts, bytes)) = self.samples.front() {
            if ts < cutoff {
                self.window_sum = self.window_sum.saturating_sub(bytes);
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Recent event log for computing per-path rates on demand.
pub struct EventLog {
    events: VecDeque<TimestampedEvent>,
    window: Duration,
}

struct TimestampedEvent {
    timestamp: Instant,
    path: String,
    bytes: u64,
}

impl EventLog {
    pub fn new(window: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            window,
        }
    }

    pub fn record(&mut self, path: String, bytes: u64) {
        let now = Instant::now();
        self.events.push_back(TimestampedEvent {
            timestamp: now,
            path,
            bytes,
        });
        self.expire(now);
    }

    /// Compute rate (bytes/sec) for all events under a path prefix.
    pub fn rate_for_prefix(&self, prefix: &str) -> f64 {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let total_bytes: u64 = self
            .events
            .iter()
            .filter(|e| e.timestamp >= cutoff && e.path.starts_with(prefix))
            .map(|e| e.bytes)
            .sum();
        total_bytes as f64 / self.window.as_secs_f64()
    }

    pub fn reset(&mut self) {
        self.events.clear();
    }

    fn expire(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        while let Some(front) = self.events.front() {
            if front.timestamp < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }
}

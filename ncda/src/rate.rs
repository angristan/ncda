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

    pub fn rate_bps(&self) -> f64 {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let bytes: u64 = self
            .samples
            .iter()
            .filter(|(timestamp, _)| *timestamp >= cutoff)
            .map(|(_, bytes)| *bytes)
            .sum();
        let elapsed = self.window.as_secs_f64();
        if elapsed == 0.0 {
            0.0
        } else {
            bytes as f64 / elapsed
        }
    }

    pub fn reset(&mut self) {
        self.samples.clear();
        self.window_sum = 0;
    }

    fn expire(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        while let Some(&(timestamp, bytes)) = self.samples.front() {
            if timestamp < cutoff {
                self.window_sum = self.window_sum.saturating_sub(bytes);
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Recent event log for per-path rates and compact history graphs.
pub struct EventLog {
    events: VecDeque<TimestampedEvent>,
    window: Duration,
}

struct TimestampedEvent {
    timestamp: Instant,
    path: String,
    pid: u32,
    bytes: u64,
}

impl EventLog {
    pub fn new(window: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            window,
        }
    }

    pub fn record(&mut self, path: String, pid: u32, bytes: u64) {
        let now = Instant::now();
        self.events.push_back(TimestampedEvent {
            timestamp: now,
            path,
            pid,
            bytes,
        });
        self.expire(now);
    }

    pub fn rate_for_prefix(&self, prefix: &str) -> f64 {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let total_bytes: u64 = self
            .events
            .iter()
            .filter(|event| event.timestamp >= cutoff && path_matches_prefix(&event.path, prefix))
            .map(|event| event.bytes)
            .sum();
        let elapsed = self.window.as_secs_f64();
        if elapsed == 0.0 {
            0.0
        } else {
            total_bytes as f64 / elapsed
        }
    }

    pub fn sparkline_for_prefix(&self, prefix: &str, buckets: usize) -> Vec<u64> {
        self.bucketize(buckets, Instant::now(), |event| {
            path_matches_prefix(&event.path, prefix)
        })
    }

    pub fn sparkline_for_pid(&self, pid: u32, buckets: usize) -> Vec<u64> {
        self.bucketize(buckets, Instant::now(), |event| event.pid == pid)
    }

    pub fn reset(&mut self) {
        self.events.clear();
    }

    fn bucketize(
        &self,
        buckets: usize,
        now: Instant,
        matches: impl Fn(&TimestampedEvent) -> bool,
    ) -> Vec<u64> {
        if buckets == 0 || self.window.is_zero() {
            return Vec::new();
        }
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let window_ns = self.window.as_nanos().max(1);
        let mut values = vec![0_u64; buckets];
        for event in &self.events {
            if event.timestamp < cutoff || !matches(event) {
                continue;
            }
            let elapsed_ns = event.timestamp.duration_since(cutoff).as_nanos();
            let index = ((elapsed_ns * buckets as u128) / window_ns)
                .min(buckets.saturating_sub(1) as u128) as usize;
            values[index] = values[index].saturating_add(event.bytes);
        }
        values
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

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_prefixes_stop_at_component_boundaries() {
        assert!(path_matches_prefix("/foo/bar", "/foo"));
        assert!(path_matches_prefix("/foo", "/foo"));
        assert!(!path_matches_prefix("/foobar", "/foo"));
        assert!(path_matches_prefix("/[container]/var", "/[container]"));
    }

    #[test]
    fn sparkline_bucketization_preserves_bytes() {
        let mut log = EventLog::new(Duration::from_secs(5));
        log.record("/a".to_string(), 7, 11);
        log.record("/a/b".to_string(), 7, 13);
        let buckets = log.sparkline_for_prefix("/a", 8);
        assert_eq!(buckets.iter().sum::<u64>(), 24);
        assert_eq!(log.sparkline_for_pid(7, 8).iter().sum::<u64>(), 24);
    }

    #[test]
    fn zero_window_rates_are_zero() {
        let mut tracker = RateTracker::new(Duration::ZERO);
        tracker.record(10);
        assert_eq!(tracker.rate_bps(), 0.0);
        let mut log = EventLog::new(Duration::ZERO);
        log.record("/a".to_string(), 1, 10);
        assert_eq!(log.rate_for_prefix("/a"), 0.0);
        assert!(log.sparkline_for_prefix("/a", 8).is_empty());
    }
}

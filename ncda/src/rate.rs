use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::process::ProcessTable;
use crate::tui::filter::FilterQuery;

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
    bucket_origin: Instant,
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
            bucket_origin: Instant::now(),
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

    pub fn rate_for_prefix(
        &self,
        prefix: &str,
        filter: &FilterQuery,
        processes: &ProcessTable,
    ) -> f64 {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let total_bytes: u64 = self
            .events
            .iter()
            .filter(|event| {
                event.timestamp >= cutoff
                    && path_matches_prefix(&event.path, prefix)
                    && filter.matches_activity(
                        &event.path,
                        event.pid,
                        processes.processes.get(&event.pid),
                    )
            })
            .map(|event| event.bytes)
            .sum();
        let elapsed = self.window.as_secs_f64();
        if elapsed == 0.0 {
            0.0
        } else {
            total_bytes as f64 / elapsed
        }
    }

    pub fn sparkline_for_prefix(
        &self,
        prefix: &str,
        buckets: usize,
        filter: &FilterQuery,
        processes: &ProcessTable,
    ) -> Vec<u64> {
        self.sparkline_for_prefix_at(prefix, buckets, filter, processes, Instant::now())
    }

    pub fn sparkline_for_prefix_at(
        &self,
        prefix: &str,
        buckets: usize,
        filter: &FilterQuery,
        processes: &ProcessTable,
        now: Instant,
    ) -> Vec<u64> {
        self.bucketize(buckets, now, |event| {
            path_matches_prefix(&event.path, prefix)
                && filter.matches_activity(
                    &event.path,
                    event.pid,
                    processes.processes.get(&event.pid),
                )
        })
    }

    pub fn sparkline_for_pid(&self, pid: u32, buckets: usize) -> Vec<u64> {
        self.bucketize(buckets, Instant::now(), |event| event.pid == pid)
    }

    pub fn reset(&mut self) {
        self.events.clear();
        self.bucket_origin = Instant::now();
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
        let window_ns = self.window.as_nanos().max(1);
        let bucket_ns = window_ns.div_ceil(buckets as u128);
        let current_tick = now.duration_since(self.bucket_origin).as_nanos() / bucket_ns;
        let mut values = vec![0_u64; buckets];
        for event in &self.events {
            let Some(event_elapsed) = event.timestamp.checked_duration_since(self.bucket_origin)
            else {
                continue;
            };
            if event.timestamp > now || !matches(event) {
                continue;
            }
            let event_tick = event_elapsed.as_nanos() / bucket_ns;
            let age = current_tick.saturating_sub(event_tick);
            if age >= buckets as u128 {
                continue;
            }
            let index = buckets - 1 - age as usize;
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
        let filter = FilterQuery::default();
        let processes = ProcessTable::new();
        let buckets = log.sparkline_for_prefix("/a", 8, &filter, &processes);
        assert_eq!(buckets.iter().sum::<u64>(), 24);
        assert_eq!(log.sparkline_for_pid(7, 8).iter().sum::<u64>(), 24);
    }

    #[test]
    fn sparkline_samples_move_only_on_fixed_ticks() {
        let mut log = EventLog::new(Duration::from_secs(4));
        let origin = log.bucket_origin;
        log.events.extend([
            TimestampedEvent {
                timestamp: origin + Duration::from_millis(100),
                path: "/a".to_string(),
                pid: 7,
                bytes: 5,
            },
            TimestampedEvent {
                timestamp: origin + Duration::from_millis(900),
                path: "/a".to_string(),
                pid: 7,
                bytes: 7,
            },
            TimestampedEvent {
                timestamp: origin + Duration::from_millis(1_100),
                path: "/a".to_string(),
                pid: 7,
                bytes: 4,
            },
        ]);

        assert_eq!(
            log.bucketize(4, origin + Duration::from_millis(1_900), |_| true),
            vec![0, 0, 12, 4]
        );
        assert_eq!(
            log.bucketize(4, origin + Duration::from_millis(1_999), |_| true),
            vec![0, 0, 12, 4]
        );
        assert_eq!(
            log.bucketize(4, origin + Duration::from_millis(2_000), |_| true),
            vec![0, 12, 4, 0]
        );
    }

    #[test]
    fn shared_snapshot_aligns_histories_across_paths() {
        let mut log = EventLog::new(Duration::from_secs(4));
        let origin = log.bucket_origin;
        for (path, bytes) in [("/a", 5), ("/b", 7)] {
            log.events.push_back(TimestampedEvent {
                timestamp: origin + Duration::from_millis(100),
                path: path.to_string(),
                pid: 7,
                bytes,
            });
        }
        let filter = FilterQuery::default();
        let processes = ProcessTable::new();
        let now = origin + Duration::from_millis(2_000);

        assert_eq!(
            log.sparkline_for_prefix_at("/a", 4, &filter, &processes, now),
            vec![0, 5, 0, 0]
        );
        assert_eq!(
            log.sparkline_for_prefix_at("/b", 4, &filter, &processes, now),
            vec![0, 7, 0, 0]
        );
    }

    #[test]
    fn histories_respect_pid_filters() {
        let mut log = EventLog::new(Duration::from_secs(5));
        log.record("/a".to_string(), 7, 11);
        log.record("/a".to_string(), 8, 13);
        let mut processes = ProcessTable::new();
        processes.record(7, crate::model::OpKind::Read, 11, 1);
        processes.record(8, crate::model::OpKind::Read, 13, 1);
        let filter = FilterQuery::parse("pid:7").unwrap();

        assert_eq!(log.rate_for_prefix("/a", &filter, &processes), 2.2);
        assert_eq!(
            log.sparkline_for_prefix("/a", 8, &filter, &processes)
                .iter()
                .sum::<u64>(),
            11
        );
    }

    #[test]
    fn zero_window_rates_are_zero() {
        let mut tracker = RateTracker::new(Duration::ZERO);
        tracker.record(10);
        assert_eq!(tracker.rate_bps(), 0.0);
        let mut log = EventLog::new(Duration::ZERO);
        log.record("/a".to_string(), 1, 10);
        let filter = FilterQuery::default();
        let processes = ProcessTable::new();
        assert_eq!(log.rate_for_prefix("/a", &filter, &processes), 0.0);
        assert!(log
            .sparkline_for_prefix("/a", 8, &filter, &processes)
            .is_empty());
    }
}

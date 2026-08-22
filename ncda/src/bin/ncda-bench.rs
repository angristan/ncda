use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use aya::maps::{PerCpuArray, RingBuf};
use aya::Ebpf;
use clap::{Parser, ValueEnum};
use serde::Serialize;
use tokio::sync::{mpsc, watch};

use ncda::bpf::{self, BpfEvent, ReaderDropCounters, ReaderDropSnapshot};
use ncda_common::CaptureStats;

const MAX_LATENCY_SAMPLES: usize = 1_000_000;

#[derive(Debug, Parser)]
#[command(
    name = "ncda-bench",
    about = "Reproducible sustained ncda capture benchmark",
    version
)]
struct Cli {
    /// Measured workload duration.
    #[clap(long, default_value = "10")]
    duration_seconds: u64,

    /// Unreported warmup duration.
    #[clap(long, default_value = "1")]
    warmup_seconds: u64,

    /// Number of concurrent workload threads.
    #[clap(long, default_value = "1")]
    threads: usize,

    /// I/O operation mix.
    #[clap(long, value_enum, default_value = "mixed")]
    mode: WorkloadMode,

    /// Bytes transferred by each read and write operation.
    #[clap(long, default_value = "4096")]
    block_size: usize,

    /// Time allowed for post-workload ring draining.
    #[clap(long, default_value = "500")]
    drain_ms: u64,

    /// Write JSON to this path instead of stdout.
    #[clap(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkloadMode {
    Read,
    Write,
    Mixed,
}

#[derive(Debug, Default, Clone, Copy)]
struct WorkloadCounters {
    read_ops: u64,
    write_ops: u64,
    read_bytes: u64,
    write_bytes: u64,
}

impl WorkloadCounters {
    fn add(&mut self, other: Self) {
        self.read_ops += other.read_ops;
        self.write_ops += other.write_ops;
        self.read_bytes += other.read_bytes;
        self.write_bytes += other.write_bytes;
    }
}

#[derive(Debug, Default)]
struct ObservedMetrics {
    read_ops: u64,
    write_ops: u64,
    read_bytes: u64,
    write_bytes: u64,
    delivery_latencies_ns: Vec<u64>,
    syscall_latencies_ns: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    environment: Environment,
    configuration: Configuration,
    workload: OperationReport,
    observed: OperationReport,
    event_recall: f64,
    byte_recall: f64,
    observed_events_per_second: f64,
    delivery_latency_ns: LatencyReport,
    syscall_latency_ns: LatencyReport,
    capture: CaptureReport,
    drops: DropReport,
    counter_scope: CounterScope,
}

#[derive(Debug, Serialize)]
struct Environment {
    ncda_version: &'static str,
    architecture: &'static str,
    build_target: &'static str,
    kernel_release: String,
    os_release: String,
    logical_cpus: usize,
    userspace_rustc: &'static str,
    ebpf_toolchain: &'static str,
    bpf_linker: &'static str,
}

#[derive(Debug, Serialize)]
struct Configuration {
    requested_duration_seconds: u64,
    measured_duration_ns: u64,
    warmup_seconds: u64,
    threads: usize,
    mode: WorkloadMode,
    block_size: usize,
    drain_ms: u64,
    max_latency_samples: usize,
}

#[derive(Debug, Serialize)]
struct OperationReport {
    read_ops: u64,
    write_ops: u64,
    read_bytes: u64,
    write_bytes: u64,
}

impl From<WorkloadCounters> for OperationReport {
    fn from(value: WorkloadCounters) -> Self {
        Self {
            read_ops: value.read_ops,
            write_ops: value.write_ops,
            read_bytes: value.read_bytes,
            write_bytes: value.write_bytes,
        }
    }
}

impl From<&ObservedMetrics> for OperationReport {
    fn from(value: &ObservedMetrics) -> Self {
        Self {
            read_ops: value.read_ops,
            write_ops: value.write_ops,
            read_bytes: value.read_bytes,
            write_bytes: value.write_bytes,
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct LatencyReport {
    samples: usize,
    p50: u64,
    p95: u64,
    p99: u64,
    max: u64,
}

#[derive(Debug, Serialize)]
struct CaptureReport {
    read_entries: u64,
    write_entries: u64,
    read_exits: u64,
    write_exits: u64,
}

#[derive(Debug, Serialize)]
struct DropReport {
    kernel_ring: u64,
    kernel_stash: u64,
    kernel_scratch: u64,
    userspace_parse: u64,
    userspace_queue: u64,
    shutdown_discarded: u64,
}

#[derive(Debug, Serialize)]
struct CounterScope {
    observed_events: &'static str,
    capture_counters: &'static str,
    kernel_drops: &'static str,
    userspace_drops: &'static str,
}

struct BenchmarkFiles {
    root: PathBuf,
    paths: Vec<PathBuf>,
}

impl BenchmarkFiles {
    fn create(threads: usize, block_size: usize) -> Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "ncda-bench-{}-{}",
            std::process::id(),
            monotonic_ns()
        ));
        std::fs::create_dir(&root)
            .with_context(|| format!("create benchmark directory {}", root.display()))?;

        let mut paths = Vec::with_capacity(threads);
        for index in 0..threads {
            let path = root.join(format!("worker-{index}.dat"));
            let file = File::create(&path)
                .with_context(|| format!("create benchmark file {}", path.display()))?;
            file.set_len(block_size as u64)?;
            paths.push(path);
        }
        Ok(Self { root, paths })
    }
}

impl Drop for BenchmarkFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.duration_seconds == 0 || cli.threads == 0 || cli.block_size == 0 {
        bail!("duration, threads, and block size must be greater than zero");
    }

    raise_memlock_limit();
    let files = BenchmarkFiles::create(cli.threads, cli.block_size)?;

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ncda"
    )))?;
    bpf::load_programs(&mut ebpf)?;

    let events = ebpf.take_map("EVENTS").context("EVENTS map not found")?;
    let ring_buf = RingBuf::try_from(events)?;
    let capture_stats = ebpf
        .take_map("CAPTURE_STATS")
        .context("CAPTURE_STATS map not found")?;
    let capture_stats = PerCpuArray::<_, ncda_common::CaptureStats>::try_from(capture_stats)?;

    let reader_drops = Arc::new(ReaderDropCounters::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tx, rx) = mpsc::channel(512);
    let reader_handle = tokio::spawn(bpf::reader_loop(
        ring_buf,
        tx,
        shutdown_rx,
        reader_drops.clone(),
    ));

    let measurement_start = Arc::new(AtomicU64::new(u64::MAX));
    let measurement_end = Arc::new(AtomicU64::new(u64::MAX));
    let collector_handle = tokio::spawn(collect_metrics(
        rx,
        std::process::id(),
        measurement_start.clone(),
        measurement_end.clone(),
    ));
    let attached = bpf::attach_programs(&mut ebpf)?;

    if cli.warmup_seconds > 0 {
        run_workload_async(
            files.paths.clone(),
            cli.block_size,
            cli.mode,
            Duration::from_secs(cli.warmup_seconds),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let kernel_start = bpf::capture_stats(&capture_stats)?;
    let userspace_start = reader_drops.snapshot();
    let start_ns = monotonic_ns();
    measurement_start.store(start_ns, Ordering::Release);
    let workload = run_workload_async(
        files.paths.clone(),
        cli.block_size,
        cli.mode,
        Duration::from_secs(cli.duration_seconds),
    )
    .await?;
    let end_ns = monotonic_ns();
    measurement_end.store(end_ns, Ordering::Release);
    let kernel = subtract_capture_stats(bpf::capture_stats(&capture_stats)?, kernel_start);

    tokio::time::sleep(Duration::from_millis(cli.drain_ms)).await;
    attached.detach(&mut ebpf)?;
    drop(ebpf);
    let _ = shutdown_tx.send(true);
    reader_handle.await.context("reader task panicked")??;
    let mut observed = collector_handle.await.context("collector task panicked")?;

    let userspace = subtract_drop_snapshot(reader_drops.snapshot(), userspace_start);
    let expected_events = workload.read_ops + workload.write_ops;
    let observed_events = observed.read_ops + observed.write_ops;
    let expected_bytes = workload.read_bytes + workload.write_bytes;
    let observed_bytes = observed.read_bytes + observed.write_bytes;

    let report = Report {
        schema_version: 2,
        environment: Environment {
            ncda_version: env!("CARGO_PKG_VERSION"),
            architecture: std::env::consts::ARCH,
            build_target: env!("NCDA_BUILD_TARGET"),
            kernel_release: std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap_or_default()
                .trim()
                .to_string(),
            os_release: os_release(),
            logical_cpus: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
            userspace_rustc: env!("NCDA_RUSTC_VERSION"),
            ebpf_toolchain: env!("NCDA_EBPF_TOOLCHAIN"),
            bpf_linker: env!("NCDA_BPF_LINKER_VERSION"),
        },
        configuration: Configuration {
            requested_duration_seconds: cli.duration_seconds,
            measured_duration_ns: end_ns.saturating_sub(start_ns),
            warmup_seconds: cli.warmup_seconds,
            threads: cli.threads,
            mode: cli.mode,
            block_size: cli.block_size,
            drain_ms: cli.drain_ms,
            max_latency_samples: MAX_LATENCY_SAMPLES,
        },
        workload: workload.into(),
        observed: (&observed).into(),
        event_recall: ratio(observed_events, expected_events),
        byte_recall: ratio(observed_bytes, expected_bytes),
        observed_events_per_second: observed_events as f64
            / (end_ns.saturating_sub(start_ns) as f64 / 1_000_000_000.0),
        delivery_latency_ns: latency_report(&mut observed.delivery_latencies_ns),
        syscall_latency_ns: latency_report(&mut observed.syscall_latencies_ns),
        capture: CaptureReport {
            read_entries: kernel.read_entries,
            write_entries: kernel.write_entries,
            read_exits: kernel.read_exits,
            write_exits: kernel.write_exits,
        },
        drops: DropReport {
            kernel_ring: kernel.ring_output_drops,
            kernel_stash: kernel.stash_update_failures,
            kernel_scratch: kernel.scratch_failures,
            userspace_parse: userspace.parse_drops,
            userspace_queue: userspace.queue_drops,
            shutdown_discarded: userspace.shutdown_discarded,
        },
        counter_scope: CounterScope {
            observed_events: "benchmark PID, events emitted during the measurement interval",
            capture_counters: "system-wide delta during the measurement interval",
            kernel_drops: "system-wide delta during the measurement interval",
            userspace_drops: "system-wide delta from measurement start through final drain",
        },
    };

    let mut json = serde_json::to_vec_pretty(&report)?;
    json.push(b'\n');
    if let Some(output) = cli.output {
        std::fs::write(&output, json)
            .with_context(|| format!("write benchmark report {}", output.display()))?;
    } else {
        print!("{}", String::from_utf8(json)?);
    }
    Ok(())
}

async fn run_workload_async(
    paths: Vec<PathBuf>,
    block_size: usize,
    mode: WorkloadMode,
    duration: Duration,
) -> Result<WorkloadCounters> {
    tokio::task::spawn_blocking(move || run_workload(&paths, block_size, mode, duration))
        .await
        .context("workload task panicked")?
}

fn run_workload(
    paths: &[PathBuf],
    block_size: usize,
    mode: WorkloadMode,
    duration: Duration,
) -> Result<WorkloadCounters> {
    let deadline = Instant::now() + duration;
    let mut handles = Vec::with_capacity(paths.len());
    for (index, path) in paths.iter().cloned().enumerate() {
        handles.push(std::thread::spawn(move || -> Result<WorkloadCounters> {
            let file = OpenOptions::new().read(true).write(true).open(&path)?;
            let write_buffer = vec![(index as u8).wrapping_add(1); block_size];
            let mut read_buffer = vec![0_u8; block_size];
            let mut counters = WorkloadCounters::default();
            while Instant::now() < deadline {
                if matches!(mode, WorkloadMode::Read | WorkloadMode::Mixed) {
                    file.read_exact_at(&mut read_buffer, 0)?;
                    counters.read_ops += 1;
                    counters.read_bytes += block_size as u64;
                }
                if matches!(mode, WorkloadMode::Write | WorkloadMode::Mixed) {
                    file.write_all_at(&write_buffer, 0)?;
                    counters.write_ops += 1;
                    counters.write_bytes += block_size as u64;
                }
            }
            Ok(counters)
        }));
    }

    let mut total = WorkloadCounters::default();
    for handle in handles {
        total.add(
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("workload thread panicked"))??,
        );
    }
    Ok(total)
}

async fn collect_metrics(
    mut rx: mpsc::Receiver<Vec<BpfEvent>>,
    benchmark_pid: u32,
    measurement_start: Arc<AtomicU64>,
    measurement_end: Arc<AtomicU64>,
) -> ObservedMetrics {
    let mut metrics = ObservedMetrics::default();
    while let Some(batch) = rx.recv().await {
        let received_ns = monotonic_ns();
        let start_ns = measurement_start.load(Ordering::Acquire);
        let end_ns = measurement_end.load(Ordering::Acquire);
        for event in batch {
            let (pid, bytes, result, syscall_latency_ns, emitted_ns, is_read) = match event {
                BpfEvent::Read {
                    pid,
                    bytes,
                    result,
                    latency_ns,
                    emitted_ns,
                    ..
                } => (pid, bytes, result, latency_ns, emitted_ns, true),
                BpfEvent::Write {
                    pid,
                    bytes,
                    result,
                    latency_ns,
                    emitted_ns,
                    ..
                } => (pid, bytes, result, latency_ns, emitted_ns, false),
                _ => continue,
            };
            if pid != benchmark_pid || result <= 0 || emitted_ns < start_ns || emitted_ns > end_ns {
                continue;
            }

            if is_read {
                metrics.read_ops += 1;
                metrics.read_bytes += bytes;
            } else {
                metrics.write_ops += 1;
                metrics.write_bytes += bytes;
            }
            if metrics.delivery_latencies_ns.len() < MAX_LATENCY_SAMPLES {
                metrics
                    .delivery_latencies_ns
                    .push(received_ns.saturating_sub(emitted_ns));
                metrics.syscall_latencies_ns.push(syscall_latency_ns);
            }
        }
    }
    metrics
}

fn latency_report(samples: &mut [u64]) -> LatencyReport {
    if samples.is_empty() {
        return LatencyReport::default();
    }
    samples.sort_unstable();
    LatencyReport {
        samples: samples.len(),
        p50: percentile(samples, 50),
        p95: percentile(samples, 95),
        p99: percentile(samples, 99),
        max: *samples.last().unwrap(),
    }
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    let index = (sorted.len() - 1) * percentile / 100;
    sorted[index]
}

fn ratio(observed: u64, expected: u64) -> f64 {
    if expected == 0 {
        0.0
    } else {
        observed as f64 / expected as f64
    }
}

fn subtract_capture_stats(end: CaptureStats, start: CaptureStats) -> CaptureStats {
    CaptureStats {
        ring_output_drops: end
            .ring_output_drops
            .saturating_sub(start.ring_output_drops),
        stash_update_failures: end
            .stash_update_failures
            .saturating_sub(start.stash_update_failures),
        scratch_failures: end.scratch_failures.saturating_sub(start.scratch_failures),
        read_entries: end.read_entries.saturating_sub(start.read_entries),
        write_entries: end.write_entries.saturating_sub(start.write_entries),
        read_exits: end.read_exits.saturating_sub(start.read_exits),
        write_exits: end.write_exits.saturating_sub(start.write_exits),
    }
}

fn subtract_drop_snapshot(
    end: ReaderDropSnapshot,
    start: ReaderDropSnapshot,
) -> ReaderDropSnapshot {
    ReaderDropSnapshot {
        parse_drops: end.parse_drops.saturating_sub(start.parse_drops),
        queue_drops: end.queue_drops.saturating_sub(start.queue_drops),
        shutdown_discarded: end
            .shutdown_discarded
            .saturating_sub(start.shutdown_discarded),
    }
}

fn os_release() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|value| value.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(result, 0, "clock_gettime(CLOCK_MONOTONIC) failed");
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn raise_memlock_limit() {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_and_ratio_are_deterministic() {
        let mut samples = vec![50, 10, 40, 20, 30];
        let report = latency_report(&mut samples);
        assert_eq!(report.p50, 30);
        assert_eq!(report.p95, 40);
        assert_eq!(report.p99, 40);
        assert_eq!(report.max, 50);
        assert_eq!(ratio(9, 10), 0.9);
    }

    #[test]
    fn workload_performs_balanced_io() {
        let files = BenchmarkFiles::create(1, 64).unwrap();
        let counters = run_workload(
            &files.paths,
            64,
            WorkloadMode::Mixed,
            Duration::from_millis(10),
        )
        .unwrap();
        assert!(counters.read_ops > 0);
        assert_eq!(counters.read_ops, counters.write_ops);
        assert_eq!(counters.read_bytes, counters.write_bytes);
    }

    #[test]
    fn benchmark_rejects_zero_work() {
        assert_eq!(ratio(0, 0), 0.0);
    }

    #[test]
    fn counter_deltas_exclude_warmup_and_saturate() {
        let kernel = subtract_capture_stats(
            CaptureStats {
                ring_output_drops: 9,
                read_entries: 101,
                ..CaptureStats::default()
            },
            CaptureStats {
                ring_output_drops: 7,
                read_entries: 100,
                write_entries: 5,
                ..CaptureStats::default()
            },
        );
        assert_eq!(kernel.ring_output_drops, 2);
        assert_eq!(kernel.read_entries, 1);
        assert_eq!(kernel.write_entries, 0);

        let userspace = subtract_drop_snapshot(
            ReaderDropSnapshot {
                parse_drops: 12,
                queue_drops: 8,
                shutdown_discarded: 7,
            },
            ReaderDropSnapshot {
                parse_drops: 10,
                queue_drops: 9,
                shutdown_discarded: 4,
            },
        );
        assert_eq!(userspace.parse_drops, 2);
        assert_eq!(userspace.queue_drops, 0);
        assert_eq!(userspace.shutdown_discarded, 3);
    }
}

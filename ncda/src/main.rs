use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::Ebpf;
use clap::Parser;
use log::{debug, info, warn};
use tokio::sync::{mpsc, watch};

use ncda::bpf::{self, BpfEvent, ReaderDropCounters};
use ncda::container::{ContainerResolver, REDISCOVERY_INTERVAL};
use ncda::tui::app::AppState;
use ncda::{model, tui};

#[derive(Debug, Parser)]
#[command(
    name = "ncda",
    about = "Real-time file access monitor (ncdu for live I/O)",
    version
)]
struct Cli {
    /// Rolling rate window in seconds.
    #[clap(long, default_value = "5")]
    rate_window: u64,

    /// Exclude paths matching this prefix (repeatable).
    #[clap(long = "exclude", default_values_t = vec![
        "/proc".to_string(),
        "/sys".to_string(),
        "/dev".to_string(),
    ])]
    exclude: Vec<String>,

    /// Print events to stdout instead of running the TUI.
    #[clap(long)]
    stdout: bool,

    /// Enable verbose logging.
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }

    // Arm handlers before any global probe is attached. Signals received
    // during later startup are then handled by the ordered shutdown path.
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("install SIGTERM handler")?;

    // Bump memlock rlimit for older kernels
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load eBPF bytecode. The programs do not emit Aya log records, so no
    // kernel logger map or userspace logger task is needed.
    info!("loading eBPF programs...");
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ncda"
    )))
    .map_err(anyhow::Error::from)
    .map_err(add_ebpf_permission_hint)?;

    let process_exit_hook = bpf::load_programs(&mut ebpf).map_err(add_ebpf_permission_hint)?;

    // Own both maps independently so dropping `ebpf` detaches all producers
    // before the reader's final drain.
    let events = ebpf.take_map("EVENTS").context("EVENTS map not found")?;
    let ring_buf = RingBuf::try_from(events)?;
    let capture_stats = ebpf
        .take_map("CAPTURE_STATS")
        .context("CAPTURE_STATS map not found")?;
    let capture_stats = PerCpuArray::<_, ncda_common::CaptureStats>::try_from(capture_stats)
        .context("CAPTURE_STATS has unexpected map type")?;
    let capture_stats = Arc::new(Mutex::new(capture_stats));

    // Shared application state
    let rate_window = Duration::from_secs(cli.rate_window);
    let state = Arc::new(Mutex::new(AppState::new(rate_window, cli.exclude)));
    let (container_shutdown_tx, container_shutdown_rx) = watch::channel(false);
    let container_handle = tokio::spawn(monitor_container_discovery(
        state.clone(),
        container_shutdown_rx,
    ));

    // Channel: BPF reader → aggregator.
    let (tx, mut rx) = mpsc::channel::<Vec<BpfEvent>>(512);
    let reader_drops = Arc::new(ReaderDropCounters::default());
    let (reader_shutdown_tx, reader_shutdown_rx) = watch::channel(false);
    let (worker_exit_tx, mut worker_exit_rx) = mpsc::unbounded_channel::<WorkerExit>();
    let reader_exit_tx = worker_exit_tx.clone();
    let reader_task_drops = Arc::clone(&reader_drops);
    let reader_handle = tokio::spawn(async move {
        let result = bpf::reader_loop(ring_buf, tx, reader_shutdown_rx, reader_task_drops).await;
        let _ = reader_exit_tx.send(WorkerExit::from_result("BPF reader", &result));
        result
    });

    // The reader is ready before global producers become active. Exit hooks
    // attach before sys_enter so no entry can outlive its consumer.
    let attached =
        bpf::attach_programs(&mut ebpf, process_exit_hook).map_err(add_ebpf_permission_hint)?;
    info!("all eBPF programs attached");

    let discard_pending = Arc::new(AtomicBool::new(false));
    let agg_discard_pending = Arc::clone(&discard_pending);
    let agg_reader_drops = Arc::clone(&reader_drops);
    let agg_state = state.clone();
    let aggregator_exit_tx = worker_exit_tx.clone();
    let aggregator_handle = tokio::spawn(async move {
        while let Some(batch) = rx.recv().await {
            handle_aggregator_batch(
                &agg_state,
                batch,
                agg_discard_pending.load(Ordering::Acquire),
                &agg_reader_drops,
            );
        }
        let _ = aggregator_exit_tx.send(WorkerExit::ok("aggregator"));
    });

    // Keep the live drop count visible without reading BPF maps in the draw
    // path. A final sample is taken after the reader and aggregator stop.
    let (stats_shutdown_tx, stats_shutdown_rx) = watch::channel(false);
    let stats_exit_tx = worker_exit_tx.clone();
    let stats_state = state.clone();
    let stats_handle = tokio::spawn(async move {
        let result =
            monitor_drop_counters(capture_stats, reader_drops, stats_state, stats_shutdown_rx)
                .await;
        let _ = stats_exit_tx.send(WorkerExit::from_result("capture stats", &result));
        result
    });
    drop(worker_exit_tx);

    let output_shutdown = Arc::new(AtomicBool::new(false));
    let output_state = state.clone();
    let output_flag = Arc::clone(&output_shutdown);
    let mut output_handle = if cli.stdout {
        tokio::spawn(run_stdout_mode(output_state, output_flag))
    } else {
        tokio::task::spawn_blocking(move || tui::run_with_shutdown(output_state, output_flag))
    };
    let mut output_finished = false;
    let mode_result = tokio::select! {
        result = &mut output_handle => {
            output_finished = true;
            result.context("output task panicked")?
        }
        result = &mut interrupt => result.context("listen for SIGINT"),
        _ = terminate.recv() => Ok(()),
        worker = worker_exit_rx.recv() => {
            let worker = worker.context("critical worker status channel closed")?;
            Err(anyhow::anyhow!(worker.message()))
        }
    };
    output_shutdown.store(true, Ordering::Release);

    // Stop expensive aggregation as soon as output ends. The reader still
    // drains every kernel record, while the aggregator counts and discards
    // pending batches instead of rebuilding state that will never be shown.
    let shutdown_started = Instant::now();
    let mut failures = Vec::new();
    if let Err(error) = mode_result {
        failures.push(format!("output: {error:#}"));
    }
    discard_pending.store(true, Ordering::Release);
    let _ = container_shutdown_tx.send(true);
    if let Err(error) = attached.detach(&mut ebpf) {
        failures.push(format!("ordered eBPF detach: {error:#}"));
    }
    drop(ebpf);
    let _ = reader_shutdown_tx.send(true);
    match reader_handle.await {
        Ok(Ok(())) => info!("ring drained in {:?}", shutdown_started.elapsed()),
        Ok(Err(error)) => failures.push(format!("BPF reader: {error:#}")),
        Err(error) => failures.push(format!("BPF reader panicked: {error}")),
    }
    if let Err(error) = aggregator_handle.await {
        failures.push(format!("aggregator panicked: {error}"));
    }
    info!("queue closed in {:?}", shutdown_started.elapsed());

    match container_handle.await {
        Ok(Ok(())) => info!("enrichment stopped in {:?}", shutdown_started.elapsed()),
        Ok(Err(error)) => failures.push(format!("container discovery: {error:#}")),
        Err(error) => failures.push(format!("container discovery panicked: {error}")),
    }

    let _ = stats_shutdown_tx.send(true);
    if !output_finished {
        match output_handle.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(format!("output: {error:#}")),
            Err(error) => failures.push(format!("output task panicked: {error}")),
        }
    }
    let final_drops = match stats_handle.await {
        Ok(Ok(snapshot)) => snapshot,
        Ok(Err(error)) => {
            failures.push(format!("capture stats: {error:#}"));
            DropSnapshot::default()
        }
        Err(error) => {
            failures.push(format!("capture stats task panicked: {error}"));
            DropSnapshot::default()
        }
    };
    info!("shutdown completed in {:?}", shutdown_started.elapsed());
    if final_drops.shutdown_discarded > 0 {
        info!(
            "discarded {} pending events after output closed",
            final_drops.shutdown_discarded
        );
    }
    if final_drops.total() > 0 {
        warn!(
            "capture lost {} events (ring={}, stash={}, scratch={}, parse={}, queue={})",
            final_drops.total(),
            final_drops.ring_output_drops,
            final_drops.stash_update_failures,
            final_drops.scratch_failures,
            final_drops.parse_drops,
            final_drops.queue_drops,
        );
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(failures.join("\n")))
    }
}

#[derive(Debug)]
struct WorkerExit {
    name: &'static str,
    error: Option<String>,
}

impl WorkerExit {
    fn ok(name: &'static str) -> Self {
        Self { name, error: None }
    }

    fn from_result<T>(name: &'static str, result: &Result<T>) -> Self {
        Self {
            name,
            error: result.as_ref().err().map(|error| format!("{error:#}")),
        }
    }

    fn message(&self) -> String {
        match &self.error {
            Some(error) => format!("{} task failed: {error}", self.name),
            None => format!("{} task stopped unexpectedly", self.name),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct DropSnapshot {
    ring_output_drops: u64,
    stash_update_failures: u64,
    scratch_failures: u64,
    parse_drops: u64,
    queue_drops: u64,
    shutdown_discarded: u64,
}

impl DropSnapshot {
    fn total(self) -> u64 {
        self.ring_output_drops
            + self.stash_update_failures
            + self.scratch_failures
            + self.parse_drops
            + self.queue_drops
    }
}

fn handle_aggregator_batch(
    state: &Mutex<AppState>,
    batch: Vec<BpfEvent>,
    discard: bool,
    counters: &ReaderDropCounters,
) {
    if discard {
        counters.record_shutdown_discarded(batch.len());
    } else {
        state.lock().unwrap().ingest(batch);
    }
}

async fn monitor_container_discovery(
    state: Arc<Mutex<AppState>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let discovered = tokio::task::spawn_blocking(ContainerResolver::discover_blocking)
            .await
            .context("container discovery worker panicked")?;
        state
            .lock()
            .unwrap()
            .containers
            .replace_discovery(discovered);

        tokio::select! {
            _ = tokio::time::sleep(REDISCOVERY_INTERVAL) => {}
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

async fn monitor_drop_counters(
    capture_stats: Arc<Mutex<PerCpuArray<MapData, ncda_common::CaptureStats>>>,
    reader_drops: Arc<ReaderDropCounters>,
    state: Arc<Mutex<AppState>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<DropSnapshot> {
    let mut interval = tokio::time::interval(Duration::from_millis(250));

    loop {
        let kernel = {
            let map = capture_stats.lock().unwrap();
            bpf::capture_stats(&map).context("read kernel capture counters")?
        };
        let reader = reader_drops.snapshot();
        let snapshot = DropSnapshot {
            ring_output_drops: kernel.ring_output_drops,
            stash_update_failures: kernel.stash_update_failures,
            scratch_failures: kernel.scratch_failures,
            parse_drops: reader.parse_drops,
            queue_drops: reader.queue_drops,
            shutdown_discarded: reader.shutdown_discarded,
        };
        state.lock().unwrap().update_drop_total(snapshot.total());

        if *shutdown.borrow() {
            return Ok(snapshot);
        }

        tokio::select! {
            _ = interval.tick() => {}
            result = shutdown.changed() => {
                if result.is_err() {
                    return Ok(snapshot);
                }
            }
        }
    }
}

fn add_ebpf_permission_hint(error: anyhow::Error) -> anyhow::Error {
    let resource_error = error.chain().find_map(|cause| {
        cause.downcast_ref::<io::Error>().and_then(|error| {
            matches!(
                error.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENOMEM)
            )
            .then_some(error.raw_os_error().unwrap_or_default())
        })
    });
    if resource_error.is_none() {
        return error;
    }

    let program = std::env::args_os()
        .next()
        .map(|arg| arg.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ncda".to_string());
    let caps = effective_capabilities().unwrap_or_default();
    let lockdown = std::fs::read_to_string("/sys/kernel/security/lockdown")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unavailable".to_string());
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let memlock = if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } == 0 {
        format!("{}/{} bytes", limit.rlim_cur, limit.rlim_max)
    } else {
        "unavailable".to_string()
    };
    error.context(format!(
        "unable to initialize eBPF (uid={}, effective capabilities: {}; lockdown: {}; RLIMIT_MEMLOCK: {})\nRoot or CAP_BPF+CAP_PERFMON is normally required; CAP_SYS_ADMIN is the legacy alternative. CAP_SYS_PTRACE may also be needed for cross-process path resolution. On pre-5.11 kernels, increase RLIMIT_MEMLOCK (and CAP_SYS_RESOURCE may be required). Active confidentiality lockdown can deny kernel reads.\nTry: sudo {program}",
        unsafe { libc::geteuid() },
        format_capabilities(caps),
        lockdown,
        memlock,
    ))
}

fn effective_capabilities() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))?;
    u64::from_str_radix(value.trim(), 16).ok()
}

fn format_capabilities(bits: u64) -> String {
    const CAPS: [(u32, &str); 4] = [
        (21, "CAP_SYS_ADMIN"),
        (24, "CAP_SYS_RESOURCE"),
        (38, "CAP_PERFMON"),
        (39, "CAP_BPF"),
    ];
    let present = CAPS
        .iter()
        .filter_map(|(bit, name)| ((bits & (1_u64 << bit)) != 0).then_some(*name))
        .collect::<Vec<_>>();
    if present.is_empty() {
        "none relevant".to_string()
    } else {
        present.join(",")
    }
}

/// Run in stdout mode — prints a periodic summary to the terminal.
async fn run_stdout_mode(state: Arc<Mutex<AppState>>, shutdown: Arc<AtomicBool>) -> Result<()> {
    println!("ncda: monitoring file access (Ctrl+C to stop)...\n");
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        if shutdown.load(Ordering::Acquire) {
            println!("\nExiting.");
            return Ok(());
        }
        tokio::select! {
            _ = interval.tick() => {
                let s = state.lock().unwrap();
                let root = &s.tree.root;
                println!(
                    "Events:{:>8} | Drops:{:>6} | Attr:{:>6} | Err:{:>6} Zero:{:>6} | R:{:>10} W:{:>10} | Ops:{:>8} | FDs cached:{:>6}",
                    s.total_events,
                    s.dropped_events,
                    s.attribution_failures,
                    s.failed_io_events,
                    s.zero_byte_io_events,
                    ncda::tui::footer::format_bytes(root.agg_stats.read_bytes),
                    ncda::tui::footer::format_bytes(root.agg_stats.write_bytes),
                    ncda::tui::footer::format_count(root.agg_stats.total_ops()),
                    s.fd_cache.len(),
                );

                // Print top directories
                let children = root.sorted_children(model::SortBy::TotalBytes, true);
                for child in children.iter().take(10) {
                    let stats = &child.agg_stats;
                    println!(
                        "  /{:<30} R:{:>8} W:{:>8} Ops:{:>6}",
                        if child.is_dir { format!("{}/", child.name) } else { child.name.clone() },
                        ncda::tui::footer::format_bytes(stats.read_bytes),
                        ncda::tui::footer::format_bytes(stats.write_bytes),
                        ncda::tui::footer::format_count(stats.total_ops()),
                    );
                }
                println!();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ebpf_permission_errors_include_sudo_hint() {
        let error = io::Error::from_raw_os_error(libc::EPERM).into();
        let message = format!("{:#}", add_ebpf_permission_hint(error));

        assert!(message.contains("unable to initialize eBPF"));
        assert!(message.contains("CAP_BPF+CAP_PERFMON"));
        assert!(message.contains("CAP_SYS_PTRACE"));
        assert!(message.contains("RLIMIT_MEMLOCK"));
        assert!(message.contains("lockdown:"));
        assert!(message.contains("Try: sudo"));
        assert!(message.contains("Operation not permitted"));
    }

    #[test]
    fn capability_names_are_reported_precisely() {
        assert_eq!(format_capabilities(0), "none relevant");
        assert_eq!(
            format_capabilities((1 << 38) | (1 << 39)),
            "CAP_PERFMON,CAP_BPF"
        );
    }

    #[test]
    fn other_ebpf_errors_are_unchanged() {
        let error = anyhow::anyhow!("invalid eBPF object");
        let message = format!("{:#}", add_ebpf_permission_hint(error));

        assert_eq!(message, "invalid eBPF object");
    }

    #[test]
    fn drop_snapshot_sums_every_loss_class() {
        let snapshot = DropSnapshot {
            ring_output_drops: 1,
            stash_update_failures: 2,
            scratch_failures: 3,
            parse_drops: 4,
            queue_drops: 5,
            shutdown_discarded: 99,
        };

        assert_eq!(snapshot.total(), 15);
    }

    #[test]
    fn shutdown_batches_are_counted_without_aggregation() {
        let state = Mutex::new(AppState::new(Duration::from_secs(5), Vec::new()));
        let counters = ReaderDropCounters::default();
        let event = BpfEvent::ProcessExit {
            pid: 42,
            emitted_ns: 1,
        };

        handle_aggregator_batch(&state, vec![event.clone()], true, &counters);
        assert_eq!(state.lock().unwrap().total_events, 0);
        assert_eq!(counters.snapshot().shutdown_discarded, 1);

        handle_aggregator_batch(&state, vec![event], false, &counters);
        assert_eq!(state.lock().unwrap().total_events, 1);
        assert_eq!(counters.snapshot().shutdown_discarded, 1);
    }
}

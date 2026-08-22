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

    bpf::load_programs(&mut ebpf).map_err(add_ebpf_permission_hint)?;

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
    let reader_handle = tokio::spawn(bpf::reader_loop(
        ring_buf,
        tx,
        reader_shutdown_rx,
        reader_drops.clone(),
    ));

    // The reader is ready before global producers become active. Exit hooks
    // attach before sys_enter so no entry can outlive its consumer.
    let attached = bpf::attach_programs(&mut ebpf).map_err(add_ebpf_permission_hint)?;
    info!("all eBPF programs attached");

    let discard_pending = Arc::new(AtomicBool::new(false));
    let agg_discard_pending = Arc::clone(&discard_pending);
    let agg_reader_drops = Arc::clone(&reader_drops);
    let agg_state = state.clone();
    let aggregator_handle = tokio::spawn(async move {
        while let Some(batch) = rx.recv().await {
            handle_aggregator_batch(
                &agg_state,
                batch,
                agg_discard_pending.load(Ordering::Acquire),
                &agg_reader_drops,
            );
        }
    });

    // Keep the live drop count visible without reading BPF maps in the draw
    // path. A final sample is taken after the reader and aggregator stop.
    let (stats_shutdown_tx, stats_shutdown_rx) = watch::channel(false);
    let stats_handle = tokio::spawn(monitor_drop_counters(
        capture_stats,
        reader_drops,
        state.clone(),
        stats_shutdown_rx,
    ));

    let mode_result = if cli.stdout {
        run_stdout_mode(state.clone()).await
    } else {
        run_tui_mode(state.clone())
    };

    // Stop expensive aggregation as soon as output ends. The reader still
    // drains every kernel record, while the aggregator counts and discards
    // pending batches instead of rebuilding state that will never be shown.
    let shutdown_started = Instant::now();
    discard_pending.store(true, Ordering::Release);
    let _ = container_shutdown_tx.send(true);
    if let Err(error) = attached.detach(&mut ebpf) {
        warn!("ordered eBPF detach failed: {error:#}");
    }
    drop(ebpf);
    let _ = reader_shutdown_tx.send(true);
    reader_handle.await.context("BPF reader task panicked")??;
    info!("ring drained in {:?}", shutdown_started.elapsed());
    aggregator_handle
        .await
        .context("aggregator task panicked")?;
    info!("queue closed in {:?}", shutdown_started.elapsed());

    container_handle
        .await
        .context("container discovery task panicked")??;
    info!("enrichment stopped in {:?}", shutdown_started.elapsed());

    let _ = stats_shutdown_tx.send(true);
    let final_drops = stats_handle
        .await
        .context("capture stats task panicked")??;
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

    mode_result
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
    let permission_denied = error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
    });

    if !permission_denied {
        return error;
    }

    let program = std::env::args_os()
        .next()
        .map(|arg| arg.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ncda".to_string());
    error.context(format!(
        "insufficient permissions to initialize eBPF; ncda requires root or suitable eBPF capabilities\nTry: sudo {program}"
    ))
}

/// Run in stdout mode — prints a periodic summary to the terminal.
async fn run_stdout_mode(state: Arc<Mutex<AppState>>) -> Result<()> {
    println!("ncda: monitoring file access (Ctrl+C to stop)...\n");

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                println!("\nExiting.");
                return Ok(());
            }
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

/// Run the interactive TUI.
fn run_tui_mode(state: Arc<Mutex<AppState>>) -> Result<()> {
    tui::run(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ebpf_permission_errors_include_sudo_hint() {
        let error = io::Error::from_raw_os_error(libc::EPERM).into();
        let message = format!("{:#}", add_ebpf_permission_hint(error));

        assert!(message.contains("insufficient permissions to initialize eBPF"));
        assert!(message.contains("Try: sudo"));
        assert!(message.contains("Operation not permitted"));
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

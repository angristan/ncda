mod bpf;
mod container;
mod model;
mod process;
mod rate;
mod tui;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use aya::maps::RingBuf;
use aya::Ebpf;
use clap::Parser;
use log::{debug, info};
use tokio::sync::mpsc;

use crate::bpf::BpfEvent;
use crate::tui::app::AppState;

#[derive(Debug, Parser)]
#[clap(
    name = "ncda",
    about = "Real-time file access monitor (ncdu for live I/O)"
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

    // Attach tracepoints.
    bpf::load_and_attach(&mut ebpf).map_err(add_ebpf_permission_hint)?;
    info!("all eBPF programs attached");

    // Take ownership of the ring buffer map so it can be moved into a 'static task
    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;

    // Shared application state
    let rate_window = Duration::from_secs(cli.rate_window);
    let state = Arc::new(Mutex::new(AppState::new(rate_window, cli.exclude)));

    // Channel: BPF reader → aggregator
    let (tx, mut rx) = mpsc::channel::<Vec<BpfEvent>>(512);

    // Spawn BPF reader task
    tokio::task::spawn(async move {
        if let Err(e) = bpf::reader_loop_polling(ring_buf, tx).await {
            log::error!("BPF reader error: {e}");
        }
    });

    // Spawn aggregator task
    let agg_state = state.clone();
    tokio::task::spawn(async move {
        while let Some(batch) = rx.recv().await {
            let mut s = agg_state.lock().unwrap();
            s.ingest(batch);
        }
    });

    if cli.stdout {
        // Stdout mode: periodically print a summary
        run_stdout_mode(state).await
    } else {
        // TUI mode
        run_tui_mode(state)
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
                    "Events:{:>8} | R:{:>10} W:{:>10} | Ops:{:>8} | FDs cached:{:>6}",
                    s.total_events,
                    crate::tui::footer::format_bytes(root.agg_stats.read_bytes),
                    crate::tui::footer::format_bytes(root.agg_stats.write_bytes),
                    crate::tui::footer::format_count(root.agg_stats.total_ops()),
                    s.fd_cache.len(),
                );

                // Print top directories
                let children = root.sorted_children(model::SortBy::TotalBytes, true);
                for child in children.iter().take(10) {
                    let stats = &child.agg_stats;
                    println!(
                        "  /{:<30} R:{:>8} W:{:>8} Ops:{:>6}",
                        if child.is_dir { format!("{}/", child.name) } else { child.name.clone() },
                        crate::tui::footer::format_bytes(stats.read_bytes),
                        crate::tui::footer::format_bytes(stats.write_bytes),
                        crate::tui::footer::format_count(stats.total_ops()),
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
}

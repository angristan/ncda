#![cfg(target_os = "linux")]

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;

use aya::maps::{PerCpuArray, RingBuf};
use aya::Ebpf;
use ncda::bpf::{self, BpfEvent, ReaderDropCounters};
use tokio::sync::{mpsc, watch};

const DATA: &[u8; 8] = b"ncda-io!";

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("ncda-integration-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        Self { root }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires root and live eBPF support"]
async fn captures_extended_fd_lifecycle_without_loss() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run with scripts/test-ebpf.sh"
    );
    raise_memlock_limit();

    let fixture = Fixture::new();
    let directory = std::fs::File::open(&fixture.root).unwrap();
    let preexisting_path = fixture.root.join("preexisting.dat");
    let preexisting_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&preexisting_path)
        .unwrap();
    preexisting_file.set_len(DATA.len() as u64).unwrap();
    let preexisting_fd =
        unsafe { libc::fcntl(preexisting_file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 1000) };
    assert!(preexisting_fd >= 1000);
    drop(preexisting_file);

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ncda"
    )))
    .unwrap();
    bpf::load_and_attach(&mut ebpf).unwrap();

    let events = ebpf.take_map("EVENTS").unwrap();
    let ring_buf = RingBuf::try_from(events).unwrap();
    let capture_stats = ebpf.take_map("CAPTURE_STATS").unwrap();
    let capture_stats =
        PerCpuArray::<_, ncda_common::CaptureStats>::try_from(capture_stats).unwrap();
    let reader_drops = Arc::new(ReaderDropCounters::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tx, mut rx) = mpsc::channel(512);
    let reader = tokio::spawn(bpf::reader_loop(
        ring_buf,
        tx,
        shutdown_rx,
        reader_drops.clone(),
    ));
    let collector = tokio::spawn(async move {
        let mut events = Vec::new();
        while let Some(batch) = rx.recv().await {
            events.extend(batch);
        }
        events
    });

    let relative_name = CString::new("lifecycle.dat").unwrap();
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            relative_name.as_ptr(),
            libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    assert!(fd >= 0);

    let openat2_name = CString::new("openat2.dat").unwrap();
    let how = OpenHow {
        flags: (libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR | libc::O_CLOEXEC) as u64,
        mode: 0o600,
        resolve: 0,
    };
    let openat2_fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory.as_raw_fd(),
            openat2_name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        ) as i32
    };
    assert!(
        openat2_fd >= 0,
        "openat2 failed: {}",
        std::io::Error::last_os_error()
    );

    assert_eq!(
        unsafe { libc::write(fd, DATA.as_ptr().cast(), DATA.len()) },
        8
    );
    assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_SET) }, 0);
    let mut buffer = [0_u8; 8];
    assert_eq!(
        unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) },
        8
    );
    assert_eq!(
        unsafe { libc::pwrite(fd, DATA.as_ptr().cast(), DATA.len(), 0) },
        8
    );
    assert_eq!(
        unsafe { libc::pread(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) },
        8
    );

    let write_parts = [
        libc::iovec {
            iov_base: DATA[..4].as_ptr().cast_mut().cast(),
            iov_len: 4,
        },
        libc::iovec {
            iov_base: DATA[4..].as_ptr().cast_mut().cast(),
            iov_len: 4,
        },
    ];
    assert_eq!(unsafe { libc::writev(fd, write_parts.as_ptr(), 2) }, 8);
    assert_eq!(unsafe { libc::lseek(fd, 8, libc::SEEK_SET) }, 8);
    let mut read_a = [0_u8; 4];
    let mut read_b = [0_u8; 4];
    let mut read_parts = [
        libc::iovec {
            iov_base: read_a.as_mut_ptr().cast(),
            iov_len: 4,
        },
        libc::iovec {
            iov_base: read_b.as_mut_ptr().cast(),
            iov_len: 4,
        },
    ];
    assert_eq!(unsafe { libc::readv(fd, read_parts.as_mut_ptr(), 2) }, 8);

    assert_eq!(
        unsafe { libc::pwrite(preexisting_fd, DATA.as_ptr().cast(), 8, 0) },
        8
    );
    assert_eq!(
        unsafe { libc::pread(preexisting_fd, buffer.as_mut_ptr().cast(), 8, 0) },
        8
    );

    let dup_fd = unsafe { libc::dup(fd) };
    assert!(dup_fd >= 0);
    let dup2_fd = unsafe { libc::dup2(fd, 1001) };
    assert_eq!(dup2_fd, 1001);
    let dup3_fd = unsafe { libc::dup3(fd, 1002, libc::O_CLOEXEC) };
    assert_eq!(dup3_fd, 1002);

    let known_fds: HashSet<u32> = [fd, openat2_fd, preexisting_fd, dup_fd, dup2_fd, dup3_fd]
        .into_iter()
        .map(|fd| fd as u32)
        .collect();
    for descriptor in [dup_fd, dup2_fd, dup3_fd, openat2_fd, fd, preexisting_fd] {
        assert_eq!(unsafe { libc::close(descriptor) }, 0);
    }

    // Detach immediately: reader_loop's final drain must preserve all records.
    drop(ebpf);
    shutdown_tx.send(true).unwrap();
    reader.await.unwrap().unwrap();
    let events = collector.await.unwrap();

    let pid = std::process::id();
    let opens = events
        .iter()
        .filter(|event| {
            matches!(event, BpfEvent::Open { pid: event_pid, path, .. }
                if *event_pid == pid && (path == "lifecycle.dat" || path == "openat2.dat"))
        })
        .count();
    assert_eq!(opens, 2);

    let mut read_ops = 0;
    let mut write_ops = 0;
    let mut read_bytes = 0;
    let mut write_bytes = 0;
    let mut dup_targets = HashSet::new();
    let mut closes = HashSet::new();
    for event in &events {
        match event {
            BpfEvent::Read {
                pid: event_pid,
                fd,
                bytes,
                latency_ns,
                emitted_ns,
                ..
            } if *event_pid == pid && known_fds.contains(fd) => {
                read_ops += 1;
                read_bytes += bytes;
                assert!(*latency_ns > 0 && *emitted_ns > 0);
            }
            BpfEvent::Write {
                pid: event_pid,
                fd,
                bytes,
                latency_ns,
                emitted_ns,
                ..
            } if *event_pid == pid && known_fds.contains(fd) => {
                write_ops += 1;
                write_bytes += bytes;
                assert!(*latency_ns > 0 && *emitted_ns > 0);
            }
            BpfEvent::Dup {
                pid: event_pid,
                old_fd,
                new_fd,
                ..
            } if *event_pid == pid && *old_fd == fd as u32 => {
                dup_targets.insert(*new_fd);
            }
            BpfEvent::Close {
                pid: event_pid, fd, ..
            } if *event_pid == pid && known_fds.contains(fd) => {
                closes.insert(*fd);
            }
            _ => {}
        }
    }
    assert_eq!((read_ops, read_bytes), (4, 32));
    assert_eq!((write_ops, write_bytes), (4, 32));
    assert_eq!(dup_targets, HashSet::from([dup_fd as u32, 1001, 1002]));
    assert_eq!(closes, known_fds);

    let kernel = bpf::capture_stats(&capture_stats).unwrap();
    let userspace = reader_drops.snapshot();
    assert_eq!(kernel.ring_output_drops, 0);
    assert_eq!(kernel.stash_update_failures, 0);
    assert_eq!(kernel.scratch_failures, 0);
    assert_eq!(userspace.parse_drops, 0);
    assert_eq!(userspace.queue_drops, 0);
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

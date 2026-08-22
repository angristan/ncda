#![cfg(target_os = "linux")]

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::process::Command;
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
    let leader_exit_helper = compile_leader_exit_helper(&fixture.root);
    let leader_exit_path = fixture.root.join("leader-exit.dat");
    let long_directory = fixture.root.join("a".repeat(180)).join("b".repeat(80));
    std::fs::create_dir_all(&long_directory).unwrap();
    let long_path = long_directory.join("long.dat");
    assert!(long_path.as_os_str().as_bytes().len() > ncda_common::MAX_FNAME_LEN);
    let invalid_path = fixture
        .root
        .join(std::ffi::OsString::from_vec(b"invalid-\xff.dat".to_vec()));
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
    let process_exit_hook = bpf::load_programs(&mut ebpf).unwrap();

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
    let attached = bpf::attach_programs(&mut ebpf, process_exit_hook).unwrap();

    let leader_child = Command::new(&leader_exit_helper)
        .arg(&leader_exit_path)
        .spawn()
        .unwrap();
    let leader_child_pid = leader_child.id();
    assert!(leader_child.wait_with_output().unwrap().status.success());

    let invalid_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&invalid_path)
        .unwrap();
    drop(invalid_file);

    let long_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&long_path)
        .unwrap();
    drop(long_file);

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
    assert_eq!(unsafe { libc::pwritev(fd, write_parts.as_ptr(), 2, 0) }, 8);
    assert_eq!(
        unsafe { libc::preadv(fd, read_parts.as_mut_ptr(), 2, 0) },
        8
    );
    assert_eq!(
        unsafe { libc::pwritev2(fd, write_parts.as_ptr(), 2, 0, 0) },
        8
    );
    assert_eq!(
        unsafe { libc::preadv2(fd, read_parts.as_mut_ptr(), 2, 0, 0) },
        8
    );

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
    let fcntl_dup_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 1003) };
    assert_eq!(fcntl_dup_fd, 1003);
    let cloexec_range_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 1004) };
    assert_eq!(cloexec_range_fd, 1004);

    assert_eq!(
        unsafe { libc::syscall(libc::SYS_close_range, fcntl_dup_fd, fcntl_dup_fd, 0) },
        0
    );
    const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_close_range,
                cloexec_range_fd,
                cloexec_range_fd,
                CLOSE_RANGE_CLOEXEC,
            )
        },
        0
    );

    let known_fds: HashSet<u32> = [
        fd,
        openat2_fd,
        preexisting_fd,
        dup_fd,
        dup2_fd,
        dup3_fd,
        fcntl_dup_fd,
        cloexec_range_fd,
    ]
    .into_iter()
    .map(|fd| fd as u32)
    .collect();
    for descriptor in [
        dup_fd,
        dup2_fd,
        dup3_fd,
        cloexec_range_fd,
        openat2_fd,
        fd,
        preexisting_fd,
    ] {
        assert_eq!(unsafe { libc::close(descriptor) }, 0);
    }

    // Detach immediately: reader_loop's final drain must preserve all records.
    attached.detach(&mut ebpf).unwrap();
    drop(ebpf);
    shutdown_tx.send(true).unwrap();
    reader.await.unwrap().unwrap();
    let events = collector.await.unwrap();

    let leader_path_bytes = leader_exit_path.as_os_str().as_bytes();
    let leader_open = events.iter().position(|event| {
        matches!(event, BpfEvent::Open { pid, path, .. }
            if *pid == leader_child_pid && path.as_slice() == leader_path_bytes)
    });
    let leader_open = leader_open.expect("surviving worker open was not captured");
    let leader_fd = match &events[leader_open] {
        BpfEvent::Open { fd, .. } => *fd,
        _ => unreachable!(),
    };
    let leader_write = events.iter().position(|event| {
        matches!(event, BpfEvent::Write { pid, fd, bytes, .. }
            if *pid == leader_child_pid && *fd == leader_fd && *bytes == DATA.len() as u64)
    });
    let leader_write = leader_write.expect("surviving worker write was not captured");
    let leader_exits = events
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            matches!(event, BpfEvent::ProcessExit { pid, .. } if *pid == leader_child_pid)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(leader_exits.len(), 1);
    assert!(leader_open < leader_write && leader_write < leader_exits[0]);

    let pid = std::process::id();
    assert!(events.iter().any(|event| {
        matches!(event, BpfEvent::Open { pid: event_pid, path, path_flags: 0, .. }
            if *event_pid == pid && path.as_slice() == invalid_path.as_os_str().as_bytes())
    }));
    assert!(events.iter().any(|event| {
        matches!(event, BpfEvent::Open { pid: event_pid, path, path_flags, .. }
            if *event_pid == pid
                && *path_flags == ncda_common::PATH_TRUNCATED
                && path.len() == ncda_common::MAX_FNAME_LEN
                && long_path.as_os_str().as_bytes().starts_with(path))
    }));

    let opens = events
        .iter()
        .filter(|event| {
            matches!(event, BpfEvent::Open { pid: event_pid, path, .. }
                if *event_pid == pid
                    && (path.as_slice() == b"lifecycle.dat" || path.as_slice() == b"openat2.dat"))
        })
        .count();
    assert_eq!(opens, 2);

    let mut read_ops = 0;
    let mut write_ops = 0;
    let mut read_bytes = 0;
    let mut write_bytes = 0;
    let mut dup_targets = HashSet::new();
    let mut closes = HashSet::new();
    let mut closed_ranges = HashSet::new();
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
            BpfEvent::CloseRange {
                pid: event_pid,
                first_fd,
                last_fd,
                flags,
                ..
            } if *event_pid == pid => {
                closed_ranges.insert((*first_fd, *last_fd, *flags));
            }
            _ => {}
        }
    }
    assert_eq!((read_ops, read_bytes), (6, 48));
    assert_eq!((write_ops, write_bytes), (6, 48));
    assert_eq!(
        dup_targets,
        HashSet::from([dup_fd as u32, 1001, 1002, 1003, 1004])
    );
    let expected_closes = known_fds
        .iter()
        .copied()
        .filter(|fd| *fd != fcntl_dup_fd as u32)
        .collect::<HashSet<_>>();
    assert_eq!(closes, expected_closes);
    assert!(closed_ranges.contains(&(1003, 1003, 0)));
    assert!(closed_ranges.contains(&(1004, 1004, CLOSE_RANGE_CLOEXEC)));

    let kernel = bpf::capture_stats(&capture_stats).unwrap();
    let userspace = reader_drops.snapshot();
    assert_eq!(kernel.ring_output_drops, 0);
    assert_eq!(kernel.stash_update_failures, 0);
    assert_eq!(kernel.scratch_failures, 0);
    assert_eq!(userspace.parse_drops, 0);
    assert_eq!(userspace.queue_drops, 0);
    assert_eq!(userspace.shutdown_discarded, 0);
}

fn compile_leader_exit_helper(root: &std::path::Path) -> PathBuf {
    let source = root.join("leader-exit.c");
    let binary = root.join("leader-exit");
    std::fs::write(
        &source,
        r#"#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

static void *worker(void *arg) {
    usleep(50000);
    int fd = open((const char *)arg, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) return (void *)1;
    if (write(fd, "ncda-io!", 8) != 8) return (void *)1;
    if (close(fd) != 0) return (void *)1;
    return 0;
}

int main(int argc, char **argv) {
    pthread_t thread;
    if (argc != 2 || pthread_create(&thread, 0, worker, argv[1]) != 0) return 1;
    pthread_exit(0);
}
"#,
    )
    .unwrap();
    let output = Command::new("cc")
        .args(["-O2", "-pthread"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "failed to compile leader-exit helper: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
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

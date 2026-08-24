# Benchmarking

`ncda-bench` runs a controlled file-I/O workload and writes a JSON report with throughput, event and byte recall, latency, capture counters, loss counters, and build metadata.

```bash
cargo build --release --locked --bin ncda-bench
sudo ./target/release/ncda-bench \
  --warmup-seconds 2 \
  --duration-seconds 30 \
  --threads 1 \
  --mode mixed \
  --block-size 4096 \
  --output ncda-benchmark.json
```

For comparable results:

1. Use an otherwise idle host.
2. Run read, write, and mixed modes separately.
3. Repeat each profile at least five times.
4. Reject runs with capture loss or recall below `1.0`.

Observed events are limited to the benchmark PID and measurement window. Kernel counters are system-wide deltas, so unrelated host activity can affect those counters without changing workload recall. Userspace loss counters include the final ring drain.

Latency sample storage is bounded at one million events.

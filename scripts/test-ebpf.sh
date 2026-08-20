#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

cargo test --locked --test ebpf_integration --no-run
binary=$(
  find target/debug/deps -maxdepth 1 -type f -name 'ebpf_integration-*' -perm -0100 \
    -printf '%T@ %p\n' \
    | sort -nr \
    | head -n1 \
    | cut -d' ' -f2-
)
if [[ -z "$binary" ]]; then
  echo "integration test binary not found" >&2
  exit 1
fi

exec sudo -n env -i \
  PATH=/usr/bin:/bin \
  RUST_BACKTRACE=1 \
  "$repo_root/$binary" \
  --ignored --nocapture --test-threads=1

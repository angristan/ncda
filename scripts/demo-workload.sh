#!/usr/bin/env bash
set -euo pipefail

readonly demo_root="${NCDA_DEMO_ROOT:-/tmp/ncda-demo}"
script_path=$(realpath "$0")
readonly script_path

reopen_source() {
    exec 3<&-
    exec 3<"$demo_root/source/events.bin"
}

run_worker() {
    local role=${1:?worker role required}
    local sequence=0
    local _read_chunk
    trap 'exit 0' INT TERM HUP

    exec 3<"$demo_root/source/events.bin"
    case "$role" in
        ingest)
            printf 'ncda-ingest' >"/proc/$$/comm"
            exec 4>"$demo_root/database/snapshot.db"
            exec 5>"$demo_root/logs/ingest.log"
            printf -v data_chunk '%32768s' ''
            while :; do
                IFS= read -r -N 32768 _read_chunk <&3 || reopen_source
                printf '%s' "$data_chunk" >&4
                printf 'event=%08d level=info component=ingest status=complete\n' "$sequence" >&5
                sequence=$((sequence + 1))
                sleep 0.02
            done
            ;;
        index)
            printf 'ncda-index' >"/proc/$$/comm"
            exec 4>"$demo_root/cache/index.bin"
            exec 5>"$demo_root/reports/summary.json"
            printf -v index_chunk '%8192s' ''
            while :; do
                IFS= read -r -N 16384 _read_chunk <&3 || reopen_source
                printf '%s' "$index_chunk" >&4
                printf '{"sequence":%d,"status":"indexed"}\n' "$sequence" >&5
                sequence=$((sequence + 1))
                sleep 0.03
            done
            ;;
        archive)
            printf 'ncda-archive' >"/proc/$$/comm"
            exec 4>"$demo_root/archive/segment.bin"
            exec 5>"$demo_root/queue/pending.log"
            printf -v archive_chunk '%4096s' ''
            while :; do
                IFS= read -r -N 8192 _read_chunk <&3 || reopen_source
                printf '%s' "$archive_chunk" >&4
                printf 'segment=%08d state=pending\n' "$sequence" >&5
                sequence=$((sequence + 1))
                sleep 0.04
            done
            ;;
        *)
            printf 'unknown worker role: %s\n' "$role" >&2
            return 2
            ;;
    esac
}

if [[ ${1:-} == worker ]]; then
    run_worker "${2:-}"
    exit
fi

if [[ -e $demo_root ]]; then
    printf 'refusing to replace existing demo path: %s\n' "$demo_root" >&2
    exit 1
fi

mkdir -p \
    "$demo_root/archive" \
    "$demo_root/cache" \
    "$demo_root/database" \
    "$demo_root/logs" \
    "$demo_root/queue" \
    "$demo_root/reports" \
    "$demo_root/source"
readonly ownership_marker="$demo_root/.ncda-demo-owned-$$"
printf '%s\n' "$$" >"$ownership_marker"
printf 'ncda-demo' >"/proc/$$/comm"
dd if=/dev/urandom of="$demo_root/source/events.bin" bs=1M count=32 status=none

worker_pids=()
start_worker() {
    NCDA_DEMO_ROOT="$demo_root" "$script_path" worker "$1" >/dev/null 2>&1 &
    worker_pids+=("$!")
}

cleanup() {
    trap - EXIT INT TERM HUP
    local pid
    for pid in "${worker_pids[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    for pid in "${worker_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    if [[ -f $ownership_marker ]] && [[ $(<"$ownership_marker") == "$$" ]]; then
        rm -f -- \
            "$demo_root/archive/segment.bin" \
            "$demo_root/cache/index.bin" \
            "$demo_root/database/snapshot.db" \
            "$demo_root/logs/ingest.log" \
            "$demo_root/queue/pending.log" \
            "$demo_root/reports/summary.json" \
            "$demo_root/source/events.bin" \
            "$ownership_marker"
        rmdir -- \
            "$demo_root/archive" \
            "$demo_root/cache" \
            "$demo_root/database" \
            "$demo_root/logs" \
            "$demo_root/queue" \
            "$demo_root/reports" \
            "$demo_root/source" \
            "$demo_root" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM HUP

start_worker ingest
start_worker index
start_worker archive
wait

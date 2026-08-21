#!/usr/bin/env bash
set -euo pipefail

readonly demo_root="${NCDA_DEMO_ROOT:-/tmp/ncda-demo}"
if [[ -e $demo_root ]]; then
    printf 'refusing to replace existing demo path: %s\n' "$demo_root" >&2
    exit 1
fi

mkdir -p \
    "$demo_root/cache" \
    "$demo_root/database" \
    "$demo_root/logs" \
    "$demo_root/reports" \
    "$demo_root/source"
readonly ownership_marker="$demo_root/.ncda-demo-owned-$$"
printf '%s\n' "$$" >"$ownership_marker"
printf 'ncda-demo\n' >"/proc/$$/comm"

dd if=/dev/urandom of="$demo_root/source/events.bin" bs=1M count=32 status=none

cleanup() {
    trap - EXIT INT TERM HUP
    exec 3>&- 4<&- 5>&- 6>&- 7>&- 2>/dev/null || true
    if [[ -f $ownership_marker ]] && [[ $(<"$ownership_marker") == "$$" ]]; then
        rm -f -- \
            "$demo_root/cache/index.bin" \
            "$demo_root/database/snapshot.db" \
            "$demo_root/logs/worker.log" \
            "$demo_root/reports/summary.json" \
            "$demo_root/source/events.bin" \
            "$ownership_marker"
        rmdir -- \
            "$demo_root/cache" \
            "$demo_root/database" \
            "$demo_root/logs" \
            "$demo_root/reports" \
            "$demo_root/source" \
            "$demo_root" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM HUP

exec 3>"$demo_root/database/snapshot.db"
exec 4<"$demo_root/source/events.bin"
exec 5>"$demo_root/cache/index.bin"
exec 6>"$demo_root/logs/worker.log"
exec 7>"$demo_root/reports/summary.json"

printf -v data_chunk '%32768s' ''
printf -v index_chunk '%8192s' ''
sequence=0
while :; do
    printf '%s' "$data_chunk" >&3
    if ! IFS= read -r -N 32768 _read_chunk <&4; then
        exec 4<&-
        exec 4<"$demo_root/source/events.bin"
    fi
    printf '%s' "$index_chunk" >&5
    printf 'event=%08d level=info component=ingest status=complete\n' "$sequence" >&6
    printf '{"sequence":%d,"status":"complete"}\n' "$sequence" >&7
    sequence=$((sequence + 1))
    sleep 0.02
done

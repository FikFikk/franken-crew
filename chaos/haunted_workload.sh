#!/usr/bin/env bash
set -euo pipefail

# Generator beban chaos terkendali di Linux cgroup v2 untuk menguji Sentinel + wa-bridge
# Penggunaan: ./chaos/haunted_workload.sh <memory_leak|memory_spike|fork_storm|zombie_storm|log_flood> [durasi_detik]

SCENARIO="${1:-memory_leak}"
DURATION="${2:-8}"
CGROUP_SLICE="${FRANKEN_CHAOS_SLICE:-franken.slice}"
UNIT_NAME="franken-chaos-workload.service"

# Pastikan tidak ada sisa proses chaos sebelum atau sesudah eksekusi skenario
cleanup() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "${UNIT_NAME}" >/dev/null 2>&1 || true
    systemctl reset-failed "${UNIT_NAME}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

run_in_cgroup() {
  local cmd_str="$1"
  if command -v systemd-run >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
    systemd-run --unit="${UNIT_NAME}" --slice="${CGROUP_SLICE}" --property=MemoryMax=256M --wait -- /usr/bin/env bash -c "${cmd_str}"
  else
    # Fallback bila dijalankan di container tanpa systemd PID 1 aktif
    /usr/bin/env bash -c "${cmd_str}"
  fi
}

case "${SCENARIO}" in
  memory_leak)
    echo "[workload] menyuntikkan memory_leak selama ${DURATION}s pada slice ${CGROUP_SLICE}"
    run_in_cgroup "python3 -c '
import time
chunks = []
deadline = time.time() + int(\"${DURATION}\")
while time.time() < deadline and len(chunks) < 96:
    chunks.append(bytearray(2 * 1024 * 1024))
    time.sleep(0.15)
'"
    ;;
  memory_spike)
    echo "[workload] menyuntikkan memory_spike selama ${DURATION}s pada slice ${CGROUP_SLICE}"
    run_in_cgroup "python3 -c '
import time
spike = bytearray(128 * 1024 * 1024)
for i in range(0, len(spike), 4096):
    spike[i] = 1
time.sleep(min(int(\"${DURATION}\"), 5))
del spike
'"
    ;;
  fork_storm)
    echo "[workload] menyuntikkan fork_storm terkendali selama ${DURATION}s (maks 24 worker)"
    run_in_cgroup "python3 -c '
import os, time
pids = []
try:
    for _ in range(24):
        pid = os.fork()
        if pid == 0:
            time.sleep(min(int(\"${DURATION}\"), 3))
            os._exit(0)
        pids.append(pid)
finally:
    for p in pids:
        try:
            os.waitpid(p, 0)
        except ChildProcessError:
            pass
'"
    ;;
  zombie_storm)
    echo "[workload] menyuntikkan zombie_storm selama ${DURATION}s agar zombie scanner memetakan PPID"
    run_in_cgroup "python3 -c '
import os, time
pids = []
for _ in range(12):
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    pids.append(pid)
time.sleep(min(int(\"${DURATION}\"), 4))
for p in pids:
    os.waitpid(p, 0)
'"
    ;;
  log_flood)
    echo "[workload] menyuntikkan log_flood dengan token uji sintetis untuk verifikasi redaksi journal"
    if command -v logger >/dev/null 2>&1; then
      for i in $(seq 1 40); do
        logger -t franken-chaos-api "ERROR ENOMEM cycle=${i} Authorization: Bearer chaosTestSecretToken123456 postgres://app:chaosPass@10.20.30.40:5432/db"
      done
    else
      for i in $(seq 1 40); do
        printf 'ERROR ENOMEM cycle=%s Authorization: Bearer chaosTestSecretToken123456\n' "${i}" >&2
      done
    fi
    ;;
  *)
    echo "skenario tidak dikenal: ${SCENARIO}" >&2
    exit 2
    ;;
esac


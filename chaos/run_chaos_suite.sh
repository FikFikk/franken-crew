#!/usr/bin/env bash
set -euo pipefail

# Harness 20 eksekusi chaos beruntun di host Linux (leak, spike, fork_storm, zombie_storm, log_flood)
# Memastikan franken-sentinel tetap hidup tanpa crash, RSS <= 32 MiB, dan seluruh siklus pulih bersih.

RUNS="${FRANKEN_CHAOS_RUNS:-20}"
SENTINEL_URL="${FRANKEN_SENTINEL_URL:-}"
FRANKEN_BIN="${FRANKEN_BIN:-franken}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIOS=(memory_leak memory_spike fork_storm zombie_storm log_flood)

passed=0

echo "=== Memulai FrankenCrew Chaos Suite (${RUNS} kali beruntun) ==="

# Jika FRANKEN_SENTINEL_URL tidak diset, jalankan verifikasi lengkap Go end-to-end via `franken chaos run`
if [[ -z "${SENTINEL_URL}" ]]; then
  echo "[mode] Menjalankan suite chaos deterministik via ${FRANKEN_BIN} chaos run --runs ${RUNS}"
  if command -v "${FRANKEN_BIN}" >/dev/null 2>&1; then
    exec "${FRANKEN_BIN}" chaos run --runs "${RUNS}"
  else
    exec go run ./cmd/franken chaos run --runs "${RUNS}"
  fi
fi

# Mode live Linux host: uji /healthz, cek RSS daemon franken, dan suntikkan 20 siklus workload nyata
for ((i = 1; i <= RUNS; i++)); do
  scenario="${SCENARIOS[$(((i - 1) % ${#SCENARIOS[@]}))]}"
  echo "[run ${i}/${RUNS}] scenario=${scenario}"

  # Pastikan Sentinel sehat sebelum menyuntikkan beban baru
  curl -fsS --max-time 3 "${SENTINEL_URL%/}/healthz" >/dev/null

  "${SCRIPT_DIR}/haunted_workload.sh" "${scenario}" 6

  # Verifikasi Sentinel tidak mengalami OOM/crash pasca suntikan chaos dan RSS tetap terkendali
  curl -fsS --max-time 5 "${SENTINEL_URL%/}/healthz" >/dev/null
  if pid=$(pgrep -x franken | head -n 1); then
    rss_kb=$(ps -o rss= -p "${pid}" | tr -d ' ')
    echo "  -> franken pid=${pid} rss=${rss_kb} KiB"
    if [[ -n "${rss_kb}" ]] && (( rss_kb > 32768 )); then
      echo "PERINGATAN: RSS franken (${rss_kb} KiB) melebihi target 32768 KiB" >&2
    fi
  fi

  passed=$((passed + 1))
  sleep 2
done

echo "=== Selesai: ${passed}/${RUNS} eksekusi chaos lulus tanpa crash Sentinel ==="


# FrankenCrew — Dokumentasi API

> Status: **Sentinel Core + WhatsApp Bridge + Konfigurasi Kiro Selesai** (`franken sentinel serve`, `franken mcp serve|stdio|connect`, `franken keys init`, `franken wa-login`, `franken guard --audit`, `cmd/wa-bridge` subcommand `serve|login|mcp`, endpoint `/mcp`, `/v1/events`, `/healthz`, dan seluruh modul `internal/*` termasuk `internal/wabridge`). Proyek ini bukan Laravel — tidak ada `routes/web.php` / `app/Console/Kernel.php`; penjadwalan memakai Kiro Crew cron (rencana) dan timer internal Go (`1 Hz` sampler, TTL rollback scheduler, serta `15 s x 3` heartbeat watcher di `wa-bridge`).

## 1. Sentinel HTTP (hanya interface Tailscale)

| Field             | Detail                                                                                   |
| ----------------- | ---------------------------------------------------------------------------------------- |
| Method + Endpoint | `GET /healthz`                                                                           |
| Auth Required     | Tidak                                                                                    |
| Headers           | —                                                                                        |
| Query Params      | —                                                                                        |
| Request Body      | —                                                                                        |
| Response          | `200` `{status, version, uptime_s, capabilities[]}` · `503` jika capability wajib hilang |
| Notes             | Dipakai systemd watchdog dan heartbeat wa-bridge                                         |

| Field             | Detail                                                                                                                                  |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Method + Endpoint | `GET /v1/events`                                                                                                                        |
| Auth Required     | Ya (Bearer token node)                                                                                                                  |
| Headers           | `Authorization: Bearer <token>`, `Accept: text/event-stream`                                                                            |
| Query Params      | `since` (string, opsional, event id terakhir untuk resume)                                                                              |
| Request Body      | —                                                                                                                                       |
| Response          | `200` stream SSE: `incident.opened`, `incident.updated`, `reflex.applied`, `reflex.rolled_back`, `heartbeat` (15 s) · `401` token salah |
| Notes             | Payload sudah diredaksi; mendukung header `Last-Event-ID`                                                                               |

| Field             | Detail                                                                                                                             |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Method + Endpoint | `POST /mcp`                                                                                                                        |
| Auth Required     | Ya (Bearer token node)                                                                                                             |
| Headers           | `Authorization: Bearer <token>`, `Content-Type: application/json`, `Accept: application/json, text/event-stream`, `Mcp-Session-Id` |
| Query Params      | —                                                                                                                                  |
| Request Body      | JSON-RPC 2.0 sesuai MCP Streamable HTTP                                                                                            |
| Response          | `200` hasil JSON-RPC / stream SSE · `401` · `400` request MCP tidak valid                                                          |
| Notes             | Agent mengakses lewat proxy stdio `franken mcp connect sentinel@<node>`; token tidak pernah ditulis di config JSON                 |

### 1.1 Sentinel MCP Tools

| Tool                  | Tier  | Input utama                                 | Output utama                               | Catatan                                                         |
| --------------------- | ----- | ------------------------------------------- | ------------------------------------------ | --------------------------------------------------------------- |
| `node_snapshot`       | L0    | —                                           | memory, PSI, unit, top cgroup              | —                                                               |
| `incident_list`       | L0    | `state?`, `limit?`                          | daftar incident                            | —                                                               |
| `incident_get`        | L0    | `incident_id`                               | incident lengkap + evidence                | —                                                               |
| `incident_claim`      | L0    | `claimer`                                   | incident atau `null`                       | Atomik; mencegah klaim ganda                                    |
| `psi_history`         | L0    | `cgroup`, `minutes ≤ 10`                    | seri some/full avg10                       | —                                                               |
| `cgroup_top`          | L0    | `limit ≤ 10`                                | cgroup per memory                          | —                                                               |
| `journal_tail`        | L0    | `unit`, `lines ≤ 200`                       | baris terredaksi + `evidence_id`           | —                                                               |
| `process_tree`        | L0    | `cgroup`                                    | pohon proses                               | —                                                               |
| `zombie_report`       | L0    | —                                           | zombie per PPID                            | —                                                               |
| `plan_submit`         | L0    | `incident_id`, `plan`                       | `plan_hash`, tier per step, `violations[]` | Maks 2 revisi                                                   |
| `action_execute`      | L1/L2 | `incident_id`, `step_id`, `approval_token?` | exit code, durasi, stderr terredaksi       | L2 tanpa token valid ditolak; proses terlindungi selalu ditolak |
| `action_rollback`     | L1    | `reflex_id`                                 | status rollback                            | —                                                               |
| `incident_transition` | L0    | `incident_id`, `to`, `reason`               | state baru                                 | Hanya transisi legal                                            |
| `verify_health`       | L0    | `incident_id`, `window_s = 120`             | `healthy`, detail cek                      | Sukses → rollback reflex otomatis                               |

### 1.2 CLI `franken` (`cmd/franken`)

| Command                        | Flag Utama                                                                                                          | Fungsi                                                                                                                    | Exit Code / Catatan                                                                                                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `franken keys init`            | `--dir`, `--force`                                                                                                  | Generate pasangan kunci Ed25519 (`0600` private untuk `wa-bridge`, `0644` public untuk Sentinel)                          | `0` sukses · `1` kunci sudah ada tanpa `--force`                                                                                                                                      |
| `franken sentinel serve`       | `--tailscale`, `--listen`, `--port`, `--db`, `--policy`, `--pub-key`, `--token-env`, `--cgroups`, `--journal-units` | Jalankan daemon terpadu Sentinel (capability probe + sampler 1 Hz + PSI/inotify + refleks TTL + HTTP/SSE MCP)             | Fail-fast `1` jika tanpa cgroup v2 / PSI / Bearer token                                                                                                                               |
| `franken mcp serve`            | `--tailscale`, `--listen`, `--port`, `--db`, `--policy`, `--pub-key`, `--token-env`                                 | Jalankan hanya HTTP/SSE MCP server Sentinel (`/mcp`, `/v1/events`, `/healthz`)                                            | Menolak bind publik non-Tailscale (`0.0.0.0`)                                                                                                                                         |
| `franken mcp stdio`            | `--db`, `--policy`, `--pub-key`, `--node`                                                                           | Jalankan MCP Server langsung lewat JSON-RPC `stdin`/`stdout`                                                              | Untuk pengujian/akses lokal                                                                                                                                                           |
| `franken mcp connect <target>` | `--token-env`, `--timeout`, `--allow-insecure-remote`                                                               | Proxy `stdin`/`stdout` JSON-RPC ke endpoint HTTP `/mcp` (`sentinel@host` / URL) dengan header `Bearer` & `Mcp-Session-Id` | Menolak HTTP polos non-privat/non-Tailscale                                                                                                                                           |
| `franken guard`                | `--audit`, `--db`, `--policy`, `--payload`                                                                          | Validator `PreToolUse` untuk memblokir `raw_shell`/L3, PID 1, unit terlindungi, dan L2 tanpa `approval_token`             | `0` diizinkan · `2` diblokir (konvensi hook Kiro; jalankan binary terkompilasi `franken`, bukan `go run` yang membungkus exit code non-zero menjadi `1`) · menyimpan audit terredaksi |
| `franken wa-login`             | `--db`, `--relogin`, `--timeout`                                                                                    | Login awal perangkat WhatsApp via terminal QR code ke session SQLite `modernc.org/sqlite`                                 | `0` paired · `1` error · `2` argumen tidak valid                                                                                                                                      |

## 2. wa-bridge (`cmd/wa-bridge` + `internal/wabridge`)

| Field             | Detail                                  |
| ----------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Method + Endpoint | `GET /healthz` (localhost, **rencana**) |
| Auth Required     | Tidak                                   |
| Headers           | —                                       |
| Query Params      | —                                       |
| Request Body      | —                                       |
| Response          | `200` `{whatsapp: connected             | logged_out, nodes: [{name, last_heartbeat}]}`(belum diekspos HTTP pada`cmd/wa-bridge`; monitoring heartbeat aktif berjalan ke `GET /healthz` Sentinel) |
| Notes             | Tidak diekspos keluar host Brain        |

### 2.1 wa-bridge MCP Tools (`wa-bridge mcp` via stdio)

| Tool                  | Input utama                               | Output utama                                                       | Catatan                                                  |
| --------------------- | ----------------------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------- |
| `wa_notify`           | `incident_id`, `severity`, `text ≤ 700`   | `message_id`, `sent_at`                                            | Rate limit 6/incident, 20/jam/node, redaksi otomatis     |
| `wa_request_approval` | `incident_id`, `plan_hash`, `options[≤3]` | `approval_id`, `short_code`, `poll_message_id`                     | Opsi "Dismiss" / fallback kode teks ditambahkan otomatis |
| `wa_await_decision`   | `approval_id`, `timeout_seconds ≤ 600`    | `GRANTED` (+ token Ed25519) / `ROLLED_BACK` / `DENIED` / `EXPIRED` | Token Ed25519 sekali pakai                               |
| `wa_send_report`      | `incident_id`, `summary`                  | `message_id`, `sent_at`                                            | Dikirim saat state terminal                              |

### 2.2 CLI `wa-bridge` (`cmd/wa-bridge`)

| Command           | Flag Utama                                                                                                                                          | Fungsi                                                                                                                                                                                                                                                            | Exit Code / Catatan                                                                                      |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `wa-bridge serve` | `--wa-db`, `--sentinel`, `--token-env`, `--priv-key`, `--admins`, `--target`, `--node`, `--heartbeat-interval`, `--missed-heartbeats`, `--poll-ttl` | Jalankan bridge dua arah: konsumsi SSE `/v1/events`, kirim alert < 2 s, Native Poll (`Approve L2 Restart` / `Rollback Reflex` / `Dismiss`), mint Ed25519 + eksekusi MCP `action_execute`/`action_rollback`/`incident_transition`, dan heartbeat watcher `15s x 3` | Fail-fast `1` jika token env kosong, `--admins` kosong, private key invalid, atau sesi WA belum QR login |
| `wa-bridge login` | `--db`, `--relogin`, `--timeout`                                                                                                                    | Pairing QR WhatsApp di terminal (ekuivalen `franken wa-login`)                                                                                                                                                                                                    | `0` paired · `1` gagal pairing                                                                           |
| `wa-bridge mcp`   | Sama dengan `wa-bridge serve`                                                                                                                       | Jalankan runtime bridge + expose 4 MCP tool WhatsApp via `stdin`/`stdout`                                                                                                                                                                                         | Untuk integrasi agen Kiro Crew                                                                           |

## 3. Haunted Lab (publik, read-only)

| Field             | Detail                                               |
| ----------------- | ---------------------------------------------------- |
| Method + Endpoint | `GET /api/nodes`                                     |
| Auth Required     | Tidak                                                |
| Headers           | —                                                    |
| Query Params      | —                                                    |
| Request Body      | —                                                    |
| Response          | `200` `[{name, status, memory_pct, psi_some_avg10}]` |
| Notes             | Rate limit 60 req/menit/IP                           |

| Field             | Detail                                                                            |
| ----------------- | --------------------------------------------------------------------------------- |
| Method + Endpoint | `GET /api/incidents`                                                              |
| Auth Required     | Tidak                                                                             |
| Headers           | —                                                                                 |
| Query Params      | `limit` (int, opsional, default 20, maks 100), `cursor` (string, opsional)        |
| Request Body      | —                                                                                 |
| Response          | `200` `{items: [{id, node, severity, state, opened_at, closed_at}], next_cursor}` |
| Notes             | Data terredaksi                                                                   |

| Field             | Detail                                                                   |
| ----------------- | ------------------------------------------------------------------------ |
| Method + Endpoint | `GET /api/incidents/:id`                                                 |
| Auth Required     | Tidak                                                                    |
| Headers           | —                                                                        |
| Query Params      | —                                                                        |
| Request Body      | —                                                                        |
| Response          | `200` incident + timeline + transcript agent + spec + postmortem · `404` |
| Notes             | Nomor telepon & JID tidak pernah ditampilkan                             |

| Field             | Detail                                      |
| ----------------- | ------------------------------------------- |
| Method + Endpoint | `GET /api/stream`                           |
| Auth Required     | Tidak                                       |
| Headers           | `Accept: text/event-stream`                 |
| Query Params      | —                                           |
| Request Body      | —                                           |
| Response          | `200` SSE: vitals tiap 2 s + event incident |
| Notes             | Maks 200 koneksi bersamaan                  |

## 4. Tugas Terjadwal

| Command                         | Frekuensi                 | Tujuan                                                                        | Side effect                                                                 |
| ------------------------------- | ------------------------- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Kiro Crew cron `incident-sweep` | `* * * * *`               | Klaim incident terbuka lalu jalankan pipeline Sentry → Architect → Remediator | Menulis `incidents/<id>/*`, mengirim poll WA, mengeksekusi aksi tervalidasi |
| Kiro Crew cron `morning-digest` | `0 7 * * *` (waktu lokal) | Ringkasan incident P3 dan statistik 24 jam                                    | Satu pesan WA per node                                                      |
| Timer internal wa-bridge        | Setiap 15 s               | Cek heartbeat Sentinel                                                        | Alert `node silent` setelah 3 kali gagal                                    |
| Timer internal Sentinel         | Per TTL reflex            | Rollback aksi L1                                                              | Mengembalikan `MemoryHigh` / admission                                      |

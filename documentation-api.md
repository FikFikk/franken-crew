# FrankenCrew — Dokumentasi API

> Status: **Sentinel Core + WhatsApp Bridge + Konfigurasi Kiro V3 / Crew Manifest Selesai** (`franken sentinel serve`, `franken mcp serve|stdio|connect`, `franken keys init`, `franken wa-login`, `franken guard --audit`, `cmd/wa-bridge` subcommand `serve|login|mcp`, endpoint `/mcp`, `/v1/events`, `/healthz`, manifest `app.json`, dan seluruh modul `internal/*` termasuk `internal/wabridge`). Proyek ini bukan Laravel — tidak ada `routes/web.php` / `app/Console/Kernel.php`; penjadwalan memakai cron resmi Kiro Crew pada `app.json` (`incident-sweep` & `morning-digest`) serta timer internal Go (`1 Hz` sampler, TTL rollback scheduler, serta `15 s x 3` heartbeat watcher di `wa-bridge`).

## 1. Sentinel HTTP (hanya interface Tailscale)

| Field             | Detail                                                                                   |
| ----------------- | ---------------------------------------------------------------------------------------- |
| Method + Endpoint | `GET /healthz`                                                                           |
| Auth Required     | Tidak                                                                                    |
| Headers           | —                                                                                        |
| Query Params      | —                                                                                        |
| Request Body      | —                                                                                        |
| Response          | `200` `{status, node, version, uptime_s, capabilities[]}` · `503` jika capability wajib hilang |
| Notes             | Dipakai systemd watchdog dan heartbeat wa-bridge                                         |

| Field             | Detail                                                                                                                                  |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Method + Endpoint | `GET /v1/events`                                                                                                                        |
| Auth Required     | Ya (Bearer token node)                                                                                                                  |
| Headers           | `Authorization: Bearer <token>`, `Accept: text/event-stream`                                                                            |
| Query Params      | `since` (string, opsional, event id terakhir untuk resume)                                                                              |
| Request Body      | —                                                                                                                                       |
| Response          | `200` stream SSE: `incident.opened`, `incident.updated`, `reflex.applied`, `reflex.rolled_back`, `heartbeat` (15 s) · `401` token salah |
| Notes             | Payload (summary, map, dan slice bersarang) sudah diredaksi (`sk-...`, `08xx`/`+628xx` tanpa menyensor metrik numerik); mendukung header `Last-Event-ID` & auto-reset kursor bila `sinceID > nextID` pasca-restart Sentinel |

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
| `journal_tail`        | L0    | `unit`, `lines ≤ 200`                       | baris terredaksi + `evidence_id`           | `RawData` & `RedactedData` SQLite terredaksi sebelum persistensi (`sk-...`, `08xx`/`+628xx`); event journal hanya menempel ke insiden unit terkait |
| `process_tree`        | L0    | `cgroup`                                    | pohon proses                               | Menandai `protected: true` via inspeksi `/proc/<pid>/{stat,cmdline}` |
| `zombie_report`       | L0    | —                                           | zombie per PPID                            | —                                                               |
| `plan_submit`         | L0    | `incident_id`, `plan`                       | `plan_hash`, tier per step, `violations[]` | Maks 2 revisi                                                   |
| `action_execute`      | L1/L2 | `incident_id`, `step_id`, `approval_token?` | exit code, durasi, stderr terredaksi       | L2 tanpa token valid ditolak; PM2 via `systemd-run`; `process_terminate` eskalasi `SIGTERM` → `SIGKILL`; proses terlindungi (`sshd`, `systemd-journald`, `tailscaled`, Sentinel, kernel thread, PID 1) ditolak |
| `action_rollback`     | L1    | `reflex_id`                                 | status rollback                            | Retry exponential backoff sebelum terminal `FAILED_ROLLBACK`; unset `CPUQuota` di-reset ke `CPUQuota=` |
| `incident_transition` | L0    | `incident_id`, `to`, `reason`               | state baru                                 | Transisi atomik satu transaksi SQL (`WHERE id = ? AND state = ?`) |
| `verify_health`       | L0    | `incident_id`, `window_seconds = 120`, `require_window_coverage?`, `auto_transition?` | `status` (`PENDING_VERIFICATION` / `RESOLVED` / `FAILED`), `healthy`, `checks`, `rolled_back_reflexes` | Observasi forward ke depan via background worker; `PENDING_VERIFICATION` selama jendela berjalan; lulus → rollback refleks + opsional `RESOLVED`; gagal + `auto_transition` → rollback refleks + `ESCALATED` |
| `postmortem_generate` | L0    | `incident_id`, `author?`, `notes?`                                                  | `file_path`, `state`, `markdown` terdiredaksi                            | Menulis berkas aman ke `incidents/<incident_id>/postmortem.md` & mencatat audit `POSTMORTEM_GENERATED`    |

### 1.2 CLI `franken` (`cmd/franken`)

| Command                        | Flag Utama                                                                                                          | Fungsi                                                                                                                    | Exit Code / Catatan                                                                                                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `franken keys init`            | `--dir`, `--force`                                                                                                  | Generate pasangan kunci Ed25519 (`0600` private untuk `wa-bridge`, `0644` public untuk Sentinel)                          | `0` sukses · `1` kunci sudah ada tanpa `--force`                                                                                                                                      |
| `franken sentinel serve`       | `--tailscale`, `--listen`, `--port`, `--db`, `--policy`, `--pub-key`, `--token-env`, `--cgroups`, `--journal-units` | Jalankan daemon terpadu Sentinel (capability probe + sampler 1 Hz + PSI/inotify + refleks TTL + HTTP/SSE MCP)             | Fail-fast `1` jika `--pub-key` (`sentinel-ed25519.pub`) gagal dimuat, tanpa cgroup v2/PSI, atau tanpa Bearer token        |
| `franken mcp serve`            | `--tailscale`, `--listen`, `--port`, `--db`, `--policy`, `--pub-key`, `--token-env`                                 | Jalankan hanya HTTP/SSE MCP server Sentinel (`/mcp`, `/v1/events`, `/healthz`)                                            | Menolak bind publik non-Tailscale (`0.0.0.0`) & fail-fast `1` jika `--pub-key` gagal dimuat                             |
| `franken mcp stdio`            | `--db`, `--policy`, `--pub-key`, `--node`                                                                           | Jalankan MCP Server langsung lewat JSON-RPC `stdin`/`stdout`                                                              | Fail-fast `1` jika `--pub-key` gagal dimuat                                                                              |
| `franken mcp connect <target>` | `--token-env`, `--timeout`, `--allow-insecure-remote`                                                               | Proxy `stdin`/`stdout` JSON-RPC ke endpoint HTTP `/mcp` (`sentinel@host` / URL) dengan header `Bearer` & `Mcp-Session-Id` | Menolak HTTP polos non-privat/non-Tailscale                                                                                                                                           |
| `franken guard`                | `--audit`, `--db`, `--policy`, `--payload`                                                                          | Validator `PreToolUse` untuk memblokir `raw_shell`/L3, PID terlindungi, unit terlindungi, dan L2 tanpa `approval_token`; mendukung format tool MCP Kiro V3 (`mcp_<server>_<tool>` dan `@<server>/<tool>`) | `0` diizinkan · `2` diblokir (dibatasi pada matcher regex MCP `.kiro/hooks/preToolUse.json` agar tidak memblokir `execute_bash` secara global) |
| `franken wa-login`             | `--db`, `--relogin`, `--timeout` (default `3m`)                                                                     | Login awal perangkat WhatsApp via terminal QR code + menunggu reconnect `515` & upload prekeys ke SQLite `modernc.org/sqlite` | `0` paired · `1` error · `2` argumen tidak valid                                                                                                                                      |
| `franken postmortem`           | `--db`, `--incident`, `--out`, `--author`, `--notes`                                                                | Generate laporan markdown postmortem terredaksi dari SQLite Sentinel                                                      | `0` tersimpan · `1` gagal · `2` argumen tidak valid                                                                                                                                   |
| `franken chaos run`            | `--runs`, `--policy`, `--out`, `--node`, `--approver`                                                               | Jalankan 20 siklus chaos (`memory_leak`, `memory_spike`, `fork_storm`, `zombie_storm`, `log_flood`) end-to-end            | `0` seluruh siklus lulus `RESOLVED` · `1` ada kegagalan                                                                                                                               |
| `franken lab simulate` | `--out`, `--policy` | Jalankan tiga skenario (heap leak, prompt injection, zombie storm) lewat detector, refleks, policy, verifier Ed25519, worker verifikasi, dan generator postmortem asli terhadap cgroup in-memory, lalu tulis replay `frankencrew.replay/v1` | `0` tersimpan · `1` gagal · `2` argumen tidak valid |
| `franken lab export` | `--db`, `--out`, `--incident` (bisa diulang), `--source-kind` (`recording`/`simulation`), `--source-label`, `--node` | Ekspor incident yang sudah selesai dari SQLite Sentinel menjadi replay terredaksi untuk Graveyard | `0` tersimpan · `1` gagal · `2` argumen tidak valid |
| `franken lab serve` | `--listen` (default `127.0.0.1:3008`), `--data-dir`, `--sentinel`, `--token-env` | Sajikan landing page dan Graveyard read-only dari aset yang di-embed (lihat bagian 3) | `0` berhenti normal · `1` gagal · `2` argumen tidak valid |

## 2. wa-bridge (`cmd/wa-bridge` + `internal/wabridge`)

| Field             | Detail                                                                                   |
| ----------------- | ---------------------------------------------------------------------------------------- |
| Method + Endpoint | `GET /healthz` (localhost, aktif saat `--mcp-listen` terpasang)                          |
| Auth Required     | Tidak                                                                                    |
| Headers           | —                                                                                        |
| Query Params      | —                                                                                        |
| Request Body      | —                                                                                        |
| Response          | `200` `{status: "ok", node}` (`node` sinkron otomatis dari `/healthz` Sentinel & SSE)    |
| Notes             | Hanya mendengarkan localhost (`127.0.0.1` / `::1`) untuk proxy `wa-bridge mcp`           |

### 2.1 wa-bridge MCP Tools (`wa-bridge mcp` via stdio)

| Tool                  | Input utama                               | Output utama                                                       | Catatan                                                  |
| --------------------- | ----------------------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------- |
| `wa_notify`           | `incident_id`, `severity`, `text ≤ 700`   | `message_id`, `sent_at`                                            | Rate limit 6/incident, 20/jam/node, redaksi otomatis     |
| `wa_request_approval` | `incident_id`, `plan_hash`, `options[≤3]` | `approval_id`, `short_code`, `poll_message_id`                     | Opsi "Dismiss" / fallback kode teks ditambahkan otomatis |
| `wa_await_decision`   | `approval_id`, `timeout_seconds ≤ 600`    | `GRANTED` (+ `step_tokens[]`: satu token Ed25519 per langkah `{step_id, action, token}`) / `ROLLED_BACK` / `DENIED` / `EXPIRED` | Tiap token sekali pakai dan hanya sah untuk langkahnya sendiri; `token` = token langkah pertama (kompatibilitas) |
| `wa_send_report`      | `incident_id`, `summary`                  | `message_id`, `sent_at`                                            | Dikirim saat state terminal                              |

### 2.2 CLI `wa-bridge` (`cmd/wa-bridge`)

| Command           | Flag Utama                                                                                                                                          | Fungsi                                                                                                                                                                                                                                                            | Exit Code / Catatan                                                                                      |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `wa-bridge serve` | `--wa-db`, `--sentinel`, `--token-env`, `--priv-key`, `--admins`, `--target`, `--node` (default kosong = auto-detect dari `/healthz` Sentinel / hostname), `--heartbeat-interval`, `--missed-heartbeats`, `--poll-ttl`, `--mcp-listen`, `--crew-webhook-url` (env `FRANKEN_CREW_WEBHOOK_URL`), `--crew-token-env` (default `KIROCREW_TOKEN`), `--crew-agent` | Pemilik tunggal sesi WA: konsumsi SSE `/v1/events`, alert < 2 s, picu fase Crew (`TRIAGE`, `EXECUTE`), Native Poll yang labelnya dibangun dari plan tersimpan, mint satu token Ed25519 per langkah, laporan akhir saat `verification.completed`, heartbeat watcher `15s x 3` | Fail-fast `1` jika token env kosong, `--admins` kosong, private key invalid, sesi WA belum QR login, atau webhook Crew diset tanpa token / ke HTTP publik |
| `wa-bridge login` | `--db`, `--relogin`, `--timeout` (default `3m`)                                                                                                     | Pairing QR WhatsApp di terminal & sinkronisasi pasca-515 (ekuivalen `franken wa-login`)                                                                                                                                                                           | `0` paired · `1` gagal pairing                                                                           |
| `wa-bridge mcp`   | Sama dengan `wa-bridge serve`                                                                                                                       | Jalankan runtime bridge + expose 4 MCP tool WhatsApp via `stdin`/`stdout`                                                                                                                                                                                         | Untuk integrasi agen Kiro Crew                                                                           |

## 3. Graveyard Dashboard (`franken lab serve`, publik, read-only)

Server read-only untuk landing page dan replay incident. Semua route hanya menerima `GET`/`HEAD`; method lain dijawab `405` dengan `Allow: GET, HEAD`. Setiap respons membawa `Content-Security-Policy` ketat (`default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; ...`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, dan `Cross-Origin-Opener-Policy: same-origin`. Path dengan traversal, slash ter-encode, atau segmen kosong dijawab `404`.

| Field             | Detail                                                                                                     |
| ----------------- | ---------------------------------------------------------------------------------------------------------- |
| Method + Endpoint | `GET /`                                                                                                    |
| Auth Required     | Tidak                                                                                                      |
| Response          | `200` `text/html` landing page (`ui/index.html`), `Cache-Control: no-cache`                                |
| Notes             | Hanya `/` yang melayani halaman; `/index.html` sengaja `404`                                               |

| Field             | Detail                                                                                                     |
| ----------------- | ---------------------------------------------------------------------------------------------------------- |
| Method + Endpoint | `GET /dist/*`, `GET /assets/*`                                                                             |
| Auth Required     | Tidak                                                                                                      |
| Response          | `200` modul ES (`text/javascript`), CSS, dan SVG dari aset yang di-embed, `Cache-Control: public, max-age=300` |
| Notes             | `ui/dist/index.mjs` juga menjadi `ui.entry` aplikasi Kiro Crew (default export komponen React + `mount()`) |

| Field             | Detail                                                                                                     |
| ----------------- | ---------------------------------------------------------------------------------------------------------- |
| Method + Endpoint | `GET /data/*`                                                                                              |
| Auth Required     | Tidak                                                                                                      |
| Response          | `200` berkas dari `--data-dir` (dibuka lewat `os.Root`, symlink tidak bisa keluar direktori), fallback ke `ui/data/` bawaan, `Cache-Control: no-cache` |
| Notes             | `*.json` membawa `Access-Control-Allow-Origin: *`; `replay.json` mengikuti skema `frankencrew.replay/v1` di bawah |

| Field             | Detail                                                                                                     |
| ----------------- | ---------------------------------------------------------------------------------------------------------- |
| Method + Endpoint | `GET /api/status`                                                                                          |
| Auth Required     | Tidak                                                                                                      |
| Response          | `200` JSON. Tanpa `--sentinel`: `{"mode":"replay"}`. Sentinel terjangkau: `{mode:"live", node, uptime_s, psi:{some_avg10, full_avg10}, memory_used_pct, open_incidents, latest:{id, severity, state, opened_at}, updated_at}`. Sentinel tidak terjangkau: `{mode:"offline", updated_at}` |
| Notes             | `Access-Control-Allow-Origin: *`; `open_incidents` hanya menghitung 5 incident terbaru; proses lab memegang Bearer token Sentinel dari `--token-env` |

| Field             | Detail                                                                                                     |
| ----------------- | ---------------------------------------------------------------------------------------------------------- |
| Method + Endpoint | `GET /healthz`                                                                                             |
| Auth Required     | Tidak                                                                                                      |
| Response          | `200` `ok` (`text/plain`)                                                                                  |

**Skema replay `frankencrew.replay/v1`:**

- Root: `schema`, `generated_at`, `source{kind: simulation|recording, label, detail}`, `node`, `incidents[]`.
- Incident: `id`, `title`, `scenario`, `severity`, `class`, `confidence`, `triage_summary`, `cgroup`, `unit`, `state`, `opened_at`, `closed_at`, `duration_s`, `tto_seconds`, `reflex_latency_ms`, `reflex_trigger`, `plan_hash`, `root_cause`, `follow_ups[]`, `stats{reflexes, l2_steps, blocked, verify_window_s}`, `series{limit_bytes, points[[t_s, memory_bytes, psi_some, psi_full]]}`, `events[]`, `poll`, `messages[]`, `postmortem_markdown`.
- Event: `t` (detik relatif terhadap saat incident dibuka), `at`, `lane` (`kernel|sentinel|crew|human|verify`), `actor`, `kind`, `title`, `detail`, `level` (`info|ok|warn|error`), `inferred` (`true` = direkonstruksi dari protokol conductor/remediator, bukan event yang tercatat di Sentinel).
- Poll: `t`, `title`, `options[]`, `chosen`, `voted_t`, `approver`. Message: `t`, `from` (`bot|operator`), `kind` (`alert|poll|vote|text|report`), `text` (markup WhatsApp `*bold*` dan `` `code` ``).

Catatan: rancangan awal endpoint `/api/nodes`, `/api/incidents`, `/api/incidents/:id`, dan `/api/stream` tidak diimplementasikan. Replay JSON statis menggantikannya, sehingga pengunjung publik tidak pernah berbicara langsung dengan Sentinel.

## 4. Tugas Terjadwal

| Command                         | Frekuensi                 | Tujuan                                                                        | Side effect                                                                 |
| ------------------------------- | ------------------------- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Webhook Kiro Crew `POST /api/hooks/agent` (dari wa-bridge) | Event-driven | `incident.opened` → `phase=TRIAGE`; vote `GRANTED` → `phase=EXECUTE` ke `franken-conductor` | Sekali per insiden+fase; retry untuk galat jaringan/429/5xx |
| Kiro Crew cron `incident-sweep` (`app.json`) | `every: 900` (15 menit)    | Jaring pengaman: `franken-conductor` `phase=SWEEP` men-triage insiden P1/P2/POST_OOM yang masih `DETECTED`/`REFLEX_APPLIED` | Hanya bila ada insiden tertinggal (webhook gagal) |
| Kiro Crew cron `morning-digest` (`app.json`) | `cron_expr: "0 7 * * *"`  | Ringkasan incident P3 dan statistik 24 jam lewat `franken-remediator`         | Satu pesan WA per node                                                      |
| Timer internal wa-bridge        | Setiap 15 s               | Cek heartbeat Sentinel                                                        | Alert `node silent` setelah 3 kali gagal                                    |
| Timer internal Sentinel         | Per TTL reflex            | Rollback aksi L1                                                              | Mengembalikan `MemoryHigh` / admission                                      |
| Background worker `verify_health` | Per `VerifyPollInterval` (default 5 s) selama jendela observasi | Mengumpulkan sampel metrik forward pasca L2; stabil bila PSI rendah dan proyeksi TTO (slope least-squares 60 s terakhir vs `memory.max`/MemTotal−64 MiB) ≥ 600 s | `REMEDIATING` → `VERIFYING` → `RESOLVED`/`ESCALATED`, rollback refleks L1, postmortem otomatis (`--postmortem-dir`), SSE `verification.completed` (`status`, `rolled_back`, `failure_reasons`, `postmortem_path`) yang memicu laporan akhir WA |
| Rediscovery target Sentinel | `--rediscover-interval` (default 10 s) | Memantau cgroup leaf `*.service` baru di `franken.slice`/`system.slice` & menutup insiden target transien yang lenyap | SSE `telemetry.target_added`/`telemetry.target_removed`, audit `TARGET_*`, rekonsiliasi startup & penangkapan OOM target lenyap via journal `--lines=0` + `EventsDelta` |

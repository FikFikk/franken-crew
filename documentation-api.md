# FrankenCrew — Dokumentasi API

> Status: **Tahap 1 & 2 Diimplementasikan** (telemetry kernel, PSI watcher, detector TTO, SQLite store & audit, policy validator, safe executor). Proyek ini bukan Laravel — tidak ada `routes/web.php` / `app/Console/Kernel.php`; penjadwalan memakai Kiro Crew cron dan timer internal Go.

## 1. Sentinel HTTP (hanya interface Tailscale)

| Field | Detail |
|---|---|
| Method + Endpoint | `GET /healthz` |
| Auth Required | Tidak |
| Headers | — |
| Query Params | — |
| Request Body | — |
| Response | `200` `{status, version, uptime_s, capabilities[]}` · `503` jika capability wajib hilang |
| Notes | Dipakai systemd watchdog dan heartbeat wa-bridge |

| Field | Detail |
|---|---|
| Method + Endpoint | `GET /v1/events` |
| Auth Required | Ya (Bearer token node) |
| Headers | `Authorization: Bearer <token>`, `Accept: text/event-stream` |
| Query Params | `since` (string, opsional, event id terakhir untuk resume) |
| Request Body | — |
| Response | `200` stream SSE: `incident.opened`, `incident.updated`, `reflex.applied`, `reflex.rolled_back`, `heartbeat` (15 s) · `401` token salah |
| Notes | Payload sudah diredaksi; mendukung header `Last-Event-ID` |

| Field | Detail |
|---|---|
| Method + Endpoint | `POST /mcp` |
| Auth Required | Ya (Bearer token node) |
| Headers | `Authorization: Bearer <token>`, `Content-Type: application/json`, `Accept: application/json, text/event-stream`, `Mcp-Session-Id` |
| Query Params | — |
| Request Body | JSON-RPC 2.0 sesuai MCP Streamable HTTP |
| Response | `200` hasil JSON-RPC / stream SSE · `401` · `400` request MCP tidak valid |
| Notes | Agent mengakses lewat proxy stdio `franken mcp connect sentinel@<node>`; token tidak pernah ditulis di config JSON |

### 1.1 Sentinel MCP Tools

| Tool | Tier | Input utama | Output utama | Catatan |
|---|---|---|---|---|
| `node_snapshot` | L0 | — | memory, PSI, unit, top cgroup | — |
| `incident_list` | L0 | `state?`, `limit?` | daftar incident | — |
| `incident_get` | L0 | `incident_id` | incident lengkap + evidence | — |
| `incident_claim` | L0 | `claimer` | incident atau `null` | Atomik; mencegah klaim ganda |
| `psi_history` | L0 | `cgroup`, `minutes ≤ 10` | seri some/full avg10 | — |
| `cgroup_top` | L0 | `limit ≤ 10` | cgroup per memory | — |
| `journal_tail` | L0 | `unit`, `lines ≤ 200` | baris terredaksi + `evidence_id` | — |
| `process_tree` | L0 | `cgroup` | pohon proses | — |
| `zombie_report` | L0 | — | zombie per PPID | — |
| `plan_submit` | L0 | `incident_id`, `plan` | `plan_hash`, tier per step, `violations[]` | Maks 2 revisi |
| `action_execute` | L1/L2 | `incident_id`, `step_id`, `approval_token?` | exit code, durasi, stderr terredaksi | L2 tanpa token valid ditolak; proses terlindungi selalu ditolak |
| `action_rollback` | L1 | `reflex_id` | status rollback | — |
| `incident_transition` | L0 | `incident_id`, `to`, `reason` | state baru | Hanya transisi legal |
| `verify_health` | L0 | `incident_id`, `window_s = 120` | `healthy`, detail cek | Sukses → rollback reflex otomatis |

## 2. wa-bridge

| Field | Detail |
|---|---|
| Method + Endpoint | `GET /healthz` (localhost) |
| Auth Required | Tidak |
| Headers | — |
| Query Params | — |
| Request Body | — |
| Response | `200` `{whatsapp: connected|logged_out, nodes: [{name, last_heartbeat}]}` |
| Notes | Tidak diekspos keluar host Brain |

### 2.1 wa-bridge MCP Tools (stdio)

| Tool | Input utama | Output utama | Catatan |
|---|---|---|---|
| `wa_notify` | `incident_id`, `severity`, `text ≤ 700` | message id | Rate limit 6/incident, 20/jam/node |
| `wa_request_approval` | `incident_id`, `plan_hash`, `options[≤3]` | `approval_id`, `nonce` | Opsi "Do nothing — I'll SSH in" ditambahkan otomatis |
| `wa_await_decision` | `approval_id`, `timeout_s ≤ 600` | `GRANTED + token` / `DENIED` / `EXPIRED` | Token Ed25519 sekali pakai |
| `wa_send_report` | `incident_id`, `summary` | message id | Dikirim saat state terminal |

## 3. Haunted Lab (publik, read-only)

| Field | Detail |
|---|---|
| Method + Endpoint | `GET /api/nodes` |
| Auth Required | Tidak |
| Headers | — |
| Query Params | — |
| Request Body | — |
| Response | `200` `[{name, status, memory_pct, psi_some_avg10}]` |
| Notes | Rate limit 60 req/menit/IP |

| Field | Detail |
|---|---|
| Method + Endpoint | `GET /api/incidents` |
| Auth Required | Tidak |
| Headers | — |
| Query Params | `limit` (int, opsional, default 20, maks 100), `cursor` (string, opsional) |
| Request Body | — |
| Response | `200` `{items: [{id, node, severity, state, opened_at, closed_at}], next_cursor}` |
| Notes | Data terredaksi |

| Field | Detail |
|---|---|
| Method + Endpoint | `GET /api/incidents/:id` |
| Auth Required | Tidak |
| Headers | — |
| Query Params | — |
| Request Body | — |
| Response | `200` incident + timeline + transcript agent + spec + postmortem · `404` |
| Notes | Nomor telepon & JID tidak pernah ditampilkan |

| Field | Detail |
|---|---|
| Method + Endpoint | `GET /api/stream` |
| Auth Required | Tidak |
| Headers | `Accept: text/event-stream` |
| Query Params | — |
| Request Body | — |
| Response | `200` SSE: vitals tiap 2 s + event incident |
| Notes | Maks 200 koneksi bersamaan |

## 4. Tugas Terjadwal

| Command | Frekuensi | Tujuan | Side effect |
|---|---|---|---|
| Kiro Crew cron `incident-sweep` | `* * * * *` | Klaim incident terbuka lalu jalankan pipeline Sentry → Architect → Remediator | Menulis `incidents/<id>/*`, mengirim poll WA, mengeksekusi aksi tervalidasi |
| Kiro Crew cron `morning-digest` | `0 7 * * *` (waktu lokal) | Ringkasan incident P3 dan statistik 24 jam | Satu pesan WA per node |
| Timer internal wa-bridge | Setiap 15 s | Cek heartbeat Sentinel | Alert `node silent` setelah 3 kali gagal |
| Timer internal Sentinel | Per TTL reflex | Rollback aksi L1 | Mengembalikan `MemoryHigh` / admission |


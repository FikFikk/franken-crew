---
inclusion: fileMatch
fileMatchPattern: "internal/{psi,cgroup,kernelfs}/**"
---

# Linux Kernel & Cgroups v2 Constraints

Applies whenever reading or modifying kernel telemetry collectors in `internal/psi`, `internal/cgroup`, or `internal/kernelfs`.

## Required Invariants

1. **Unified Hierarchy Only:** Cgroups v2 (`cgroup.controllers`) and PSI (`/proc/pressure/memory`) are mandatory; `kernelfs.Probe` must fail fast with actionable kernel parameter guidance (`psi=1`, `systemd.unified_cgroup_hierarchy=1`) if absent.
2. **Fixture Testability:** Never bypass `kernelfs.FS` with raw `os.ReadFile`/`os.WriteFile` inside collector logic. Always accept `kernelfs.FS` so tests run hermetically on Windows, macOS, and non-root CI.
3. **`memory.reclaim` Guardrails:** Proactive reclaim writes MUST remain per-cgroup and bounded to `<= 25%` of `memory.current`. Never write to `/proc/sys/vm/drop_caches`.
4. **Resilient Polling Fallback:** If PSI trigger write fails (`EINVAL`/`EPERM`), degrade gracefully to 1 Hz `avg10` polling and raise a single degraded-capability notice. If a cgroup disappears (`POLLERR`), tear down cleanly and re-discover after 5s.
5. **Safe Proc Parsing:** When parsing `/proc/<pid>/stat`, split on the first `(` and last `)` to extract `comm`, because process names can contain spaces or parentheses.


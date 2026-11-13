---
inclusion: always
---

# Technology Stack & Build Standards

## Backend (`franken` Single Binary)

- **Language:** Go 1.26.11+ (`go.mod` pins the patched toolchain; `CGO_ENABLED=0` static builds for `linux/arm64` and `linux/amd64`)
- **Security gate:** `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` must report no vulnerabilities before a release
- **Storage:** `modernc.org/sqlite` (WAL mode, `synchronous=NORMAL`, `foreign_keys=ON`)
- **MCP Transport:** `github.com/modelcontextprotocol/go-sdk/mcp` v1.8.0 (Streamable HTTP/SSE and stdio JSON-RPC)
- **Cryptography:** Stdlib `crypto/ed25519`, PKCS#8 (`0600`) / PKIX (`0644`), canonical JSON SHA-256 plan binding, single-use SQLite nonces
- **Testing:** Standard `testing` + `pgregory.net/rapid` property-based tests (invariants P1–P4)

## Mandatory Verification Commands

```bash
go vet ./...
go test -count=1 ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/franken
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/franken
```

## Coding Rules

- All kernel pseudo-file access MUST go through `internal/kernelfs.FS` so unit tests run cleanly against `kernelfs.MemFS` fixtures without root privileges.
- All code comments in Go sources MUST be written in Bahasa Indonesia; identifiers, errors, logs, specs, and commit messages MUST remain in English.


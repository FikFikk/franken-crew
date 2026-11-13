// Package ui menanam dashboard Graveyard ke biner franken: halaman landing (index.html, assets/), modul ESM
// tanpa build step (dist/, juga dipakai Kiro Crew lewat app.json ui.entry), dan data/replay.json yang
// dihasilkan oleh `franken lab simulate` atau `franken lab export`.
package ui

import "embed"

// Files memuat index.html, dist/, assets/, dan data/ untuk server `franken lab serve` (read-only).
//
//go:embed index.html dist assets data
var Files embed.FS

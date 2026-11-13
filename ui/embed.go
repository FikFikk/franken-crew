// Package ui menanam aset statis dashboard Graveyard ke biner franken. Isi direktori ini hanya placeholder
// minimal; build dashboard sebenarnya menimpa index.html, dist/, dan assets/, sedangkan data/replay.json
// dihasilkan oleh `franken lab simulate`.
package ui

import "embed"

// Files memuat index.html, dist/, assets/, dan data/ untuk server `franken lab serve` (read-only).
//
//go:embed index.html dist assets data
var Files embed.FS

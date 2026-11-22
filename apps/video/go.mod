// Modul kosong: membuat apps/video modul terpisah agar `go ... ./...` di akar repo
// tidak masuk ke node_modules proyek Remotion (beberapa paket npm berisi file .go).
module github.com/FikFikk/franken-crew/apps/video

go 1.26

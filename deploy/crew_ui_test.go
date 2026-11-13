package deploy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// crewUIManifest hanya memuat bagian app.json yang dipakai dashboard Kiro Crew untuk halaman aplikasi.
type crewUIManifest struct {
	Name          string `json:"name"`
	HeroImageDark string `json:"heroImageDark"`
	UI            *struct {
		Entry string `json:"entry"`
		Pages []struct {
			Route         string `json:"route"`
			Label         string `json:"label"`
			Icon          string `json:"icon"`
			EntryPoint    string `json:"entryPoint"`
			MountFunction string `json:"mountFunction"`
		} `json:"pages"`
	} `json:"ui"`
}

func readCrewUIManifest(t *testing.T) crewUIManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "app.json"))
	if err != nil {
		t.Fatalf("read app.json: %v", err)
	}
	var app crewUIManifest
	if err := json.Unmarshal(raw, &app); err != nil {
		t.Fatalf("decode app.json: %v", err)
	}
	return app
}

// Kiro Crew memuat ui.entry relatif terhadap ui/ dan tidak menjalankan build, jadi bundle harus ada di repo.
func TestCrewApp_RegistersGraveyardPage(t *testing.T) {
	app := readCrewUIManifest(t)
	if app.UI == nil {
		t.Fatal("app.json must declare a ui block so Kiro Crew shows the Graveyard page")
	}
	if app.UI.Entry != "dist/index.mjs" {
		t.Errorf("ui.entry = %q, want %q", app.UI.Entry, "dist/index.mjs")
	}
	if len(app.UI.Pages) != 1 {
		t.Fatalf("ui.pages must list exactly the Graveyard page, got %d pages", len(app.UI.Pages))
	}
	page := app.UI.Pages[0]
	if want := "/apps/" + app.Name; page.Route != want {
		t.Errorf("ui.pages[0].route = %q, want %q", page.Route, want)
	}
	if page.Label == "" || page.Icon == "" {
		t.Errorf("ui.pages[0] needs a sidebar label and a Lucide icon, got label=%q icon=%q", page.Label, page.Icon)
	}

	entry := page.EntryPoint
	if entry == "" {
		entry = app.UI.Entry
	}
	src, err := os.ReadFile(filepath.Join("..", "ui", filepath.FromSlash(entry)))
	if err != nil {
		t.Fatalf("ui entry %q must be committed under ui/: %v", entry, err)
	}
	mountFn := page.MountFunction
	if mountFn == "" {
		mountFn = "mount" // Default Kiro Crew bila mountFunction kosong.
	}
	exportsMount := regexp.MustCompile(`\bexport\s+(?:(?:async\s+)?function\s+` + regexp.QuoteMeta(mountFn) + `\b|\{[^}]*\b` + regexp.QuoteMeta(mountFn) + `\b[^}]*\})`)
	if !exportsMount.Match(src) {
		t.Errorf("ui entry %q must export the mount function %q", entry, mountFn)
	}
	if !regexp.MustCompile(`\bexport\s+default\b`).Match(src) {
		t.Errorf("ui entry %q must have a default export: the Crew dashboard renders it as the page component", entry)
	}
}

// Untuk aplikasi federated, path hero art relatif terhadap root repo; berkas yang hilang membuat kartu App Store kosong.
func TestCrewApp_HeroArtIsCommitted(t *testing.T) {
	app := readCrewUIManifest(t)
	if app.HeroImageDark == "" {
		t.Fatal("app.json must set heroImageDark for the App Store card")
	}
	if _, err := os.Stat(filepath.Join("..", filepath.FromSlash(app.HeroImageDark))); err != nil {
		t.Errorf("heroImageDark %q must exist in the repo: %v", app.HeroImageDark, err)
	}
}

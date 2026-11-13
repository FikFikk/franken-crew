package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/postmortem"
)

func runPostmortem(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("postmortem", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dbPath := fs.String("db", "franken-sentinel.db", "path to Sentinel SQLite database")
	incID := fs.String("incident", "", "incident ID to generate postmortem for (required)")
	outDir := fs.String("out", "incidents", "base output directory for postmortem.md")
	author := fs.String("author", "franken-remediator", "author recorded in postmortem header and audit trail")
	notes := fs.String("notes", "", "optional operator summary notes (redacted automatically)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", fs.Args())
		return 2
	}
	if *incID == "" {
		fmt.Fprintln(stderr, "error: --incident is required")
		return 2
	}

	store, err := incident.NewStore(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "error opening incident store: %v\n", err)
		return 1
	}
	defer func() {
		_ = store.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	doc, err := postmortem.GenerateAndWrite(ctx, store, postmortem.Options{
		IncidentID: *incID,
		OutputDir:  *outDir,
		Author:     *author,
		Notes:      *notes,
	})
	if err != nil {
		fmt.Fprintf(stderr, "postmortem error: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Generated postmortem for %s -> %s (state=%s, evidence=%d, audit=%d)\n",
		doc.IncidentID, doc.FilePath, doc.State, doc.EvidenceUsed, doc.AuditEntries)
	return 0
}


package main

import (
	"flag"
	"io"
	"testing"
)

func TestRegisterBridgeFlags_ParsesCrewWebhookFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var cfg bridgeFlags
	registerBridgeFlags(fs, &cfg)
	err := fs.Parse([]string{
		"--crew-webhook-url", "http://127.0.0.1:5476/api/hooks/agent",
		"--crew-token-env", "MY_CREW_TOKEN",
		"--crew-agent", "franken-conductor",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.crewWebhookURL != "http://127.0.0.1:5476/api/hooks/agent" || cfg.crewTokenEnv != "MY_CREW_TOKEN" || cfg.crewAgent != "franken-conductor" {
		t.Fatalf("unexpected crew flags: %+v", cfg)
	}
}

func TestBuildCrewNotifier(t *testing.T) {
	env := map[string]string{"KIROCREW_TOKEN": "crew-tok"}
	getenv := func(k string) string { return env[k] }

	if n, err := buildCrewNotifier(bridgeFlags{}, getenv); err != nil || n != nil {
		t.Fatalf("empty URL must disable the Crew trigger, got notifier=%v err=%v", n, err)
	}
	if _, err := buildCrewNotifier(bridgeFlags{crewWebhookURL: "http://127.0.0.1:5476/api/hooks/agent", crewTokenEnv: "MISSING_TOKEN"}, getenv); err == nil {
		t.Fatal("expected an error when the Crew token env var is empty")
	}
	if _, err := buildCrewNotifier(bridgeFlags{crewWebhookURL: "http://8.8.8.8/api/hooks/agent", crewTokenEnv: "KIROCREW_TOKEN"}, getenv); err == nil {
		t.Fatal("expected plain HTTP to a public host to be rejected")
	}
	n, err := buildCrewNotifier(bridgeFlags{crewWebhookURL: "http://127.0.0.1:5476/api/hooks/agent", crewTokenEnv: "KIROCREW_TOKEN"}, getenv)
	if err != nil || n == nil {
		t.Fatalf("expected a Crew notifier, got notifier=%v err=%v", n, err)
	}
}

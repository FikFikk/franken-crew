package redact

import (
	"strings"
	"testing"
)

func TestString_RedactionPatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
		excludes string
	}{
		{
			name:     "Authorization header Bearer",
			input:    "GET /api HTTP/1.1\nAuthorization: Bearer mySuperSecretToken123456789\nHost: example.com",
			contains: "[REDACTED_AUTH]",
			excludes: "mySuperSecretToken123456789",
		},
		{
			name:     "JWT token in log line",
			input:    "User session verified with eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c successfully",
			contains: "[REDACTED_JWT]",
			excludes: "eyJhbGciOiJIUzI1NiIs",
		},
		{
			name:     "Database connection string with credentials",
			input:    "Connected to postgres://admin:superSecretP@ss123@db.internal.net:5432/production_db",
			contains: "[REDACTED_PASSWORD]",
			excludes: "superSecretP@ss123",
		},
		{
			name:     "JSON password and secret field",
			input:    `{"username": "devops", "password": "UnsafePassword99!", "secret": "xyz123abc"}`,
			contains: "[REDACTED_SECRET]",
			excludes: "UnsafePassword99!",
		},
		{
			name:     "URL query param with token",
			input:    "https://api.internal/webhook?token=secretWebhookToken123&action=reboot",
			contains: "[REDACTED_SECRET]",
			excludes: "secretWebhookToken123",
		},
		{
			name:     "PEM private key block",
			input:    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y2\nsecret_key_bytes_here\n-----END RSA PRIVATE KEY-----",
			contains: "[REDACTED_PRIVATE_KEY]",
			excludes: "secret_key_bytes_here",
		},
		{
			name:     "IPv4 address",
			input:    "Incoming request from 192.168.1.100 to server 10.0.0.5",
			contains: "[REDACTED_IP]",
			excludes: "192.168.1.100",
		},
		{
			name:     "Phone number in alert",
			input:    "Contact on-call engineer at +6281234567890 immediately",
			contains: "[REDACTED_PHONE]",
			excludes: "6281234567890",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := String(tc.input)
			if !strings.Contains(got, tc.contains) {
				t.Errorf("expected output to contain %q, got: %s", tc.contains, got)
			}
			if strings.Contains(got, tc.excludes) {
				t.Errorf("output still contains sensitive data %q: %s", tc.excludes, got)
			}
		})
	}
}

func TestLinesAndMap(t *testing.T) {
	lines := []string{
		"Starting service on 127.0.0.1:8080",
		"DB_URL=postgres://app:pass123@localhost/app_db",
	}
	redactedLines := Lines(lines)
	if strings.Contains(redactedLines[0], "127.0.0.1") {
		t.Errorf("IP address was not redacted from lines: %s", redactedLines[0])
	}
	if strings.Contains(redactedLines[1], "pass123") {
		t.Errorf("Password was not redacted from connection string: %s", redactedLines[1])
	}

	meta := map[string]any{
		"node":        "node01",
		"auth_token":  "top_secret_token_123",
		"target_ip":   "10.20.30.40",
		"nested_info": map[string]any{"secret": "nested_secret_val"},
	}
	redactedMap := Map(meta)
	if redactedMap["auth_token"] != "[REDACTED_SECRET]" {
		t.Errorf("auth_token not redacted in map: %v", redactedMap["auth_token"])
	}
	if strings.Contains(redactedMap["target_ip"].(string), "10.20.30.40") {
		t.Errorf("target_ip not redacted: %v", redactedMap["target_ip"])
	}
}


func TestString_Tahap4TokensIndonesianPhonesAndTelemetryBounds(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "sensor token sk- format OpenAI dan Kiro tanpa memutus field lain",
			input:       "Authorization failed using key sk-proj_abcDEF1234567890_XYZ987 when calling model",
			wantContain: []string{"[REDACTED_TOKEN]", "when calling model"},
			wantAbsent:  []string{"sk-proj_abcDEF1234567890_XYZ987"},
		},
		{
			name:        "sensor nomor HP Indonesia 08xx dan +628xx sambil mempertahankan metrik byte dan epoch",
			input:       `{"mem_bytes":1073741824,"ts_ms":1731500000123,"contact":"0812-3456-7890","alt":"+62 812-3456-7890","compact":"081234567890"}`,
			wantContain: []string{"1073741824", "1731500000123", "[REDACTED_PHONE]"},
			wantAbsent:  []string{"0812-3456-7890", "+62 812-3456-7890", "081234567890"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := String(tc.input)
			for _, w := range tc.wantContain {
				if !containsSubstr(got, w) {
					t.Errorf("String(%q) = %q, tidak mengandung %q", tc.input, got, w)
				}
			}
			for _, bad := range tc.wantAbsent {
				if containsSubstr(got, bad) {
					t.Errorf("String(%q) = %q, masih mengandung %q", tc.input, got, bad)
				}
			}
		})
	}
}

func TestMap_RecursiveNestedSlicesAndSecretKeys(t *testing.T) {
	input := map[string]any{
		"api_key":    "plain-api-key",
		"mem_bytes":  1073741824,
		"events":     []any{"contact 0812-3456-7890", map[string]any{"authorization": "secret", "msg": "token sk-1234567890abcdefghijklmnop bytes=1073741824"}},
		"notes":      []string{"owner +6281234567890"},
	}

	got := Map(input)
	if got["api_key"] != "[REDACTED_SECRET]" {
		t.Fatalf("api_key seharusnya disensor, dapat: %v", got["api_key"])
	}
	if got["mem_bytes"] != 1073741824 {
		t.Fatalf("mem_bytes tidak boleh berubah, dapat: %v", got["mem_bytes"])
	}
	events, ok := got["events"].([]any)
	if !ok || len(events) != 2 {
		t.Fatalf("events slice hilang atau berubah tipe: %#v", got["events"])
	}
	if s0, _ := events[0].(string); s0 != "contact [REDACTED_PHONE]" {
		t.Errorf("events[0] = %q, harap 'contact [REDACTED_PHONE]'", s0)
	}
	nestedMap, ok := events[1].(map[string]any)
	if !ok {
		t.Fatalf("events[1] bukan map[string]any: %#v", events[1])
	}
	if nestedMap["authorization"] != "[REDACTED_SECRET]" {
		t.Errorf("nested authorization = %v, harap [REDACTED_SECRET]", nestedMap["authorization"])
	}
	if msg, _ := nestedMap["msg"].(string); !containsSubstr(msg, "[REDACTED_TOKEN]") || !containsSubstr(msg, "1073741824") || containsSubstr(msg, "sk-1234567890") {
		t.Errorf("nested msg tidak tersensor dengan benar: %q", msg)
	}
}

func containsSubstr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

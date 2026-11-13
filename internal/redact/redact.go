package redact

import (
	"regexp"
	"strings"
)

var (
	// Pola untuk mendeteksi Authorization headers (Bearer, Basic, Token)
	reAuthHeader = regexp.MustCompile(`(?i)(authorization:\s*(bearer|basic|token)\s+)([A-Za-z0-9\-\._~\+\/]+=*)`)

	// Pola untuk mendeteksi token Bearer yang berdiri sendiri
	reBearer = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9\-\._~\+\/]{16,})`)

	// Pola untuk mendeteksi JWT (tiga segmen base64url yang dipisahkan titik)
	reJWT = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)

	// Pola untuk mendeteksi connection strings (postgres, mysql, mongodb, redis, amqp) yang memuat kredensial
	reConnString = regexp.MustCompile(`(?i)([a-z0-9+]+://)([^:]+):([^@\s]+)@([a-z0-9\.\-_:]+)`)

	// Pola untuk pasangan key-value sensitif (password, secret, token, api_key, private_key)
	reKeyValue = regexp.MustCompile(`(?i)("(?:token|password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)"\s*:\s*")[^"]+(")`)
	reParamVal = regexp.MustCompile(`(?i)((?:token|password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)=)([^&\s]+)`)

	// Pola untuk private key block (PEM format)
	rePrivateKey = regexp.MustCompile(`(?s)-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----.*?-----END[ A-Z0-9_-]*PRIVATE KEY-----`)

	// Pola untuk API key dan token rahasia (OpenAI/Kiro sk-, AWS AKIA, GitHub, Slack)
	reAPIKey = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b`)

	// Pola untuk alamat IPv4
	reIPv4 = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// Pola untuk nomor telepon internasional dan lokal Indonesia (08xx/+628xx) dengan batas kata
	rePhone = regexp.MustCompile(
		`\+[-.\s]?62[-.\s]?8[0-9]{1,2}(?:[-.\s]?[0-9]{3,4}){1,2}[-.\s]?[0-9]{3,5}\b` +
			`|\b(?:62|0)8[0-9]{1,2}(?:[-.\s]?[0-9]{3,4}){1,2}[-.\s]?[0-9]{3,5}\b` +
			`|\+[1-9][0-9]{0,2}[-.\s](?:\(?[0-9]{2,4}\)?[-.\s]){1,3}[0-9]{3,6}\b` +
			`|\+[1-9][0-9]{8,14}\b` +
			`|(?:\([0-9]{3}\)[-.\s]?|\b[0-9]{3}[-.\s])[0-9]{3,4}[-.\s][0-9]{4,6}\b`,
	)
)

// String menyensor string teks dari seluruh data rahasia seperti token, password, IP, dan nomor telepon.
func String(input string) string {
	if input == "" {
		return ""
	}

	result := input

	// Sensor private key PEM
	result = rePrivateKey.ReplaceAllString(result, "[REDACTED_PRIVATE_KEY]")

	// Sensor JWT tokens
	result = reJWT.ReplaceAllString(result, "[REDACTED_JWT]")

	// Sensor authorization headers
	result = reAuthHeader.ReplaceAllString(result, "${1}[REDACTED_AUTH]")

	// Sensor bearer tokens
	result = reBearer.ReplaceAllString(result, "${1}[REDACTED_TOKEN]")

	// Sensor connection strings (sembunyikan password dan username sensitif)
	result = reConnString.ReplaceAllString(result, "${1}[REDACTED_USER]:[REDACTED_PASSWORD]@${4}")

	// Sensor key-value JSON
	result = reKeyValue.ReplaceAllString(result, "${1}[REDACTED_SECRET]${2}")

	// Sensor parameter URL query string
	result = reParamVal.ReplaceAllString(result, "${1}[REDACTED_SECRET]")

	// Sensor API key dan token rahasia umum sebelum pola numerik berjalan
	result = reAPIKey.ReplaceAllString(result, "[REDACTED_TOKEN]")

	// Sensor IPv4
	result = reIPv4.ReplaceAllString(result, "[REDACTED_IP]")

	// Sensor nomor telepon (hanya jika panjangnya masuk akal)
	result = rePhone.ReplaceAllStringFunc(result, func(match string) string {
		digits := 0
		for _, r := range match {
			if r >= '0' && r <= '9' {
				digits++
			}
		}
		if digits >= 10 && digits <= 15 {
			return "[REDACTED_PHONE]"
		}
		return match
	})

	return result
}

// Lines memproses slice baris teks (misalnya output journald) dan menyensor tiap baris.
func Lines(lines []string) []string {
	if lines == nil {
		return nil
	}
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = String(line)
	}
	return out
}

// Map memproses map key-value dan menyensor nilainya secara rekursif jika bertipe string atau nested map.
func Map(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if isSensitiveKey(k) {
			out[k] = "[REDACTED_SECRET]"
			continue
		}
		out[k] = sanitizeValue(v)
	}
	return out
}

// isSensitiveKey mendeteksi nama field yang menyimpan kredensial atau otorisasi.
func isSensitiveKey(k string) bool {
	lowerKey := strings.ToLower(k)
	for _, needle := range []string{
		"password",
		"secret",
		"token",
		"credential",
		"authorization",
		"api_key",
		"apikey",
		"private_key",
		"passphrase",
	} {
		if strings.Contains(lowerKey, needle) {
			return true
		}
	}
	return false
}

// sanitizeValue menyensor nilai string, map, dan slice secara rekursif agar data bersarang ikut aman.
func sanitizeValue(v any) any {
	switch val := v.(type) {
	case string:
		return String(val)
	case map[string]any:
		return Map(val)
	case []string:
		return Lines(val)
	case []map[string]any:
		res := make([]map[string]any, len(val))
		for i, item := range val {
			res[i] = Map(item)
		}
		return res
	case []any:
		res := make([]any, len(val))
		for i, item := range val {
			res[i] = sanitizeValue(item)
		}
		return res
	default:
		return val
	}
}

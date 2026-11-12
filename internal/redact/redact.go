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

	// Pola untuk alamat IPv4
	reIPv4 = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// Pola untuk nomor telepon internasional dan lokal (+62, 08, dsb)
	rePhone = regexp.MustCompile(`(?:\+?[0-9]{1,3}[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{4,6}`)
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
		lowerKey := strings.ToLower(k)
		if strings.Contains(lowerKey, "password") || strings.Contains(lowerKey, "secret") || strings.Contains(lowerKey, "token") {
			out[k] = "[REDACTED_SECRET]"
			continue
		}
		switch val := v.(type) {
		case string:
			out[k] = String(val)
		case map[string]any:
			out[k] = Map(val)
		case []string:
			out[k] = Lines(val)
		default:
			out[k] = val
		}
	}
	return out
}

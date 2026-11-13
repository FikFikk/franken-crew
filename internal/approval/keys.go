package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// DefaultPrivateKeyName adalah nama berkas kunci privat Ed25519 untuk wa-bridge (permission 0600).
	DefaultPrivateKeyName = "bridge-ed25519.key"
	// DefaultPublicKeyName adalah nama berkas kunci publik Ed25519 untuk Sentinel (permission 0644).
	DefaultPublicKeyName = "sentinel-ed25519.pub"
)

var (
	// ErrKeysAlreadyExist dikembalikan saat `franken keys init` dijalankan pada direktori yang sudah memiliki kunci tanpa `--force`.
	ErrKeysAlreadyExist = errors.New("approval: keys already exist (use --force to overwrite)")
	// ErrInvalidKeyFormat dikembalikan ketika berkas PEM bukan kunci Ed25519 PKCS#8/PKIX yang valid.
	ErrInvalidKeyFormat = errors.New("approval: invalid Ed25519 PEM key format")
)

// KeyPair menyimpan pasangan kunci Ed25519 hasil generasi beserta sidik jari SHA-256 kunci publik.
type KeyPair struct {
	PublicKey   ed25519.PublicKey
	PrivateKey  ed25519.PrivateKey
	Fingerprint string
}

// GenerateKeyPair menghasilkan pasangan kunci Ed25519 baru menggunakan CSPRNG OS (`crypto/rand`).
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	fp, err := PublicKeyFingerprint(pub)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PublicKey:   pub,
		PrivateKey:  priv,
		Fingerprint: fp,
	}, nil
}

// PublicKeyFingerprint menghitung sidik jari SHA-256 hex dari representasi DER PKIX kunci publik Ed25519.
func PublicKeyFingerprint(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: unexpected public key length %d", ErrInvalidKeyFormat, len(pub))
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key for fingerprint: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// InitKeys menginisialisasi pasangan kunci Ed25519 di direktori target dengan permission ketat (`0600` privat, `0644` publik).
func InitKeys(dir string, force bool) (string, string, *KeyPair, error) {
	if dir == "" {
		return "", "", nil, errors.New("approval: key directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", nil, fmt.Errorf("create key directory %q: %w", dir, err)
	}

	privPath := filepath.Join(dir, DefaultPrivateKeyName)
	pubPath := filepath.Join(dir, DefaultPublicKeyName)

	if !force {
		if _, err := os.Stat(privPath); err == nil {
			return "", "", nil, fmt.Errorf("%w: %s", ErrKeysAlreadyExist, privPath)
		}
		if _, err := os.Stat(pubPath); err == nil {
			return "", "", nil, fmt.Errorf("%w: %s", ErrKeysAlreadyExist, pubPath)
		}
	}

	kp, err := GenerateKeyPair()
	if err != nil {
		return "", "", nil, err
	}

	if err := SavePrivateKey(privPath, kp.PrivateKey); err != nil {
		return "", "", nil, err
	}
	if err := SavePublicKey(pubPath, kp.PublicKey); err != nil {
		// Hapus kunci privat yang baru dibuat agar direktori tidak tertinggal dalam kondisi setengah jadi
		_ = os.Remove(privPath)
		return "", "", nil, err
	}

	return privPath, pubPath, kp, nil
}

// SavePrivateKey menyimpan kunci privat Ed25519 dalam format PEM PKCS#8 secara atomik dengan permission 0600.
func SavePrivateKey(path string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: unexpected private key length %d", ErrInvalidKeyFormat, len(priv))
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal pkcs8 private key: %w", err)
	}
	defer zeroBytes(der)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	defer zeroBytes(pemBytes)

	return writeFileStrictMode(path, pemBytes, 0o600)
}

// SavePublicKey menyimpan kunci publik Ed25519 dalam format PEM PKIX secara atomik dengan permission 0644.
func SavePublicKey(path string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: unexpected public key length %d", ErrInvalidKeyFormat, len(pub))
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal pkix public key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})

	return writeFileStrictMode(path, pemBytes, 0o644)
}

// LoadPrivateKey membaca dan mem-parsing kunci privat Ed25519 dari berkas PEM PKCS#8.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", path, err)
	}
	defer zeroBytes(data)

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%w: expected PRIVATE KEY PEM block", ErrInvalidKeyFormat)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyFormat, err)
	}

	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: key is not Ed25519 private key", ErrInvalidKeyFormat)
	}
	return priv, nil
}

// LoadPublicKey membaca dan mem-parsing kunci publik Ed25519 dari berkas PEM PKIX.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%w: expected PUBLIC KEY PEM block", ErrInvalidKeyFormat)
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyFormat, err)
	}

	pub, ok := parsed.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: key is not Ed25519 public key", ErrInvalidKeyFormat)
	}
	return pub, nil
}

// writeFileStrictMode menulis berkas via berkas sementara dengan mode eksplisit agar kunci privat tidak pernah terbuka ke user lain.
func writeFileStrictMode(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("ensure parent dir for %q: %w", path, err)
	}

	tmp, err := os.CreateTemp(dir, ".franken-key-*")
	if err != nil {
		return fmt.Errorf("create temp key file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	// Terapkan permission sejak awal sebelum penulisan selesai
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp key file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write key bytes: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close key file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp key file to %q: %w", path, err)
	}
	cleanup = false

	// Pastikan permission target tetap akurat pasca rename
	_ = os.Chmod(path, mode)
	return nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

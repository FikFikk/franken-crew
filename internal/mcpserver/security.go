package mcpserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

var (
	// ErrUnsafeBindAddress dikembalikan jika alamat bind HTTP mengarah ke wildcard 0.0.0.0/:: atau IP publik tanpa izin eksplisit.
	ErrUnsafeBindAddress = errors.New("mcpserver: unsafe bind address (must bind to Tailscale, loopback, or private interface)")
	// ErrMissingBearerToken dikembalikan saat menginisialisasi HTTP server tanpa bearer token autentikasi.
	ErrMissingBearerToken = errors.New("mcpserver: non-empty bearer token is required for HTTP transport")
	// ErrTailscaleNotFound dikembalikan ketika tidak ada interface atau alamat CGNAT Tailscale yang aktif di host.
	ErrTailscaleNotFound = errors.New("mcpserver: no Tailscale interface IP found on host")

	tailscaleCGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleIPv6Prefix  = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// IsTailscaleAddr memeriksa apakah sebuah alamat IP berada di rentang CGNAT Tailscale (100.64.0.0/10 atau fd7a:115c:a1e0::/48).
func IsTailscaleAddr(addr netip.Addr) bool {
	return tailscaleCGNATPrefix.Contains(addr) || tailscaleIPv6Prefix.Contains(addr)
}

// ValidateBindAddr memverifikasi alamat listener agar terikat hanya pada loopback, Tailscale, atau IP privat eksplisit.
func ValidateBindAddr(addr string, allowWildcard bool) (string, error) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return "", fmt.Errorf("%w: empty bind address", ErrUnsafeBindAddress)
	}

	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: invalid host:port %q: %v", ErrUnsafeBindAddress, trimmed, err)
	}
	if port == "" {
		return "", fmt.Errorf("%w: port is required in %q", ErrUnsafeBindAddress, trimmed)
	}

	if host == "" {
		if allowWildcard {
			return trimmed, nil
		}
		return "", fmt.Errorf("%w: wildcard host in %q is prohibited", ErrUnsafeBindAddress, trimmed)
	}

	if strings.EqualFold(host, "localhost") {
		return net.JoinHostPort("127.0.0.1", port), nil
	}

	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("%w: unsupported non-IP host %q", ErrUnsafeBindAddress, host)
	}

	if parsed.IsUnspecified() {
		if allowWildcard {
			return trimmed, nil
		}
		return "", fmt.Errorf("%w: wildcard IP %s is prohibited", ErrUnsafeBindAddress, parsed.String())
	}

	if parsed.IsLoopback() || IsTailscaleAddr(parsed) || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return net.JoinHostPort(parsed.String(), port), nil
	}

	if allowWildcard {
		return trimmed, nil
	}
	return "", fmt.Errorf("%w: public IP %s is blocked unless explicitly allowed", ErrUnsafeBindAddress, parsed.String())
}

// FindTailscaleIP mencari alamat IPv4/IPv6 Tailscale aktif pada interface jaringan host.
func FindTailscaleIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list network interfaces: %w", err)
	}

	var fallbackV6 string
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		nameLower := strings.ToLower(iface.Name)
		isTSIface := strings.Contains(nameLower, "tailscale") || strings.HasPrefix(nameLower, "ts")

		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if IsTailscaleAddr(addr) || (isTSIface && addr.IsPrivate()) {
				if addr.Is4() {
					return addr.String(), nil
				}
				if fallbackV6 == "" {
					fallbackV6 = addr.String()
				}
			}
		}
	}

	if fallbackV6 != "" {
		return fallbackV6, nil
	}
	return "", ErrTailscaleNotFound
}

// BearerAuthMiddleware mewajibkan header `Authorization: Bearer <token>` menggunakan perbandingan hash waktu konstan.
func BearerAuthMiddleware(expectedToken string, next http.Handler) http.Handler {
	expectedSum := sha256.Sum256([]byte(expectedToken))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expectedToken == "" {
			writeUnauthorized(w, "server bearer authentication is not configured")
			return
		}

		authHeader := r.Header.Get("Authorization")
		if len(authHeader) < 8 || !strings.EqualFold(authHeader[:7], "Bearer ") {
			writeUnauthorized(w, "missing bearer authorization header")
			return
		}

		presented := strings.TrimSpace(authHeader[7:])
		if presented == "" {
			writeUnauthorized(w, "empty bearer token")
			return
		}

		presentedSum := sha256.Sum256([]byte(presented))
		if subtle.ConstantTimeCompare(presentedSum[:], expectedSum[:]) != 1 {
			writeUnauthorized(w, "invalid bearer token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="franken-sentinel"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, msg)
}

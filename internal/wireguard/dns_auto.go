package wireguard

import (
	"database/sql"
	"errors"
	"net"
	"strings"

	"netplug-go/internal/db"
)

// DefaultAutoDNSHost is the fallback resolver IP when WireGuard server IP is unavailable.
const DefaultAutoDNSHost = "169.254.20.10"

var linkLocalDNSNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("169.254.0.0/16")
	return n
}()

// IsLinkLocalDNSHost reports whether ip is in 169.254.0.0/16 (NodeLocal-style link-local).
func IsLinkLocalDNSHost(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	return linkLocalDNSNet.Contains(parsed.To4())
}

// DefaultAutoDNSHostIP returns the fallback DNS IP used when server address cannot be read.
func DefaultAutoDNSHostIP() string {
	return DefaultAutoDNSHost
}

// TryDNSServerHost returns the WireGuard server IPv4 when configured.
func TryDNSServerHost(sqlDB *sql.DB) (string, bool) {
	host, err := DNSServerHost(sqlDB)
	return host, err == nil && host != ""
}

// EnsureAutoDNSHost assigns ClientDNSHost when client and listen addresses are blank.
// Prefers the WireGuard server IP so clients can always reach the resolver through the tunnel.
func EnsureAutoDNSHost(sqlDB *sql.DB, s *db.DNSSettings) (bool, error) {
	if s == nil {
		return false, errors.New("dns settings is nil")
	}
	clientHost := strings.TrimSpace(s.ClientDNSHost)
	listenHost := strings.TrimSpace(s.ListenHost)
	storedListenHost := hostFromStoredListenAddr(s.ListenAddr)
	legacyAutoLinkLocal := clientHost == DefaultAutoDNSHost && listenHost == "" && storedListenHost == ""
	if (clientHost != "" || listenHost != "" || storedListenHost != "") && !legacyAutoLinkLocal {
		return false, nil
	}
	autoHost := allocateAutoDNSHost(sqlDB)
	if clientHost == autoHost {
		return false, nil
	}
	s.ClientDNSHost = autoHost
	return true, nil
}

func allocateAutoDNSHost(sqlDB *sql.DB) string {
	if host, ok := TryDNSServerHost(sqlDB); ok {
		return host
	}
	return DefaultAutoDNSHost
}

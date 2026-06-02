package wireguard

import (
	"database/sql"
	"errors"
	"net"
	"strings"

	"netplug-go/internal/db"
)

// DefaultAutoDNSHost is the link-local resolver IP (same default as Kubernetes NodeLocal DNSCache).
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

// DefaultAutoDNSHostIP returns the dedicated link-local DNS IP used when fields are left blank.
func DefaultAutoDNSHostIP() string {
	return DefaultAutoDNSHost
}

// TryDNSServerHost returns the WireGuard server IPv4 when configured.
func TryDNSServerHost(sqlDB *sql.DB) (string, bool) {
	host, err := DNSServerHost(sqlDB)
	return host, err == nil && host != ""
}

// EnsureAutoDNSHost assigns ClientDNSHost when client and listen addresses are blank.
// Uses 169.254.20.10 (link-local, NodeLocal DNS convention), not the WireGuard 10.x subnet.
func EnsureAutoDNSHost(sqlDB *sql.DB, s *db.DNSSettings) (bool, error) {
	if s == nil {
		return false, errors.New("dns settings is nil")
	}
	if strings.TrimSpace(s.ClientDNSHost) != "" || strings.TrimSpace(s.ListenHost) != "" {
		return false, nil
	}
	if hostFromStoredListenAddr(s.ListenAddr) != "" {
		return false, nil
	}
	s.ClientDNSHost = allocateDedicatedDNSHost()
	return true, nil
}

func allocateDedicatedDNSHost() string {
	return DefaultAutoDNSHost
}

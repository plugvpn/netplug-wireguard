package wireguard

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"netplug-go/internal/db"
)

// DNSServerHost returns the WireGuard server IPv4 from vpn_configuration.
func DNSServerHost(sqlDB *sql.DB) (string, error) {
	if sqlDB == nil {
		return "", errors.New("database is not available")
	}
	sys, err := db.GetSystemConfig(sqlDB)
	if err != nil {
		return "", err
	}
	if len(sys.VPNConfigJSON) == 0 {
		return "", errors.New("WireGuard is not configured yet")
	}
	var vc struct {
		WireGuard struct {
			ServerAddress string `json:"serverAddress"`
		} `json:"wireGuard"`
	}
	if err := json.Unmarshal(sys.VPNConfigJSON, &vc); err != nil {
		return "", err
	}
	ip := parseServerIPv4(vc.WireGuard.ServerAddress)
	if ip == nil {
		return "", fmt.Errorf("invalid WireGuard server address %q", vc.WireGuard.ServerAddress)
	}
	return ip.String(), nil
}

// NormalizeDNSHost accepts an IPv4/IPv6 address or CIDR and returns the host IP string.
func NormalizeDNSHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("listen address is empty")
	}
	if ip := parseServerIPv4(host); ip != nil {
		return ip.String(), nil
	}
	ipStr := host
	if strings.Contains(host, "/") {
		ipStr = strings.TrimSpace(strings.SplitN(host, "/", 2)[0])
	}
	if ip := net.ParseIP(ipStr); ip != nil {
		return ip.String(), nil
	}
	return "", fmt.Errorf("invalid listen address %q", host)
}

// DNSListenAddress returns host:port using the WireGuard server address from vpn_configuration.
// port defaults to db.DefaultDNSListenPort when zero or negative.
func DNSListenAddress(sqlDB *sql.DB, port int) (string, error) {
	return ResolveDNSListenAddress(sqlDB, db.DNSSettings{ListenPort: port})
}

// SuggestDedicatedDNSHost returns the recommended link-local resolver IP for the DNS UI.
func SuggestDedicatedDNSHost(string) string {
	return DefaultAutoDNSHost
}

// ResolveDNSListenAddress builds host:port for CoreDNS to bind.
// Uses ListenHost when set, else ClientDNSHost, else the WireGuard server address.
func ResolveDNSListenAddress(sqlDB *sql.DB, s db.DNSSettings) (string, error) {
	port := s.ListenPort
	if port <= 0 {
		port = db.DefaultDNSListenPort
	}
	if port > 65535 {
		return "", fmt.Errorf("invalid DNS listen port %d", port)
	}
	host, err := resolveListenHost(sqlDB, s)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func resolveListenHost(sqlDB *sql.DB, s db.DNSSettings) (string, error) {
	host := strings.TrimSpace(s.ListenHost)
	if host == "" {
		host = strings.TrimSpace(s.ClientDNSHost)
	}
	if host == "" {
		host = hostFromStoredListenAddr(s.ListenAddr)
	}
	if host == "" {
		return DNSServerHost(sqlDB)
	}
	return NormalizeDNSHost(host)
}

// DNSResolverHost returns the IP clients should use for DNS when NetPlug DNS is enabled.
// Uses ClientDNSHost when set, else ListenHost, else the WireGuard server address.
func DNSResolverHost(sqlDB *sql.DB, s db.DNSSettings) (string, error) {
	host := strings.TrimSpace(s.ClientDNSHost)
	if host == "" {
		host = strings.TrimSpace(s.ListenHost)
	}
	if host == "" {
		host = hostFromStoredListenAddr(s.ListenAddr)
	}
	if host == "" {
		return DNSServerHost(sqlDB)
	}
	return NormalizeDNSHost(host)
}

// ClientDNS returns the DNS= value for WireGuard client configs and QR codes.
// When NetPlug DNS is enabled, uses the configured resolver host; otherwise WireGuard DNS from system config.
func ClientDNS(sqlDB *sql.DB) (string, error) {
	if sqlDB == nil {
		return "", errors.New("database is not available")
	}
	dnsCfg, err := db.GetDNSSettings(sqlDB)
	if err != nil {
		return "", err
	}
	if dnsCfg.Enabled {
		host, err := DNSResolverHost(sqlDB, dnsCfg)
		if err != nil {
			return "", err
		}
		if host != "" {
			return host, nil
		}
	}

	sys, err := db.GetSystemConfig(sqlDB)
	if err != nil {
		return "", err
	}
	var vc struct {
		WireGuard struct {
			DNS string `json:"dns"`
		} `json:"wireGuard"`
	}
	if len(sys.VPNConfigJSON) > 0 {
		_ = json.Unmarshal(sys.VPNConfigJSON, &vc)
	}
	return strings.TrimSpace(vc.WireGuard.DNS), nil
}

func hostFromStoredListenAddr(listen string) string {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return ""
	}
	if strings.Contains(listen, ":") {
		host, _, err := net.SplitHostPort(listen)
		if err == nil {
			return strings.TrimSpace(host)
		}
	}
	return listen
}

package wireguard

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"netplug-go/internal/db"
)

// ErrNoClientPrivateKey is returned when vpn_users.private_key is missing (e.g. peers imported from wg0.conf).
var ErrNoClientPrivateKey = errors.New("user has no private key")

func RenderClientConfig(sqlDB *sql.DB, userID string) (configText string, filename string, err error) {
	if sqlDB == nil {
		return "", "", errors.New("db is nil")
	}

	var (
		username   string
		privKey    sql.NullString
		address    sql.NullString
		psk        sql.NullString
	)
	err = sqlDB.QueryRow(`
		SELECT username, private_key, allowed_ips, preshared_key
		FROM vpn_users
		WHERE id = ?
		LIMIT 1
	`, userID).Scan(&username, &privKey, &address, &psk)
	if err != nil {
		return "", "", err
	}
	if !privKey.Valid || strings.TrimSpace(privKey.String) == "" {
		return "", "", ErrNoClientPrivateKey
	}
	if !address.Valid || strings.TrimSpace(address.String) == "" {
		return "", "", errors.New("user has no address")
	}

	// `vpn_users.allowed_ips` is stored as: "<tunnel-ip-cidr>, <optional extra prefixes...>"
	// For a client config, only the first CIDR belongs in [Interface] Address.
	userAddr := strings.TrimSpace(address.String)
	if i := strings.IndexByte(userAddr, ','); i >= 0 {
		userAddr = strings.TrimSpace(userAddr[:i])
	}
	if userAddr == "" {
		return "", "", errors.New("user has no address")
	}

	var (
		serverPub  string
		serverHost string
		serverPort int
	)
	err = sqlDB.QueryRow(`SELECT public_key, host, COALESCE(port, 0) FROM vpn_servers WHERE id='wireguard' LIMIT 1`).Scan(&serverPub, &serverHost, &serverPort)
	if err != nil {
		return "", "", err
	}

	sys, err := db.GetSystemConfig(sqlDB)
	if err != nil {
		return "", "", err
	}
	var vc struct {
		WireGuard struct {
			AllowedIPs          string `json:"allowedIps"`
			PersistentKeepalive int    `json:"persistentKeepalive"`
			MTU                 int    `json:"mtu"`
		} `json:"wireGuard"`
	}
	_ = json.Unmarshal(sys.VPNConfigJSON, &vc)

	clientDNS, err := ClientDNS(sqlDB)
	if err != nil {
		return "", "", err
	}

	allowed := strings.TrimSpace(vc.WireGuard.AllowedIPs)
	if allowed == "" {
		allowed = "0.0.0.0/0, ::/0"
	}
	serverDNSHost, _ := DNSServerHost(sqlDB)
	if routePrefix := resolverHostRoutePrefix(clientDNS, serverDNSHost); routePrefix != "" {
		allowed = ensureAllowedContains(allowed, routePrefix)
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", strings.TrimSpace(privKey.String)))
	b.WriteString(fmt.Sprintf("Address = %s\n", userAddr))
	if clientDNS != "" {
		b.WriteString(fmt.Sprintf("DNS = %s\n", clientDNS))
	}
	if vc.WireGuard.MTU > 0 {
		b.WriteString(fmt.Sprintf("MTU = %d\n", vc.WireGuard.MTU))
	}
	b.WriteString("\n")
	b.WriteString("[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", strings.TrimSpace(serverPub)))
	if psk.Valid && strings.TrimSpace(psk.String) != "" {
		b.WriteString(fmt.Sprintf("PresharedKey = %s\n", strings.TrimSpace(psk.String)))
	}
	b.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", strings.TrimSpace(serverHost), serverPort))
	b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", allowed))
	if vc.WireGuard.PersistentKeepalive > 0 {
		b.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", vc.WireGuard.PersistentKeepalive))
	}
	b.WriteString("\n")

	fn := fmt.Sprintf("%s.conf", username)
	return b.String(), fn, nil
}

func ensureAllowedContains(allowed, prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return allowed
	}
	for _, part := range strings.Split(allowed, ",") {
		if strings.TrimSpace(part) == prefix {
			return allowed
		}
	}
	allowed = strings.TrimSpace(allowed)
	if allowed == "" {
		return prefix
	}
	return allowed + ", " + prefix
}

func resolverHostRoutePrefix(resolverHost, serverHost string) string {
	resolverIP := net.ParseIP(strings.TrimSpace(resolverHost))
	if resolverIP == nil {
		return ""
	}
	prefix := "/32"
	if resolverIP.To4() == nil {
		prefix = "/128"
	}
	if IsLinkLocalDNSHost(resolverHost) {
		return resolverIP.String() + prefix
	}
	serverIP := net.ParseIP(strings.TrimSpace(serverHost))
	if serverIP != nil && resolverIP.Equal(serverIP) {
		return resolverIP.String() + prefix
	}
	return ""
}

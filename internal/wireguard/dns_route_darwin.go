//go:build darwin

package wireguard

import (
	"strings"
)

func addDNSHostRoute(iface, ip string) error {
	// Link-local must be routed to utun; otherwise macOS sends 169.254.x.x out en0.
	_, err := execOut("route", "-q", "add", "-host", ip, "-interface", iface)
	if err != nil && isRouteExists(err) {
		return nil
	}
	return err
}

func removeDNSHostRoute(iface, ip string) error {
	_, err := execOut("route", "-q", "delete", "-host", ip)
	if err != nil && isRouteGone(err) {
		return nil
	}
	return err
}

func isRouteExists(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file exists") ||
		strings.Contains(msg, "already in table") ||
		strings.Contains(msg, "already exists")
}

func isRouteGone(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not in table") ||
		strings.Contains(msg, "not found")
}

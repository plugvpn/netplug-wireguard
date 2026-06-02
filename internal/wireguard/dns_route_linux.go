//go:build linux

package wireguard

import (
	"strings"
)

func addDNSHostRoute(iface, ip string) error {
	_, err := execOut("ip", "route", "replace", ip+"/32", "dev", iface, "scope", "link")
	if err != nil && isRouteExists(err) {
		return nil
	}
	return err
}

func removeDNSHostRoute(iface, ip string) error {
	_, err := execOut("ip", "route", "del", ip+"/32", "dev", iface)
	if err != nil && isRouteGone(err) {
		return nil
	}
	return err
}

func isRouteExists(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file exists") || strings.Contains(msg, "already exists")
}

func isRouteGone(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such process") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "cannot find")
}

//go:build darwin

package wireguard

import (
	"strings"
)

func addInterfaceAlias(iface, ip string) error {
	if has, err := interfaceHasIPv4(iface, ip); err != nil {
		return err
	} else if has {
		return nil
	}
	// utun is point-to-point; local and destination must both be set (wg-quick uses the same IP).
	_, err := execOut("ifconfig", iface, "inet", ip, ip, "alias")
	if err != nil && isAddrExists(err) {
		return nil
	}
	return err
}

func removeInterfaceAlias(iface, ip string) error {
	if has, err := interfaceHasIPv4(iface, ip); err != nil {
		return err
	} else if !has {
		return nil
	}
	_, err := execOut("ifconfig", iface, "inet", ip, ip, "-alias")
	if err != nil && isAddrGone(err) {
		return nil
	}
	return err
}

func interfaceHasIPv4(iface, ip string) (bool, error) {
	out, err := execOut("ifconfig", iface)
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "inet "+ip) || strings.Contains(out, ip+" --> "+ip), nil
}

func isAddrExists(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "file exists")
}

func isAddrGone(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "does not exist")
}

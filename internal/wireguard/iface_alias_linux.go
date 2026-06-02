//go:build linux

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
	_, err := execOut("ip", "-4", "addr", "add", ip+"/32", "dev", iface)
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
	_, err := execOut("ip", "-4", "addr", "del", ip+"/32", "dev", iface)
	if err != nil && isAddrGone(err) {
		return nil
	}
	return err
}

func interfaceHasIPv4(iface, ip string) (bool, error) {
	out, err := execOut("ip", "-4", "-o", "addr", "show", "dev", iface)
	if err != nil {
		return false, err
	}
	needle := "inet " + ip + "/"
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return true, nil
		}
	}
	return false, nil
}

func isAddrExists(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file exists") || strings.Contains(msg, "eexist")
}

func isAddrGone(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "cannot assign") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no such process")
}

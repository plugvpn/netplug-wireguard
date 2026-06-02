//go:build !linux && !darwin

package wireguard

func addDNSHostRoute(iface, ip string) error {
	return nil
}

func removeDNSHostRoute(iface, ip string) error {
	return nil
}

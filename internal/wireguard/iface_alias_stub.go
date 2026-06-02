//go:build !linux && !darwin

package wireguard

import "fmt"

func addInterfaceAlias(iface, ip string) error {
	return fmt.Errorf("automatic DNS interface addresses are not supported on this platform")
}

func removeInterfaceAlias(iface, ip string) error {
	return nil
}

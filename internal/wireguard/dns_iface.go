package wireguard

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"

	"netplug-go/internal/db"
)

// DNSIfaceOpts configures adding/removing a DNS resolver IP on the WireGuard interface.
type DNSIfaceOpts struct {
	DataDir             string
	ConfiguredInterface string
	SQLDB               *sql.DB
	Settings            db.DNSSettings
}

// EnsureDNSInterfaceAlias adds the resolver IP to the tunnel interface when it is not the primary server address.
func EnsureDNSInterfaceAlias(opts DNSIfaceOpts) error {
	host, needed, err := dnsAliasHost(opts)
	if err != nil {
		return err
	}
	if !needed {
		return nil
	}
	iface := ActiveWireGuardInterface(opts.DataDir, opts.ConfiguredInterface)
	if iface == "" {
		return errors.New("WireGuard interface is not running — start WireGuard before enabling DNS")
	}
	if err := addInterfaceAlias(iface, host); err != nil {
		return fmt.Errorf("add DNS address %s on %s: %w", host, iface, err)
	}
	if err := addDNSHostRoute(iface, host); err != nil {
		_ = removeInterfaceAlias(iface, host)
		return fmt.Errorf("route DNS address %s via %s: %w", host, iface, err)
	}
	log.Printf("wireguard: added DNS address %s on %s (alias + route)", host, iface)
	return nil
}

// RemoveDNSInterfaceAlias removes a dedicated resolver IP from the tunnel interface.
func RemoveDNSInterfaceAlias(opts DNSIfaceOpts) error {
	host, needed, err := dnsAliasHost(opts)
	if err != nil {
		return err
	}
	if !needed {
		return nil
	}
	iface := ActiveWireGuardInterface(opts.DataDir, opts.ConfiguredInterface)
	if iface == "" {
		return nil
	}
	_ = removeDNSHostRoute(iface, host)
	if err := removeInterfaceAlias(iface, host); err != nil {
		return fmt.Errorf("remove DNS address %s from %s: %w", host, iface, err)
	}
	log.Printf("wireguard: removed DNS address %s from %s", host, iface)
	return nil
}

func dnsAliasHost(opts DNSIfaceOpts) (host string, needed bool, err error) {
	if opts.SQLDB == nil {
		return "", false, errors.New("database is not available")
	}
	host, err = DNSResolverHost(opts.SQLDB, opts.Settings)
	if err != nil {
		return "", false, err
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", false, nil
	}
	if IsLinkLocalDNSHost(host) {
		return host, true, nil
	}
	primary, ok := TryDNSServerHost(opts.SQLDB)
	if ok && primary == host {
		return host, false, nil
	}
	return host, true, nil
}

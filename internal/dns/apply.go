package dns

import (
	"database/sql"
	"errors"
	"strings"

	"netplug-go/internal/db"
	"netplug-go/internal/wireguard"
)

// ApplyFromDB starts or stops CoreDNS from dns_settings. When enabling DNS, WireGuard must already be up.
func ApplyFromDB(m *Manager, sqlDB *sql.DB, coreDNSBin string) error {
	if m == nil {
		return errors.New("DNS service is unavailable")
	}
	if sqlDB == nil {
		return errors.New("database is not available")
	}

	dnsCfg, err := db.GetDNSSettings(sqlDB)
	if err != nil {
		return err
	}
	if strings.TrimSpace(dnsCfg.Binary) == "" {
		bin := strings.TrimSpace(coreDNSBin)
		if bin == "" {
			bin = db.DefaultDNSBinary
		}
		dnsCfg.Binary = bin
	}

	if !dnsCfg.Enabled {
		return m.Stop()
	}

	if wireguard.ActiveWireGuardInterface(m.dataDir, m.wgIface) == "" {
		return errors.New("WireGuard interface is not running — start WireGuard before enabling DNS")
	}

	if generated, err := wireguard.EnsureAutoDNSHost(sqlDB, &dnsCfg); err != nil {
		return err
	} else if generated {
		if err := db.UpsertDNSSettings(sqlDB, dnsCfg); err != nil {
			return err
		}
	}

	listen, err := wireguard.ResolveDNSListenAddress(sqlDB, dnsCfg)
	if err != nil {
		return err
	}
	dnsCfg.ListenAddr = listen

	records, err := db.ListDNSRecords(sqlDB)
	if err != nil {
		return err
	}
	rules, err := db.ListDNSDomainRules(sqlDB)
	if err != nil {
		return err
	}
	return m.Apply(dnsCfg, records, rules)
}

package wireguard

import (
	"database/sql"
	"testing"

	"netplug-go/internal/db"

	_ "github.com/mattn/go-sqlite3"
)

func TestDefaultAutoDNSHostIP(t *testing.T) {
	ip := DefaultAutoDNSHostIP()
	if ip != DefaultAutoDNSHost {
		t.Fatalf("got %q want %q", ip, DefaultAutoDNSHost)
	}
	if !IsLinkLocalDNSHost(ip) {
		t.Fatalf("expected link-local 169.254.x.x, got %q", ip)
	}
}

func TestEnsureAutoDNSHost_noWGServer(t *testing.T) {
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := db.Migrate(sqlDB); err != nil {
		t.Fatal(err)
	}
	if err := db.ApplySchemaPatches(sqlDB); err != nil {
		t.Fatal(err)
	}
	_, err = sqlDB.Exec(`
		INSERT INTO system_config (id, is_setup_complete, vpn_configuration)
		VALUES ('system', 1, '{"wireGuard":{"serverAddress":""}}')
	`)
	if err != nil {
		t.Fatal(err)
	}

	cfg := db.DNSSettings{Enabled: true, ListenPort: 53}
	generated, err := EnsureAutoDNSHost(sqlDB, &cfg)
	if err != nil || !generated || cfg.ClientDNSHost != DefaultAutoDNSHost {
		t.Fatalf("generated=%v host=%q err=%v", generated, cfg.ClientDNSHost, err)
	}

	generated2, err := EnsureAutoDNSHost(sqlDB, &cfg)
	if err != nil || generated2 {
		t.Fatalf("second ensure: generated=%v err=%v", generated2, err)
	}
	if err := db.UpsertDNSSettings(sqlDB, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := ClientDNS(sqlDB)
	if err != nil || got != DefaultAutoDNSHost {
		t.Fatalf("ClientDNS: got %q want %q err=%v", got, DefaultAutoDNSHost, err)
	}
}

func TestEnsureAutoDNSHost_generatesWhenListenBlankAndWGServerSet(t *testing.T) {
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := db.Migrate(sqlDB); err != nil {
		t.Fatal(err)
	}
	if err := db.ApplySchemaPatches(sqlDB); err != nil {
		t.Fatal(err)
	}
	_, err = sqlDB.Exec(`
		INSERT INTO system_config (id, is_setup_complete, vpn_configuration)
		VALUES ('system', 1, '{"wireGuard":{"serverAddress":"10.8.0.1/24"}}')
	`)
	if err != nil {
		t.Fatal(err)
	}

	cfg := db.DNSSettings{Enabled: true, ListenPort: 53}
	generated, err := EnsureAutoDNSHost(sqlDB, &cfg)
	if err != nil || !generated || cfg.ClientDNSHost != "10.8.0.1" {
		t.Fatalf("generated=%v host=%q err=%v", generated, cfg.ClientDNSHost, err)
	}
	if err := db.UpsertDNSSettings(sqlDB, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := ClientDNS(sqlDB)
	if err != nil || got != "10.8.0.1" {
		t.Fatalf("ClientDNS: got %q want %q err=%v", got, "10.8.0.1", err)
	}
}

func TestEnsureAutoDNSHost_migratesLegacyAutoLinkLocalToServerHost(t *testing.T) {
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := db.Migrate(sqlDB); err != nil {
		t.Fatal(err)
	}
	if err := db.ApplySchemaPatches(sqlDB); err != nil {
		t.Fatal(err)
	}
	_, err = sqlDB.Exec(`
		INSERT INTO system_config (id, is_setup_complete, vpn_configuration)
		VALUES ('system', 1, '{"wireGuard":{"serverAddress":"10.188.0.1/24"}}')
	`)
	if err != nil {
		t.Fatal(err)
	}

	cfg := db.DNSSettings{Enabled: true, ClientDNSHost: DefaultAutoDNSHost, ListenPort: 53}
	updated, err := EnsureAutoDNSHost(sqlDB, &cfg)
	if err != nil || !updated {
		t.Fatalf("updated=%v err=%v", updated, err)
	}
	if cfg.ClientDNSHost != "10.188.0.1" {
		t.Fatalf("got %q want 10.188.0.1", cfg.ClientDNSHost)
	}
}

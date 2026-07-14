package wireguard

import (
	"database/sql"
	"testing"

	"netplug-go/internal/db"

	_ "github.com/mattn/go-sqlite3"
)

func TestDNSListenAddress(t *testing.T) {
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

	cfgJSON := `{"wireGuard":{"serverAddress":"10.8.0.1/24"}}`
	_, err = sqlDB.Exec(`
		INSERT INTO system_config (id, is_setup_complete, vpn_configuration)
		VALUES ('system', 1, ?)
	`, cfgJSON)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := DNSListenAddress(sqlDB, 53)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "10.8.0.1:53" {
		t.Fatalf("got %q want 10.8.0.1:53", addr)
	}
	addr, err = DNSListenAddress(sqlDB, 5353)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "10.8.0.1:5353" {
		t.Fatalf("got %q want 10.8.0.1:5353", addr)
	}
}

func TestResolveDNSListenAddress_customHost(t *testing.T) {
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

	cfg := db.DNSSettings{ListenHost: "192.168.1.1", ListenPort: 5353}
	addr, err := ResolveDNSListenAddress(sqlDB, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "192.168.1.1:5353" {
		t.Fatalf("got %q want 192.168.1.1:5353", addr)
	}
}

func TestClientDNS_dedicatedHost(t *testing.T) {
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

	cfgJSON := `{"wireGuard":{"serverAddress":"10.8.0.1/24"}}`
	_, err = sqlDB.Exec(`
		INSERT INTO system_config (id, is_setup_complete, vpn_configuration)
		VALUES ('system', 1, ?)
	`, cfgJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertDNSSettings(sqlDB, db.DNSSettings{
		Enabled:       true,
		ClientDNSHost: "10.8.0.2",
		ListenPort:    53,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := ClientDNS(sqlDB)
	if err != nil || got != "10.8.0.2" {
		t.Fatalf("ClientDNS: got %q err=%v", got, err)
	}
	addr, err := ResolveDNSListenAddress(sqlDB, db.DNSSettings{Enabled: true, ClientDNSHost: "10.8.0.2", ListenPort: 53})
	if err != nil || addr != "10.8.0.2:53" {
		t.Fatalf("listen: got %q err=%v", addr, err)
	}
}

func TestSuggestDedicatedDNSHost(t *testing.T) {
	if got := SuggestDedicatedDNSHost("10.8.0.1"); got != "10.8.0.1" {
		t.Fatalf("got %q want %q", got, "10.8.0.1")
	}
	if got := SuggestDedicatedDNSHost(""); got != DefaultAutoDNSHost {
		t.Fatalf("got %q want %q", got, DefaultAutoDNSHost)
	}
}

func TestClientDNS_enabled(t *testing.T) {
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

	cfgJSON := `{"wireGuard":{"serverAddress":"10.8.0.1/24","dns":"1.1.1.1"}}`
	_, err = sqlDB.Exec(`
		INSERT INTO system_config (id, is_setup_complete, vpn_configuration)
		VALUES ('system', 1, ?)
	`, cfgJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertDNSSettings(sqlDB, db.DNSSettings{Enabled: true, ListenPort: 53}); err != nil {
		t.Fatal(err)
	}

	got, err := ClientDNS(sqlDB)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.8.0.1" {
		t.Fatalf("enabled DNS: got %q want 10.8.0.1", got)
	}
}

func TestClientDNS_disabled(t *testing.T) {
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

	cfgJSON := `{"wireGuard":{"serverAddress":"10.8.0.1/24","dns":"1.1.1.1, 1.0.0.1"}}`
	_, err = sqlDB.Exec(`
		INSERT INTO system_config (id, is_setup_complete, vpn_configuration)
		VALUES ('system', 1, ?)
	`, cfgJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertDNSSettings(sqlDB, db.DNSSettings{Enabled: false}); err != nil {
		t.Fatal(err)
	}

	got, err := ClientDNS(sqlDB)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1.1.1.1, 1.0.0.1" {
		t.Fatalf("disabled DNS: got %q want 1.1.1.1, 1.0.0.1", got)
	}
}

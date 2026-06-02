package wireguard

import (
	"database/sql"
	"testing"

	"netplug-go/internal/db"

	_ "github.com/mattn/go-sqlite3"
)

func TestDNSAliasHost(t *testing.T) {
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

	host, needed, err := dnsAliasHost(DNSIfaceOpts{
		SQLDB:    sqlDB,
		Settings: db.DNSSettings{Enabled: true, ListenPort: 53},
	})
	if err != nil || needed || host != "10.8.0.1" {
		t.Fatalf("primary only: host=%q needed=%v err=%v", host, needed, err)
	}

	host, needed, err = dnsAliasHost(DNSIfaceOpts{
		SQLDB:    sqlDB,
		Settings: db.DNSSettings{Enabled: true, ClientDNSHost: "10.8.0.2", ListenPort: 53},
	})
	if err != nil || !needed || host != "10.8.0.2" {
		t.Fatalf("dedicated: host=%q needed=%v err=%v", host, needed, err)
	}
}

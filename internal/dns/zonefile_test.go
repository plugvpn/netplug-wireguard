package dns

import (
	"strings"
	"testing"

	"netplug-go/internal/db"
)

func TestWriteZoneFile(t *testing.T) {
	body, err := WriteZoneFile("vpn", 300, []db.DNSRecord{
		{Name: "router", Type: "CNAME", Value: "gw.vpn", TTL: 300, Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, "$ORIGIN vpn.") {
		t.Fatalf("missing origin:\n%s", s)
	}
	if !strings.Contains(s, "router 300 IN CNAME gw.vpn.") {
		t.Fatalf("missing CNAME:\n%s", s)
	}
}

func TestWriteHostsFile(t *testing.T) {
	body := WriteHostsFile([]db.DNSRecord{
		{Name: "router.vpn", Type: "A", Value: "10.8.0.1", Enabled: true},
		{Name: "nas.vpn", Type: "A", Value: "10.8.0.1", Enabled: true},
	})
	s := string(body)
	if !strings.Contains(s, "10.8.0.1 router.vpn nas.vpn") && !strings.Contains(s, "10.8.0.1 nas.vpn router.vpn") {
		t.Fatalf("unexpected hosts:\n%s", s)
	}
}

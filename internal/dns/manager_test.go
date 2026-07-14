package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netplug-go/internal/db"
)

func TestSplitListenAddr(t *testing.T) {
	host, port, err := splitListenAddr("0.0.0.0:53")
	if err != nil || host != "0.0.0.0" || port != "53" {
		t.Fatalf("got %q %q err=%v", host, port, err)
	}
	host, port, err = splitListenAddr(":53")
	if err != nil || host != "0.0.0.0" || port != "53" {
		t.Fatalf(":53: got %q %q err=%v", host, port, err)
	}
}

func TestResolveCoreDNSBinary(t *testing.T) {
	path, err := resolveCoreDNSBinary("")
	if err == nil || path != "" {
		t.Fatalf("empty name: got %q err=%v", path, err)
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "coredns-test")
	if err := os.WriteFile(fake, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	path, err = resolveCoreDNSBinary(fake)
	if err != nil || path != fake {
		t.Fatalf("absolute path: got %q err=%v", path, err)
	}
}

func TestRenderCorefile(t *testing.T) {
	cfg := db.DNSSettings{ForwardUpstreams: "1.1.1.1", CacheTTL: 300}
	body := renderCorefile("0.0.0.0", "53", cfg, zoneFiles{})
	if body == "" || !strings.Contains(body, ".:53") || !strings.Contains(body, "1.1.1.1") {
		t.Fatalf("unexpected corefile:\n%s", body)
	}
	zoneFile := filepath.Join(t.TempDir(), "vpn.db")
	hosts := filepath.Join(t.TempDir(), "hosts.db")
	cfg.QueryLogEnabled = true
	body = renderCorefile("10.8.0.1", "53", cfg, zoneFiles{
		blockHosts:   hosts,
		rewriteHosts: hosts,
		zoneBlocks:   []rewriteZone{{zone: "vpn", file: zoneFile}},
	})
	if !strings.Contains(body, ".:53") || !strings.Contains(body, "vpn:53") || !strings.Contains(body, "bind 10.8.0.1") || !strings.Contains(body, "log") {
		t.Fatalf("unexpected corefile for server IP:\n%s", body)
	}
	body = renderCorefile("169.254.20.10", "53", cfg, zoneFiles{})
	if !strings.Contains(body, ".:53") || !strings.Contains(body, "bind 169.254.20.10") {
		t.Fatalf("expected link-local listen in corefile:\n%s", body)
	}
}

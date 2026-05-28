package wireguard

import (
	"strings"
	"testing"
)

func TestCleanWGQuickStripOutput_removesWarnings(t *testing.T) {
	raw := "Warning: `/data/wg0.conf' is world accessible\n\n[Peer]\nPublicKey = abc\nAllowedIPs = 10.0.0.2/32\n"
	got := cleanWGQuickStripOutput(raw)
	if strings.Contains(got, "Warning:") {
		t.Fatalf("expected warning stripped, got %q", got)
	}
	if !strings.Contains(got, "[Peer]") {
		t.Fatalf("expected peer config kept, got %q", got)
	}
}

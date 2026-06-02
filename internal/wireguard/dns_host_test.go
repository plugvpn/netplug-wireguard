package wireguard

import "testing"

func TestNormalizeDNSHost(t *testing.T) {
	host, err := NormalizeDNSHost("10.8.0.1/24")
	if err != nil || host != "10.8.0.1" {
		t.Fatalf("cidr: got %q err=%v", host, err)
	}
	host, err = NormalizeDNSHost("10.8.0.2")
	if err != nil || host != "10.8.0.2" {
		t.Fatalf("ip: got %q err=%v", host, err)
	}
	_, err = NormalizeDNSHost("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid host")
	}
}

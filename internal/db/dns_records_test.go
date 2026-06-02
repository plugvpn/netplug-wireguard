package db

import (
	"testing"
)

func TestValidateDNSRewrite(t *testing.T) {
	cases := []struct {
		rec DNSRecord
		ok  bool
	}{
		{DNSRecord{Name: "router.vpn", Type: "A", Value: "10.8.0.1"}, true},
		{DNSRecord{Name: "router", Type: "A", Value: "10.8.0.1"}, false},
		{DNSRecord{Name: "x.vpn", Type: "A", Value: "not-ip"}, false},
		{DNSRecord{Name: "x.vpn", Type: "AAAA", Value: "2001:db8::1"}, true},
		{DNSRecord{Name: "alias.vpn", Type: "CNAME", Value: "router.vpn"}, true},
		{DNSRecord{Name: "x.vpn", Type: "MX", Value: "10 mail.vpn"}, true},
		{DNSRecord{Name: "x.vpn", Type: "BOGUS", Value: "x"}, false},
	}
	for _, tc := range cases {
		err := ValidateDNSRewrite(tc.rec)
		if tc.ok && err != nil {
			t.Errorf("%+v: expected ok, got %v", tc.rec, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%+v: expected error", tc.rec)
		}
	}
}

func TestSplitRewriteDomain(t *testing.T) {
	zone, owner := SplitRewriteDomain("router.vpn")
	if zone != "vpn" || owner != "router" {
		t.Fatalf("router.vpn: got zone=%q owner=%q", zone, owner)
	}
	zone, owner = SplitRewriteDomain("mail.router.vpn")
	if zone != "router.vpn" || owner != "mail" {
		t.Fatalf("mail.router.vpn: got zone=%q owner=%q", zone, owner)
	}
}

func TestNormalizeDNSRewriteDomain(t *testing.T) {
	if got := NormalizeDNSRewriteDomain("Router.VPN."); got != "router.vpn" {
		t.Fatalf("got %q", got)
	}
}

package wireguard

import "testing"

func TestResolverHostRoutePrefix(t *testing.T) {
	tests := []struct {
		name       string
		resolver   string
		serverHost string
		want       string
	}{
		{name: "link local resolver", resolver: "169.254.20.10", serverHost: "10.8.0.1", want: "169.254.20.10/32"},
		{name: "server resolver", resolver: "10.188.0.1", serverHost: "10.188.0.1", want: "10.188.0.1/32"},
		{name: "non server resolver", resolver: "10.188.0.2", serverHost: "10.188.0.1", want: ""},
		{name: "ipv6 server resolver", resolver: "fd00::1", serverHost: "fd00::1", want: "fd00::1/128"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolverHostRoutePrefix(tt.resolver, tt.serverHost)
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

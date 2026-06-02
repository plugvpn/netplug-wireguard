package dns

import (
	"bytes"
	"fmt"
	"strings"

	"netplug-go/internal/db"
)

// WriteHostsFile renders a CoreDNS hosts file for A/AAAA rewrites.
func WriteHostsFile(records []db.DNSRecord) []byte {
	ipToNames := make(map[string][]string)
	for _, r := range records {
		if !r.Enabled {
			continue
		}
		recType := strings.ToUpper(strings.TrimSpace(r.Type))
		if recType != "A" && recType != "AAAA" {
			continue
		}
		domain := db.NormalizeDNSRewriteDomain(r.Name)
		if domain == "" {
			continue
		}
		ip := strings.TrimSpace(r.Value)
		ipToNames[ip] = append(ipToNames[ip], domain)
	}
	var buf bytes.Buffer
	for ip, names := range ipToNames {
		fmt.Fprintf(&buf, "%s %s\n", ip, strings.Join(names, " "))
	}
	return buf.Bytes()
}

package dns

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"

	"netplug-go/internal/db"
)

// WriteZoneFile renders an RFC1035 zone file for CoreDNS file plugin.
func WriteZoneFile(zone string, defaultTTL int, records []db.DNSRecord) ([]byte, error) {
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if defaultTTL <= 0 {
		defaultTTL = db.DefaultDNSRewriteTTL
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "$ORIGIN %s.\n", zone)
	fmt.Fprintf(&buf, "$TTL %d\n\n", defaultTTL)

	wrote := 0
	for _, r := range records {
		if !r.Enabled {
			continue
		}
		line, err := formatZoneLine(zone, defaultTTL, r)
		if err != nil {
			return nil, err
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
		wrote++
	}
	if wrote == 0 {
		fmt.Fprintf(&buf, "@ %d IN SOA %s. hostadmin.%s. ( 1 7200 3600 86400 300 )\n", defaultTTL, zone, zone)
	}
	return buf.Bytes(), nil
}

func formatZoneLine(zone string, defaultTTL int, r db.DNSRecord) (string, error) {
	name := strings.TrimSpace(r.Name)
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		name = "@"
	}
	recType, err := db.NormalizeDNSRecordType(r.Type)
	if err != nil {
		return "", err
	}
	ttl := r.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	value := strings.TrimSpace(r.Value)

	switch recType {
	case "A":
		ip := canonicalIP(value, true)
		return fmt.Sprintf("%s %d IN A %s", name, ttl, ip), nil
	case "AAAA":
		ip := canonicalIP(value, false)
		return fmt.Sprintf("%s %d IN AAAA %s", name, ttl, ip), nil
	case "TXT":
		return fmt.Sprintf("%s %d IN TXT %s", name, ttl, formatTXT(value)), nil
	case "MX":
		prio, host, err := formatMX(value, zone)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s %d IN MX %d %s", name, ttl, prio, host), nil
	case "CNAME", "NS", "PTR":
		host, err := formatHostRdata(value, zone)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s %d IN %s %s", name, ttl, recType, host), nil
	default:
		return "", fmt.Errorf("unsupported record type %s", recType)
	}
}

func canonicalIP(value string, v4 bool) string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return strings.TrimSpace(value)
	}
	if v4 {
		return ip.To4().String()
	}
	return ip.String()
}

func formatTXT(value string) string {
	if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
		return value
	}
	escaped := strings.ReplaceAll(value, `\"`, `\\"`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

func formatMX(value, zone string) (prio int, host string, err error) {
	parts := strings.Fields(value)
	if len(parts) < 2 {
		return 0, "", fmt.Errorf("MX value must be priority and hostname")
	}
	prio, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", err
	}
	host, err = formatHostRdata(strings.Join(parts[1:], " "), zone)
	return prio, host, err
}

func formatHostRdata(value, zone string) (string, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, ".")
	if value == "" || value == "@" {
		return strings.TrimSuffix(zone, ".") + ".", nil
	}
	if strings.Contains(value, ".") {
		return value + ".", nil
	}
	return value + "." + strings.TrimSuffix(zone, ".") + ".", nil
}

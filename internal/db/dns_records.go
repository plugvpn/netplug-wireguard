package db

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

// DefaultDNSRewriteTTL is the default TTL for custom DNS rewrites.
const DefaultDNSRewriteTTL = 300

// DNSRecordTypes lists record types manageable in the UI (CoreDNS file plugin).
var DNSRecordTypes = []string{"A", "AAAA", "CNAME", "TXT", "PTR", "MX", "NS"}

// DNSRecord is a custom DNS rewrite (full domain name → record data).
type DNSRecord struct {
	ID      string
	Name    string
	Type    string
	Value   string
	TTL     int
	Enabled bool
}

func newDNSRecordID() string {
	return uuid.NewString()
}

// NormalizeDNSRewriteDomain lowercases and trims a rewrite domain (FQDN).
func NormalizeDNSRewriteDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}

// SplitRewriteDomain splits a rewrite FQDN into authoritative zone and owner name.
func SplitRewriteDomain(fqdn string) (zone, owner string) {
	fqdn = NormalizeDNSRewriteDomain(fqdn)
	if fqdn == "" {
		return "", ""
	}
	labels := strings.Split(fqdn, ".")
	if len(labels) == 1 {
		return fqdn, "@"
	}
	if len(labels) == 2 {
		return labels[1], labels[0]
	}
	return strings.Join(labels[1:], "."), labels[0]
}

// NormalizeDNSRecordType uppercases and validates against DNSRecordTypes.
func NormalizeDNSRecordType(t string) (string, error) {
	t = strings.ToUpper(strings.TrimSpace(t))
	for _, allowed := range DNSRecordTypes {
		if t == allowed {
			return t, nil
		}
	}
	return "", fmt.Errorf("unsupported record type %q (use A, AAAA, CNAME, TXT, PTR, MX, or NS)", t)
}

// ValidateDNSRewrite checks domain, type, value, and TTL for a custom rewrite.
func ValidateDNSRewrite(r DNSRecord) error {
	domain := NormalizeDNSRewriteDomain(r.Name)
	if domain == "" {
		return errors.New("domain is required")
	}
	if !strings.Contains(domain, ".") {
		return errors.New("enter a full domain name (e.g. router.vpn)")
	}
	if err := validateRewriteDomainLabels(domain); err != nil {
		return err
	}
	zone, _ := SplitRewriteDomain(domain)
	recType, err := NormalizeDNSRecordType(r.Type)
	if err != nil {
		return err
	}
	value := strings.TrimSpace(r.Value)
	if value == "" {
		return errors.New("record value is required")
	}
	ttl := r.TTL
	if ttl <= 0 {
		ttl = DefaultDNSRewriteTTL
	}
	if ttl > 2147483647 {
		return errors.New("TTL is too large")
	}

	switch recType {
	case "A":
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("A record value must be an IPv4 address, got %q", value)
		}
	case "AAAA":
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("AAAA record value must be an IPv6 address, got %q", value)
		}
	case "CNAME", "NS", "PTR":
		if err := validateDNSHostname(value, zone, recType == "PTR"); err != nil {
			return err
		}
	case "TXT":
		if len(value) > 4096 {
			return errors.New("TXT record value is too long")
		}
	case "MX":
		if err := validateMXValue(value, zone); err != nil {
			return err
		}
	}

	_ = ttl
	return nil
}

func validateRewriteDomainLabels(domain string) error {
	for _, label := range strings.Split(domain, ".") {
		if err := validateDNSLabel(label); err != nil {
			return fmt.Errorf("invalid domain %q", domain)
		}
	}
	return nil
}

func validateMXValue(value, zone string) error {
	parts := strings.Fields(value)
	if len(parts) < 2 {
		return errors.New("MX value must be priority and hostname (e.g. 10 mail)")
	}
	prio, err := strconv.Atoi(parts[0])
	if err != nil || prio < 0 || prio > 65535 {
		return errors.New("MX priority must be a number from 0 to 65535")
	}
	return validateDNSHostname(strings.Join(parts[1:], " "), zone, false)
}

func validateDNSHostname(host, zone string, allowReverse bool) error {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return errors.New("hostname is required")
	}
	if allowReverse && strings.Count(host, ".") >= 1 {
		labels := strings.Split(host, ".")
		for _, label := range labels {
			if label == "" {
				return errors.New("invalid hostname")
			}
		}
		return nil
	}
	labels := strings.Split(host, ".")
	if len(labels) == 1 {
		label := labels[0]
		if label == "@" {
			return nil
		}
		return validateDNSLabel(label)
	}
	for _, label := range labels {
		if label == "" {
			return errors.New("invalid hostname")
		}
		if err := validateDNSLabel(label); err != nil {
			return err
		}
	}
	_ = zone
	return nil
}

func validateDNSLabel(label string) error {
	if label == "" || len(label) > 63 {
		return fmt.Errorf("invalid DNS label %q", label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("invalid DNS label %q", label)
	}
	for _, r := range label {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
			continue
		}
		return fmt.Errorf("invalid DNS label %q", label)
	}
	return nil
}

func ListDNSRecords(dbConn *sql.DB) ([]DNSRecord, error) {
	if dbConn == nil {
		return nil, errors.New("db is nil")
	}
	rows, err := dbConn.Query(`
		SELECT id, name, record_type, value, ttl, enabled
		FROM dns_records
		ORDER BY lower(name), record_type, value
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSRecord
	for rows.Next() {
		var r DNSRecord
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Value, &r.TTL, &enabled); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func InsertDNSRecord(dbConn *sql.DB, r DNSRecord) (DNSRecord, error) {
	if dbConn == nil {
		return DNSRecord{}, errors.New("db is nil")
	}
	if strings.TrimSpace(r.ID) == "" {
		r.ID = newDNSRecordID()
	}
	r.Name = NormalizeDNSRewriteDomain(r.Name)
	recType, err := NormalizeDNSRecordType(r.Type)
	if err != nil {
		return DNSRecord{}, err
	}
	r.Type = recType
	r.Value = strings.TrimSpace(r.Value)
	if r.TTL <= 0 {
		r.TTL = DefaultDNSRewriteTTL
	}
	enabled := 1
	if !r.Enabled {
		enabled = 0
	}
	_, err = dbConn.Exec(`
		INSERT INTO dns_records (id, name, record_type, value, ttl, enabled)
		VALUES (?, ?, ?, ?, ?, ?)
	`, r.ID, r.Name, r.Type, r.Value, r.TTL, enabled)
	if err != nil {
		return DNSRecord{}, err
	}
	r.Enabled = enabled != 0
	return r, nil
}

func DeleteDNSRecord(dbConn *sql.DB, id string) error {
	if dbConn == nil {
		return errors.New("db is nil")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("record id is required")
	}
	res, err := dbConn.Exec(`DELETE FROM dns_records WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

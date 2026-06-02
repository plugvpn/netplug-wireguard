package db

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/google/uuid"
)

// Default blocklist (StevenBlack unified hosts — ads + malware).
const DefaultDNSBlocklistURL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

// DefaultDNSBlockAddress is returned for blocked domains.
const DefaultDNSBlockAddress = "0.0.0.0"

// DefaultDNSCacheTTL is the CoreDNS cache plugin TTL in seconds.
const DefaultDNSCacheTTL = 300

// DNS upstream presets (x-ui / Marzban style quick picks).
var DNSUpstreamPresets = []struct {
	ID    string
	Label string
	Value string
}{
	{"cloudflare", "Cloudflare (1.1.1.1)", "1.1.1.1 1.0.0.1"},
	{"cloudflare-malware", "Cloudflare malware (1.1.1.2)", "1.1.1.2 1.0.0.2"},
	{"cloudflare-family", "Cloudflare family (1.1.1.3)", "1.1.1.3 1.0.0.3"},
	{"google", "Google (8.8.8.8)", "8.8.8.8 8.8.4.4"},
	{"quad9", "Quad9 secure (9.9.9.9)", "9.9.9.9 149.112.112.112"},
	{"shecan", "Shecan (Iran)", "178.22.122.100 185.51.200.2"},
	{"opendns", "OpenDNS (208.67.222.222)", "208.67.222.222 208.67.220.220"},
}

// DNSDomainRule is a manual block or allow exception.
type DNSDomainRule struct {
	ID       string
	Domain   string
	RuleType string // block | allow
	Enabled  bool
}

func newDNSDomainRuleID() string {
	return uuid.NewString()
}

// NormalizeDNSDomainRule normalizes a domain for block/allow lists.
func NormalizeDNSDomainRule(domain string) string {
	return NormalizeDNSRewriteDomain(domain)
}

// ValidateDNSDomainRule validates a block/allow domain rule.
func ValidateDNSDomainRule(rule DNSDomainRule) error {
	domain := NormalizeDNSDomainRule(rule.Domain)
	if domain == "" {
		return errors.New("domain is required")
	}
	if !strings.Contains(domain, ".") {
		return errors.New("enter a full domain name (e.g. ads.example.com)")
	}
	if err := validateRewriteDomainLabels(domain); err != nil {
		return err
	}
	t := strings.ToLower(strings.TrimSpace(rule.RuleType))
	if t != "block" && t != "allow" {
		return errors.New("rule type must be block or allow")
	}
	return nil
}

func ListDNSDomainRules(dbConn *sql.DB) ([]DNSDomainRule, error) {
	if dbConn == nil {
		return nil, errors.New("db is nil")
	}
	rows, err := dbConn.Query(`
		SELECT id, domain, rule_type, enabled
		FROM dns_domain_rules
		ORDER BY rule_type, lower(domain)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSDomainRule
	for rows.Next() {
		var r DNSDomainRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Domain, &r.RuleType, &enabled); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func InsertDNSDomainRule(dbConn *sql.DB, r DNSDomainRule) (DNSDomainRule, error) {
	if dbConn == nil {
		return DNSDomainRule{}, errors.New("db is nil")
	}
	if strings.TrimSpace(r.ID) == "" {
		r.ID = newDNSDomainRuleID()
	}
	r.Domain = NormalizeDNSDomainRule(r.Domain)
	r.RuleType = strings.ToLower(strings.TrimSpace(r.RuleType))
	if err := ValidateDNSDomainRule(r); err != nil {
		return DNSDomainRule{}, err
	}
	enabled := 1
	if !r.Enabled {
		enabled = 0
	}
	_, err := dbConn.Exec(`
		INSERT INTO dns_domain_rules (id, domain, rule_type, enabled)
		VALUES (?, ?, ?, ?)
	`, r.ID, r.Domain, r.RuleType, enabled)
	if err != nil {
		return DNSDomainRule{}, err
	}
	r.Enabled = enabled != 0
	return r, nil
}

func DeleteDNSDomainRule(dbConn *sql.DB, id string) error {
	if dbConn == nil {
		return errors.New("db is nil")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("rule id is required")
	}
	res, err := dbConn.Exec(`DELETE FROM dns_domain_rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ParseBlocklistURLs splits newline/space-separated blocklist URLs.
func ParseBlocklistURLs(raw string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' '
	}) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

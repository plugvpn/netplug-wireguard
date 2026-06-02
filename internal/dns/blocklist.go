package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netplug-go/internal/db"
)

const blocklistFetchTimeout = 45 * time.Second

// WriteBlockHostsFile builds a CoreDNS hosts file for blocked domains.
func WriteBlockHostsFile(blockIP string, domains []string) []byte {
	blockIP = strings.TrimSpace(blockIP)
	if blockIP == "" {
		blockIP = db.DefaultDNSBlockAddress
	}
	var buf bytes.Buffer
	seen := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = db.NormalizeDNSDomainRule(d)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		fmt.Fprintf(&buf, "%s %s\n", blockIP, d)
	}
	return buf.Bytes()
}

// CollectBlockedDomains merges blocklists, manual blocks, and subtracts allowlist.
func CollectBlockedDomains(cfg db.DNSSettings, rules []db.DNSDomainRule, dataDir string) ([]string, error) {
	allow := make(map[string]struct{})
	block := make(map[string]struct{})

	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		d := db.NormalizeDNSDomainRule(r.Domain)
		if d == "" {
			continue
		}
		switch strings.ToLower(r.RuleType) {
		case "allow":
			allow[d] = struct{}{}
		case "block":
			block[d] = struct{}{}
		}
	}

	if cfg.BlockAdsEnabled {
		urls := db.ParseBlocklistURLs(cfg.BlocklistURLs)
		if len(urls) == 0 {
			urls = []string{db.DefaultDNSBlocklistURL}
		}
		fetched, err := loadBlocklistDomains(dataDir, urls)
		if err != nil {
			return nil, err
		}
		for _, d := range fetched {
			block[d] = struct{}{}
		}
	}

	out := make([]string, 0, len(block))
	for d := range block {
		if _, ok := allow[d]; ok {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

func loadBlocklistDomains(dataDir string, urls []string) ([]string, error) {
	domains := make(map[string]struct{})
	for _, u := range urls {
		body, err := fetchBlocklist(u, dataDir)
		if err != nil {
			return nil, fmt.Errorf("blocklist %q: %w", u, err)
		}
		for _, d := range parseHostsDomains(body) {
			domains[d] = struct{}{}
		}
	}
	out := make([]string, 0, len(domains))
	for d := range domains {
		out = append(out, d)
	}
	return out, nil
}

func fetchBlocklist(url, dataDir string) ([]byte, error) {
	cachePath := blocklistCachePath(dataDir, url)
	cached, _ := os.ReadFile(cachePath)
	if len(cached) > 0 {
		if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) < 24*time.Hour {
			return cached, nil
		}
	}

	client := &http.Client{Timeout: blocklistFetchTimeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		if len(cached) > 0 {
			return cached, nil
		}
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		if len(cached) > 0 {
			return cached, nil
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if len(cached) > 0 {
			return cached, nil
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		if len(cached) > 0 {
			return cached, nil
		}
		return nil, err
	}
	_ = os.MkdirAll(filepath.Dir(cachePath), 0o755)
	_ = os.WriteFile(cachePath, body, 0o644)
	return body, nil
}

func blocklistCachePath(dataDir, url string) string {
	safe := strings.NewReplacer("://", "_", "/", "_", "?", "_").Replace(url)
	return filepath.Join(dataDir, "dns", "blocklist-cache", safe)
}

func parseHostsDomains(body []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::" || ip == "::1" {
			for _, host := range fields[1:] {
				host = strings.TrimSpace(host)
				if host == "" || host == "localhost" {
					continue
				}
				host = db.NormalizeDNSDomainRule(host)
				if strings.Contains(host, ".") {
					out = append(out, host)
				}
			}
		}
	}
	return out
}

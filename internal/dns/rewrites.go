package dns

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"netplug-go/internal/db"
)

type rewriteZone struct {
	zone string
	file string
}

type zoneFiles struct {
	blockHosts    string
	rewriteHosts  string
	zoneBlocks    []rewriteZone
}

// prepareZoneFiles writes block hosts, rewrite hosts, and per-zone files for CoreDNS.
func prepareZoneFiles(dir string, cfg db.DNSSettings, records []db.DNSRecord, rules []db.DNSDomainRule, dataDir string) (zoneFiles, error) {
	var out zoneFiles
	zonesDir := filepath.Join(dir, "zones")
	if err := os.MkdirAll(zonesDir, 0o755); err != nil {
		return out, err
	}

	blocked, err := CollectBlockedDomains(cfg, rules, dataDir)
	if err != nil {
		return out, err
	}
	blockBody := WriteBlockHostsFile(cfg.BlockAddress, blocked)
	if len(blockBody) > 0 {
		blockPath := filepath.Join(dir, "block.db")
		if err := os.WriteFile(blockPath, blockBody, 0o644); err != nil {
			return out, err
		}
		out.blockHosts = blockPath
	}

	rewriteHosts, zoneBlocks, err := prepareRewriteZones(dir, records)
	if err != nil {
		return out, err
	}
	out.rewriteHosts = rewriteHosts
	out.zoneBlocks = zoneBlocks
	return out, nil
}

// prepareRewriteZones writes hosts and per-zone files for DNS rewrites.
func prepareRewriteZones(dir string, records []db.DNSRecord) (hostsFile string, zoneBlocks []rewriteZone, err error) {
	zonesDir := filepath.Join(dir, "zones")
	if err := os.MkdirAll(zonesDir, 0o755); err != nil {
		return "", nil, err
	}

	hostsPath := filepath.Join(dir, "hosts.db")
	hostsBody := WriteHostsFile(records)
	if len(hostsBody) > 0 {
		if err := os.WriteFile(hostsPath, hostsBody, 0o644); err != nil {
			return "", nil, err
		}
		hostsFile = hostsPath
	}

	byZone := make(map[string][]db.DNSRecord)
	for _, r := range records {
		if !r.Enabled {
			continue
		}
		recType := strings.ToUpper(strings.TrimSpace(r.Type))
		if recType == "A" || recType == "AAAA" {
			continue
		}
		zone, owner := db.SplitRewriteDomain(r.Name)
		if zone == "" {
			continue
		}
		r.Name = owner
		byZone[zone] = append(byZone[zone], r)
	}

	zones := make([]string, 0, len(byZone))
	for z := range byZone {
		zones = append(zones, z)
	}
	sort.Strings(zones)

	for _, zone := range zones {
		recs := byZone[zone]
		zoneFile := filepath.Join(zonesDir, zone+".db")
		body, err := WriteZoneFile(zone, db.DefaultDNSRewriteTTL, recs)
		if err != nil {
			return "", nil, err
		}
		if err := os.WriteFile(zoneFile, body, 0o644); err != nil {
			return "", nil, err
		}
		zoneBlocks = append(zoneBlocks, rewriteZone{zone: zone, file: zoneFile})
	}
	return hostsFile, zoneBlocks, nil
}

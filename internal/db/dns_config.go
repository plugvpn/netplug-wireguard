package db

import (
	"database/sql"
	"errors"
	"strings"
)

const dnsSettingsRowID = "default"

// DefaultDNSListenPort is the CoreDNS listen port when unset.
const DefaultDNSListenPort = 53

// DefaultDNSBinary is the CoreDNS executable name or path when unset.
const DefaultDNSBinary = "coredns"

// DNSSettings holds admin DNS / CoreDNS options (single-row table).
type DNSSettings struct {
	Enabled          bool
	ClientDNSHost    string // IP peers use in DNS= (configs/QR); may differ from ListenHost
	ListenHost       string
	ListenAddr       string // computed host:port for display/runtime
	ListenPort       int
	Binary           string
	ForwardUpstreams string
	BlockAdsEnabled  bool
	BlocklistURLs    string
	BlockAddress     string
	CacheTTL         int
	QueryLogEnabled  bool
}

func DefaultDNSSettings() DNSSettings {
	return DNSSettings{
		Enabled:          false,
		ListenAddr:       "",
		ListenPort:       DefaultDNSListenPort,
		Binary:           DefaultDNSBinary,
		ForwardUpstreams: "1.1.1.1 1.0.0.1",
		BlockAddress:     DefaultDNSBlockAddress,
		CacheTTL:         DefaultDNSCacheTTL,
	}
}

func GetDNSSettings(dbConn *sql.DB) (DNSSettings, error) {
	if dbConn == nil {
		return DNSSettings{}, errors.New("db is nil")
	}
	def := DefaultDNSSettings()
	var enabled int
	var listenPort int
	var clientDNSHost, listenHost, listen, upstreams, binary, blocklistURLs, blockAddress string
	var blockAds, queryLog int
	var cacheTTL int
	err := dbConn.QueryRow(`
		SELECT enabled, COALESCE(client_dns_host, ''), COALESCE(listen_host, ''), listen_addr, COALESCE(listen_port, 53), COALESCE(core_dns_bin, 'coredns'), forward_upstreams,
		       COALESCE(block_ads_enabled, 0), COALESCE(blocklist_urls, ''), COALESCE(block_address, '0.0.0.0'),
		       COALESCE(cache_ttl, 300), COALESCE(query_log_enabled, 0)
		FROM dns_settings
		WHERE id = ?
		LIMIT 1
	`, dnsSettingsRowID).Scan(&enabled, &clientDNSHost, &listenHost, &listen, &listenPort, &binary, &upstreams, &blockAds, &blocklistURLs, &blockAddress, &cacheTTL, &queryLog)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return def, nil
		}
		return DNSSettings{}, err
	}
	def.Enabled = enabled != 0
	if listenPort > 0 {
		def.ListenPort = listenPort
	}
	if strings.TrimSpace(clientDNSHost) != "" {
		def.ClientDNSHost = strings.TrimSpace(clientDNSHost)
	}
	if strings.TrimSpace(listenHost) != "" {
		def.ListenHost = strings.TrimSpace(listenHost)
	}
	if strings.TrimSpace(listen) != "" {
		def.ListenAddr = strings.TrimSpace(listen)
	}
	if strings.TrimSpace(binary) != "" {
		def.Binary = strings.TrimSpace(binary)
	}
	if strings.TrimSpace(upstreams) != "" {
		def.ForwardUpstreams = strings.TrimSpace(upstreams)
	}
	def.BlockAdsEnabled = blockAds != 0
	if strings.TrimSpace(blocklistURLs) != "" {
		def.BlocklistURLs = strings.TrimSpace(blocklistURLs)
	}
	if strings.TrimSpace(blockAddress) != "" {
		def.BlockAddress = strings.TrimSpace(blockAddress)
	}
	if cacheTTL > 0 {
		def.CacheTTL = cacheTTL
	}
	def.QueryLogEnabled = queryLog != 0
	return def, nil
}

func UpsertDNSSettings(dbConn *sql.DB, s DNSSettings) error {
	if dbConn == nil {
		return errors.New("db is nil")
	}
	clientDNSHost := strings.TrimSpace(s.ClientDNSHost)
	listenHost := strings.TrimSpace(s.ListenHost)
	upstreams := strings.TrimSpace(s.ForwardUpstreams)
	if upstreams == "" {
		upstreams = DefaultDNSSettings().ForwardUpstreams
	}
	port := s.ListenPort
	if port <= 0 {
		port = DefaultDNSListenPort
	}
	binary := strings.TrimSpace(s.Binary)
	if binary == "" {
		binary = DefaultDNSBinary
	}
	blockAddr := strings.TrimSpace(s.BlockAddress)
	if blockAddr == "" {
		blockAddr = DefaultDNSBlockAddress
	}
	cacheTTL := s.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = DefaultDNSCacheTTL
	}
	_, err := dbConn.Exec(`
		INSERT INTO dns_settings (id, enabled, client_dns_host, listen_host, listen_addr, listen_port, core_dns_bin, forward_upstreams,
		                         block_ads_enabled, blocklist_urls, block_address, cache_ttl, query_log_enabled)
		VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		  enabled = excluded.enabled,
		  client_dns_host = excluded.client_dns_host,
		  listen_host = excluded.listen_host,
		  listen_addr = '',
		  listen_port = excluded.listen_port,
		  core_dns_bin = excluded.core_dns_bin,
		  forward_upstreams = excluded.forward_upstreams,
		  block_ads_enabled = excluded.block_ads_enabled,
		  blocklist_urls = excluded.blocklist_urls,
		  block_address = excluded.block_address,
		  cache_ttl = excluded.cache_ttl,
		  query_log_enabled = excluded.query_log_enabled,
		  updated_at = datetime('now')
	`, dnsSettingsRowID, boolInt(s.Enabled), clientDNSHost, listenHost, port, binary, upstreams,
		boolInt(s.BlockAdsEnabled), strings.TrimSpace(s.BlocklistURLs), blockAddr, cacheTTL, boolInt(s.QueryLogEnabled))
	return err
}

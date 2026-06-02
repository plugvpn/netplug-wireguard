package app

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	HTTPAddr     string
	DataDir      string
	DBPath       string
	CookieSecure bool
	WGInterface  string
	WGInterval   int  // seconds
	PCQDisabled  bool // NETPLUG_PCQ_DISABLE removes tc shaping managed by NetPlug
	Debug        bool // NETPLUG_DEBUG enables JSON structured debug logs (e.g. PCQ tc apply)
	CoreDNSBin   string // COREDNS_BIN path or name on PATH (default: coredns)

	ProjectRoot string
}

func LoadConfig() (Config, error) {
	root, err := os.Getwd()
	if err != nil {
		return Config{}, err
	}

	httpAddr := env("HTTP_ADDR", ":8080")
	dataDir := env("DATA_DIR", filepath.Join(root, "sandbox", "data"))
	dbPath := env("SQLITE_PATH", filepath.Join(dataDir, "netplug.sqlite"))

	cookieSecure := false
	if v := os.Getenv("COOKIE_SECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, errors.New("COOKIE_SECURE must be true/false")
		}
		cookieSecure = b
	}

	wgIface := env("WG_INTERFACE", "wg0")
	pcqDisable := envBoolFlexible("NETPLUG_PCQ_DISABLE", false)
	debug := envBoolFlexible("NETPLUG_DEBUG", false)

	wgInterval := 30
	if v := os.Getenv("WIREGUARD_SYNC_INTERVAL_SEC"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, errors.New("WIREGUARD_SYNC_INTERVAL_SEC must be a positive integer")
		}
		wgInterval = n
	}

	return Config{
		HTTPAddr:     httpAddr,
		DataDir:      dataDir,
		DBPath:       dbPath,
		CookieSecure: cookieSecure,
		WGInterface:  wgIface,
		WGInterval:   wgInterval,
		PCQDisabled:  pcqDisable,
		Debug:        debug,
		CoreDNSBin:   env("COREDNS_BIN", "coredns"),
		ProjectRoot:  root,
	}, nil
}

func (c Config) DatabaseDSN() string {
	// mattn/go-sqlite3 DSN with pragmas.
	// WAL + busy_timeout keeps the UI snappy while sync writes happen.
	return c.DBPath + "?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on"
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBoolFlexible(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch v {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fallback
		}
		return b
	}
}

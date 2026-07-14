package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"netplug-go/internal/db"
	"netplug-go/internal/dns"
	"netplug-go/internal/version"
	"netplug-go/internal/view"
	"netplug-go/internal/wireguard"

	"github.com/go-chi/chi/v5"
)

type Handlers struct {
	svc *Services
}

const maxSetupUploadBytes = 10 << 20 // 10MB

func NewHandlers(svc *Services) *Handlers {
	return &Handlers{svc: svc}
}

func (h *Handlers) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.isSetupComplete() && r.URL.Path != "/setup" && !strings.HasPrefix(r.URL.Path, "/setup/") {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}
		userID := h.svc.Sessions.GetString(r.Context(), "user_id")
		if userID == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handlers) isSetupComplete() bool {
	cfg, err := db.GetSystemConfig(h.svc.DB)
	if err != nil {
		return false
	}
	return cfg.IsSetupComplete
}

func (h *Handlers) LoginPage(w http.ResponseWriter, r *http.Request) {
	if !h.isSetupComplete() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	view.Render(w, r, "login.tmpl", view.M{
		"Title": "Login",
	})
}

func (h *Handlers) LoginPost(w http.ResponseWriter, r *http.Request) {
	if !h.isSetupComplete() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || password == "" {
		view.Render(w, r, "login.tmpl", view.M{
			"Title": "Login",
			"Error": "Username and password are required.",
		})
		return
	}

	var (
		id   string
		hash string
	)
	err := h.svc.DB.QueryRow(`SELECT id, password FROM users WHERE username = ? LIMIT 1`, username).Scan(&id, &hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			view.Render(w, r, "login.tmpl", view.M{
				"Title": "Login",
				"Error": "Invalid credentials.",
			})
			return
		}
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		view.Render(w, r, "login.tmpl", view.M{
			"Title": "Login",
			"Error": "Invalid credentials.",
		})
		return
	}

	h.svc.Sessions.Put(r.Context(), "user_id", id)
	http.Redirect(w, r, "/ui", http.StatusFound)
}

func (h *Handlers) SetupPage(w http.ResponseWriter, r *http.Request) {
	// If already setup, redirect to the UI or login.
	if h.isSetupComplete() {
		if h.svc.Sessions.GetString(r.Context(), "user_id") != "" {
			http.Redirect(w, r, "/ui", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var userCount int
	_ = h.svc.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&userCount)
	isLoggedIn := h.svc.Sessions.GetString(r.Context(), "user_id") != ""

	cfg, _ := db.GetSystemConfig(h.svc.DB)
	view.Render(w, r, "setup.tmpl", view.M{
		"Title":      "Setup",
		"HasAdmin":   userCount > 0,
		"IsLoggedIn": isLoggedIn,
		"VPNConfig":  string(cfg.VPNConfigJSON),
	})
}

func (h *Handlers) SetupGenerateKeysPartial(w http.ResponseWriter, r *http.Request) {
	priv, pub, err := wireguard.GenerateKeyPair()
	if err != nil {
		http.Error(w, "key generation failed", http.StatusInternalServerError)
		return
	}
	view.RenderPartial(w, r, "partials/setup_keys.tmpl", view.M{
		"PrivateKey": priv,
		"PublicKey":  pub,
	})
}

func (h *Handlers) SetupAdminPost(w http.ResponseWriter, r *http.Request) {
	if h.isSetupComplete() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")
	var errMsg string
	switch {
	case username == "" || password == "" || confirm == "":
		errMsg = "Username, password, and password confirmation are required."
	case password != confirm:
		errMsg = "Passwords do not match."
	}
	if errMsg != "" {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":    "Setup",
			"HasAdmin": false,
			"Error":    errMsg,
			"Username": username,
		})
		return
	}

	var existing int
	_ = h.svc.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&existing)
	if existing > 0 {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	id := uuidString()
	_, err = h.svc.DB.Exec(`INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, 'admin')`, id, username, string(hash))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	h.svc.Sessions.Put(r.Context(), "user_id", id)
	http.Redirect(w, r, "/setup", http.StatusFound)
}

func (h *Handlers) SetupLoginPost(w http.ResponseWriter, r *http.Request) {
	if h.isSetupComplete() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || password == "" {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":      "Setup",
			"HasAdmin":   true,
			"IsLoggedIn": false,
			"Error":      "Username and password are required.",
			"Username":   username,
		})
		return
	}

	var (
		id   string
		hash string
		role string
	)
	err := h.svc.DB.QueryRow(`SELECT id, password, role FROM users WHERE username = ? LIMIT 1`, username).Scan(&id, &hash, &role)
	if err != nil || role != "admin" {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":      "Setup",
			"HasAdmin":   true,
			"IsLoggedIn": false,
			"Error":      "Invalid credentials.",
			"Username":   username,
		})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":      "Setup",
			"HasAdmin":   true,
			"IsLoggedIn": false,
			"Error":      "Invalid credentials.",
			"Username":   username,
		})
		return
	}

	h.svc.Sessions.Put(r.Context(), "user_id", id)
	http.Redirect(w, r, "/setup", http.StatusFound)
}

// parseWireGuardSetupForm parses the generate-path setup form. Numeric fields must be non-empty;
// validation for ranges is done in wireguard.ValidateSetupConfig.
func parseWireGuardSetupForm(r *http.Request) (wireguard.SetupConfig, error) {
	c := wireguard.SetupConfig{
		ServerHost:         strings.TrimSpace(r.FormValue("server_host")),
		ServerAddress:      strings.TrimSpace(r.FormValue("server_address")),
		ClientAddressRange: strings.TrimSpace(r.FormValue("client_address_range")),
		DNS:                strings.TrimSpace(r.FormValue("dns")),
		AllowedIPs:         strings.TrimSpace(r.FormValue("allowed_ips")),
		PreUp:              r.FormValue("pre_up"),
		PostUp:             r.FormValue("post_up"),
		PreDown:            r.FormValue("pre_down"),
		PostDown:           r.FormValue("post_down"),
		PrivateKey:         strings.TrimSpace(r.FormValue("private_key")),
		PublicKey:          strings.TrimSpace(r.FormValue("public_key")),
	}
	sp := strings.TrimSpace(r.FormValue("server_port"))
	if sp == "" {
		return c, errors.New("server port is required")
	}
	p, err := strconv.Atoi(sp)
	if err != nil || p < 1 || p > 65535 {
		return c, errors.New("server port must be a number between 1 and 65535")
	}
	c.ServerPort = p

	mtus := strings.TrimSpace(r.FormValue("mtu"))
	if mtus == "" {
		return c, errors.New("MTU is required")
	}
	mtu, err := strconv.Atoi(mtus)
	if err != nil {
		return c, errors.New("MTU must be a valid number")
	}
	c.MTU = mtu

	pks := strings.TrimSpace(r.FormValue("persistent_keepalive"))
	if pks == "" {
		return c, errors.New("persistent keepalive is required")
	}
	pk, err := strconv.Atoi(pks)
	if err != nil {
		return c, errors.New("persistent keepalive must be a valid number")
	}
	c.PersistentKeepalive = pk
	return c, nil
}

// setupFormEcho returns raw form strings for re-rendering setup after an error (preserves "0", etc.).
func setupFormEcho(r *http.Request) map[string]string {
	return map[string]string{
		"server_host":          strings.TrimSpace(r.FormValue("server_host")),
		"server_port":          strings.TrimSpace(r.FormValue("server_port")),
		"server_address":       strings.TrimSpace(r.FormValue("server_address")),
		"client_address_range": strings.TrimSpace(r.FormValue("client_address_range")),
		"dns":                  strings.TrimSpace(r.FormValue("dns")),
		"allowed_ips":          strings.TrimSpace(r.FormValue("allowed_ips")),
		"mtu":                  strings.TrimSpace(r.FormValue("mtu")),
		"persistent_keepalive": strings.TrimSpace(r.FormValue("persistent_keepalive")),
	}
}

func importSetupFormEcho(r *http.Request) map[string]string {
	return map[string]string{
		"server_host": strings.TrimSpace(r.FormValue("server_host")),
	}
}

func (h *Handlers) SetupWireGuardPost(w http.ResponseWriter, r *http.Request) {
	if h.isSetupComplete() {
		http.Redirect(w, r, "/ui", http.StatusFound)
		return
	}
	if h.svc.Sessions.GetString(r.Context(), "user_id") == "" {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":      "Setup",
			"HasAdmin":   true,
			"IsLoggedIn": false,
			"Error":      "Your setup session expired. Sign in again to continue setup.",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	cfg, parseErr := parseWireGuardSetupForm(r)
	if parseErr != nil {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":      "Setup",
			"HasAdmin":   true,
			"Error":      parseErr.Error(),
			"Prefill":    cfg,
			"Form":       setupFormEcho(r),
			"PrivateKey": cfg.PrivateKey,
			"PublicKey":  cfg.PublicKey,
		})
		return
	}

	if err := wireguard.ValidateSetupConfig(cfg); err != nil {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":      "Setup",
			"HasAdmin":   true,
			"Error":      err.Error(),
			"Prefill":    cfg,
			"Form":       setupFormEcho(r),
			"PrivateKey": cfg.PrivateKey,
			"PublicKey":  cfg.PublicKey,
		})
		return
	}

	vpnCfg := map[string]any{
		"wireGuard": map[string]any{
			"enabled":             true,
			"serverHost":          cfg.ServerHost,
			"serverPort":          cfg.ServerPort,
			"serverAddress":       cfg.ServerAddress,
			"clientAddressRange":  cfg.ClientAddressRange,
			"dns":                 cfg.DNS,
			"mtu":                 cfg.MTU,
			"persistentKeepalive": cfg.PersistentKeepalive,
			"allowedIps":          cfg.AllowedIPs,
			"preUp":               cfg.PreUp,
			"postUp":              cfg.PostUp,
			"preDown":             cfg.PreDown,
			"postDown":            cfg.PostDown,
		},
	}
	if err := db.UpsertSystemConfig(h.svc.DB, true, vpnCfg); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if err := wireguard.UpsertWireGuardServer(h.svc.DB, h.svc.Config.DataDir, cfg); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if err := wireguard.WriteWireGuardConfig(h.svc.DB, h.svc.Config.DataDir); err != nil {
		http.Error(w, "failed to write wg0.conf", http.StatusInternalServerError)
		return
	}
	_ = wireguard.ApplyConfig(h.svc.Config.DataDir, h.svc.Config.WGInterface)
	h.reconcilePCQ()

	http.Redirect(w, r, "/ui", http.StatusFound)
}

func (h *Handlers) SetupWireGuardImportPost(w http.ResponseWriter, r *http.Request) {
	if h.isSetupComplete() {
		http.Redirect(w, r, "/ui", http.StatusFound)
		return
	}
	if h.svc.Sessions.GetString(r.Context(), "user_id") == "" {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":        "Setup",
			"HasAdmin":     true,
			"IsLoggedIn":   false,
			"Error":        "Your setup session expired. Sign in again to continue setup.",
			"ImportWizard": true,
		})
		return
	}

	// Multipart upload for wg0.conf + optional scripts.
	r.Body = http.MaxBytesReader(w, r.Body, maxSetupUploadBytes)
	if err := r.ParseMultipartForm(maxSetupUploadBytes); err != nil {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":        "Setup",
			"HasAdmin":     true,
			"Error":        "Invalid upload (file too large or malformed).",
			"ImportWizard": true,
		})
		return
	}

	serverHost := strings.TrimSpace(r.FormValue("server_host"))
	if serverHost == "" {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":        "Setup",
			"HasAdmin":     true,
			"Error":        "server host is required",
			"ImportForm":   importSetupFormEcho(r),
			"ImportWizard": true,
		})
		return
	}

	wgFile, _, err := r.FormFile("wg0_conf")
	if err != nil {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":        "Setup",
			"HasAdmin":     true,
			"Error":        "wg0.conf file is required for import.",
			"ImportForm":   importSetupFormEcho(r),
			"ImportWizard": true,
		})
		return
	}
	defer wgFile.Close()

	parsed, err := wireguard.ParseWGQuickConfig(wgFile)
	if err != nil {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":        "Setup",
			"HasAdmin":     true,
			"Error":        err.Error(),
			"ImportForm":   importSetupFormEcho(r),
			"ImportWizard": true,
		})
		return
	}

	// Save optional hook scripts and convert to absolute paths.
	dataDir := h.svc.Config.DataDir
	scriptPaths, err := saveWGHookScripts(dataDir, r)
	if err != nil {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":        "Setup",
			"HasAdmin":     true,
			"Error":        err.Error(),
			"ImportForm":   importSetupFormEcho(r),
			"ImportWizard": true,
		})
		return
	}

	// Build WireGuard config JSON from imported interface.
	serverPort := parsed.Interface.ListenPort
	if serverPort == 0 {
		serverPort = 51820
	}
	serverAddr := strings.TrimSpace(parsed.Interface.Address)
	if serverAddr == "" {
		serverAddr = "10.8.0.1/24"
	}
	clientRange := deriveClientRange(serverAddr)
	if clientRange == "" {
		clientRange = "10.8.0.0/24"
	}

	privateKey := strings.TrimSpace(parsed.Interface.PrivateKey)
	publicKey, err := wireguard.DerivePublicKey(privateKey)
	if err != nil {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":        "Setup",
			"HasAdmin":     true,
			"Error":        "Invalid server private key in wg0.conf.",
			"ImportForm":   importSetupFormEcho(r),
			"ImportWizard": true,
		})
		return
	}

	preUp := firstNonEmpty(scriptPaths.PreUp, parsed.Interface.PreUp)
	postUp := firstNonEmpty(scriptPaths.PostUp, parsed.Interface.PostUp)
	preDown := firstNonEmpty(scriptPaths.PreDown, parsed.Interface.PreDown)
	postDown := firstNonEmpty(scriptPaths.PostDown, parsed.Interface.PostDown)

	dns := strings.TrimSpace(parsed.Interface.DNS)
	if dns == "" {
		dns = "1.1.1.1, 1.0.0.1"
	}
	mtu := parsed.Interface.MTU
	if mtu == 0 {
		mtu = 1420
	}

	// Keep existing project defaults for client settings when importing.
	const defaultPersistentKeepalive = 25
	const defaultAllowedIPs = "0.0.0.0/0, ::/0"

	vpnCfg := map[string]any{
		"wireGuard": map[string]any{
			"enabled":             true,
			"serverHost":          serverHost,
			"serverPort":          serverPort,
			"serverAddress":       serverAddr,
			"clientAddressRange":  clientRange,
			"dns":                 dns,
			"mtu":                 mtu,
			"persistentKeepalive": defaultPersistentKeepalive,
			"allowedIps":          defaultAllowedIPs,
			"preUp":               preUp,
			"postUp":              postUp,
			"preDown":             preDown,
			"postDown":            postDown,
		},
	}

	if err := db.UpsertSystemConfig(h.svc.DB, true, vpnCfg); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if err := wireguard.UpsertWireGuardServer(h.svc.DB, dataDir, wireguard.SetupConfig{
		ServerHost:          serverHost,
		ServerPort:          serverPort,
		ServerAddress:       serverAddr,
		ClientAddressRange:  clientRange,
		DNS:                 dns,
		MTU:                 mtu,
		PersistentKeepalive: defaultPersistentKeepalive,
		AllowedIPs:          defaultAllowedIPs,
		PreUp:               preUp,
		PostUp:              postUp,
		PreDown:             preDown,
		PostDown:            postDown,
		PrivateKey:          privateKey,
		PublicKey:           publicKey,
	}); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if err := importPeersAsUsers(h.svc.DB, parsed.Peers); err != nil {
		view.Render(w, r, "setup.tmpl", view.M{
			"Title":        "Setup",
			"HasAdmin":     true,
			"Error":        err.Error(),
			"ImportForm":   importSetupFormEcho(r),
			"ImportWizard": true,
		})
		return
	}

	if err := wireguard.WriteWireGuardConfig(h.svc.DB, dataDir); err != nil {
		http.Error(w, "failed to write wg0.conf", http.StatusInternalServerError)
		return
	}
	_ = wireguard.ApplyConfig(dataDir, h.svc.Config.WGInterface)
	h.reconcilePCQ()
	http.Redirect(w, r, "/ui", http.StatusFound)
}

type hookScriptPaths struct {
	PreUp    string
	PostUp   string
	PreDown  string
	PostDown string
}

func saveWGHookScripts(dataDir string, r *http.Request) (hookScriptPaths, error) {
	var out hookScriptPaths
	// Deterministic filenames inside same dir as wg0.conf (requirement).
	type item struct {
		Field string
		Name  string
		Set   func(string)
	}
	items := []item{
		{Field: "pre_up_script", Name: "wg0-pre-up.sh", Set: func(p string) { out.PreUp = p }},
		{Field: "post_up_script", Name: "wg0-post-up.sh", Set: func(p string) { out.PostUp = p }},
		{Field: "pre_down_script", Name: "wg0-pre-down.sh", Set: func(p string) { out.PreDown = p }},
		{Field: "post_down_script", Name: "wg0-post-down.sh", Set: func(p string) { out.PostDown = p }},
	}

	for _, it := range items {
		f, _, err := r.FormFile(it.Field)
		if err != nil {
			// no file is fine
			continue
		}
		if err := func() error {
			defer f.Close()
			dst := filepath.Join(dataDir, it.Name)
			b, err := ioReadAllLimited(f, 1024*1024) // 1MB per script
			if err != nil {
				return err
			}
			if err := os.WriteFile(dst, b, 0o700); err != nil {
				return err
			}
			it.Set(dst)
			return nil
		}(); err != nil {
			return hookScriptPaths{}, err
		}
	}
	return out, nil
}

func ioReadAllLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("uploaded script is too large")
	}
	return b, nil
}

func deriveClientRange(serverAddr string) string {
	addr := strings.TrimSpace(serverAddr)
	// Address may contain multiple entries separated by comma.
	if i := strings.IndexByte(addr, ','); i >= 0 {
		addr = strings.TrimSpace(addr[:i])
	}
	if addr == "" {
		return ""
	}
	if !strings.Contains(addr, "/") {
		// Guess /24 for IPv4, /64 for IPv6 if needed.
		if ip := net.ParseIP(addr); ip != nil && strings.Count(addr, ".") == 3 {
			addr = addr + "/24"
		} else if ip != nil && strings.Contains(addr, ":") {
			addr = addr + "/64"
		}
	}
	_, ipnet, err := net.ParseCIDR(addr)
	if err != nil || ipnet == nil {
		return ""
	}
	return ipnet.String()
}

func firstNonEmpty(primary string, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return fallback
}

func importPeersAsUsers(sqlDB *sql.DB, peers []wireguard.WGQuickPeer) error {
	if sqlDB == nil {
		return errors.New("db is nil")
	}
	for _, p := range peers {
		pub := strings.TrimSpace(p.PublicKey)
		allowed := strings.TrimSpace(p.AllowedIPs)
		if pub == "" || allowed == "" {
			continue
		}

		username := strings.TrimSpace(p.Username)
		if username == "" {
			if ip := wireguard.FirstPeerVPNIP(allowed); ip != "" {
				username = ip
			} else {
				username = pub
			}
		}

		id := wireguard.NewID()
		_, err := sqlDB.Exec(`
			INSERT INTO vpn_users (
			  id, username, allowed_ips, endpoint, public_key, preshared_key,
			  server_id, is_enabled
			)
			VALUES (?, ?, ?, ?, ?, ?, 'wireguard', 1)
			ON CONFLICT(username) DO UPDATE SET
			  allowed_ips = excluded.allowed_ips,
			  endpoint = excluded.endpoint,
			  public_key = excluded.public_key,
			  preshared_key = excluded.preshared_key,
			  server_id = 'wireguard',
			  is_enabled = 1,
			  updated_at = datetime('now')
		`, id, username, allowed, nullIfEmpty(p.Endpoint), pub, nullIfEmpty(p.PresharedKey))
		if err != nil {
			return err
		}
	}
	return nil
}

func mustAtoi(s string, fallback int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func uuidString() string {
	return wireguard.NewID()
}

func (h *Handlers) LogoutPost(w http.ResponseWriter, r *http.Request) {
	_ = h.svc.Sessions.Destroy(r.Context())
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *Handlers) UIPage(w http.ResponseWriter, r *http.Request) {
	view.Render(w, r, "ui.tmpl", view.M{
		"Title": "Overview",
		"Now":   time.Now(),
	})
}

type overviewConnStats struct {
	InUse        int
	Available    int
	Total        int
	Mid          int
	InUsePct     int
	AvailablePct int
}

type overviewXferStats struct {
	Received int64
	Sent     int64
	Combined int64
}

type overviewSysInfo struct {
	ServerAddress string
	Version       string
	OSName        string
	Hostname      string
	UptimeHuman   string
	AcceptingOn   string
	Ports         string
}

func (h *Handlers) loadOverviewData() (overviewConnStats, overviewXferStats, overviewSysInfo) {
	var total, enabled, connected int
	_ = h.svc.DB.QueryRow(`SELECT COUNT(*) FROM vpn_users WHERE server_id='wireguard'`).Scan(&total)
	_ = h.svc.DB.QueryRow(`SELECT COUNT(*) FROM vpn_users WHERE server_id='wireguard' AND is_enabled=1`).Scan(&enabled)
	_ = h.svc.DB.QueryRow(`SELECT COUNT(*) FROM vpn_users WHERE server_id='wireguard' AND is_enabled=1 AND is_connected=1`).Scan(&connected)

	inUse := connected
	available := maxInt(0, enabled-inUse)
	cs := overviewConnStats{
		InUse:     inUse,
		Available: available,
		Total:     total,
		Mid:       total / 2,
	}
	if total > 0 {
		cs.InUsePct = int(float64(inUse) / float64(total) * 100)
		cs.AvailablePct = int(float64(available) / float64(total) * 100)
	}

	var rx, tx int64
	_ = h.svc.DB.QueryRow(`SELECT COALESCE(SUM(total_bytes_received + bytes_received),0), COALESCE(SUM(total_bytes_sent + bytes_sent),0) FROM vpn_users WHERE server_id='wireguard'`).Scan(&rx, &tx)
	xf := overviewXferStats{Received: rx, Sent: tx, Combined: rx + tx}

	hn, _ := os.Hostname()
	uptime := time.Since(h.svc.StartedAt)
	si := overviewSysInfo{
		ServerAddress: h.svc.Config.HTTPAddr,
		Version:       version.Display(),
		OSName:        runtime.GOOS,
		Hostname:      hn,
		UptimeHuman:   humanUptime(uptime),
		AcceptingOn:   h.svc.Config.WGInterface,
		Ports:         strconv.Itoa(wireguardPort(h.svc.DB)),
	}
	return cs, xf, si
}

func (h *Handlers) OverviewConnectionsPartial(w http.ResponseWriter, r *http.Request) {
	conn, _, _ := h.loadOverviewData()
	view.RenderPartial(w, r, "partials/overview_connections.tmpl", view.M{"Conn": conn})
}

func (h *Handlers) OverviewServerPartial(w http.ResponseWriter, r *http.Request) {
	_, _, sys := h.loadOverviewData()
	view.RenderPartial(w, r, "partials/overview_server.tmpl", view.M{"Sys": sys})
}

func (h *Handlers) OverviewTransferPartial(w http.ResponseWriter, r *http.Request) {
	_, xfer, _ := h.loadOverviewData()
	view.RenderPartial(w, r, "partials/overview_transfer.tmpl", view.M{"Xfer": xfer})
}

func (h *Handlers) OverviewLivePartial(w http.ResponseWriter, r *http.Request) {
	conn, _, sys := h.loadOverviewData()
	view.RenderPartial(w, r, "partials/overview_live_oob.tmpl", view.M{
		"Conn": conn,
		"Sys":  sys,
	})
}

// OverviewAllPartial is kept for backwards compatibility; redirects clients to live OOB refresh.
func (h *Handlers) OverviewAllPartial(w http.ResponseWriter, r *http.Request) {
	h.OverviewLivePartial(w, r)
}

func wireguardPort(dbConn *sql.DB) int {
	var p sql.NullInt64
	_ = dbConn.QueryRow(`SELECT port FROM vpn_servers WHERE id='wireguard' LIMIT 1`).Scan(&p)
	if p.Valid {
		return int(p.Int64)
	}
	return 51820
}

func humanUptime(d time.Duration) string {
	sec := int(d.Seconds())
	days := sec / 86400
	hours := (sec % 86400) / 3600
	mins := (sec % 3600) / 60
	var parts []string
	if days > 0 {
		parts = append(parts, plural(days, "day"))
	}
	if hours > 0 {
		parts = append(parts, plural(hours, "hour"))
	}
	if mins > 0 {
		parts = append(parts, plural(mins, "minute"))
	}
	if len(parts) == 0 {
		return "Less than a minute"
	}
	if len(parts) == 1 {
		return parts[0]
	}
	if len(parts) == 2 {
		return parts[0] + ", " + parts[1]
	}
	return parts[0] + ", " + parts[1] + ", " + parts[2]
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func formatInstantAgo(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	sec := int(d / time.Second)
	switch {
	case sec < 1:
		return "just now"
	case sec < 60:
		if sec == 1 {
			return "1 second ago"
		}
		return fmt.Sprintf("%d seconds ago", sec)
	case sec < 3600:
		min := sec / 60
		if min == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", min)
	case sec < 86400:
		h := sec / 3600
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	case sec < 30*86400:
		day := sec / 86400
		if day == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", day)
	default:
		return t.UTC().Format("Jan 2, 2006")
	}
}

func formatTimeAgoFromRFC3339(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return ""
	}
	return formatInstantAgo(t)
}

func relativeAgoLastHandshake(lastHS, connectedAt sql.NullString) string {
	if lastHS.Valid {
		if a := formatTimeAgoFromRFC3339(strings.TrimSpace(lastHS.String)); a != "" {
			return a
		}
	}
	if connectedAt.Valid {
		return formatTimeAgoFromRFC3339(strings.TrimSpace(connectedAt.String))
	}
	return ""
}

func (h *Handlers) UsersPage(w http.ResponseWriter, r *http.Request) {
	rows, err := h.svc.DB.Query(`
		SELECT
			id,
			username,
			allowed_ips,
			endpoint,
			is_enabled,
			is_connected,
			bytes_received,
			bytes_sent,
			total_bytes_received,
			total_bytes_sent,
			remaining_days,
			remaining_traffic_bytes,
			connected_at,
			last_handshake,
			peer_icon
		FROM vpn_users
		ORDER BY username ASC
		LIMIT 500
	`)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type userRow struct {
		ID                    string
		Username              string
		IPAddress             string
		Endpoint              string
		IsEnabled             bool
		IsConnected           bool
		TotalRxBytes          int64
		TotalTxBytes          int64
		RemainingDaysValue    int64
		HasRemainingDays      bool
		RemainingTrafficBytes int64
		HasRemainingTraffic   bool
		ConnectedAt           string
		LastHandshakeAgo      string
		PeerIcon              string
	}
	var users []userRow
	for rows.Next() {
		var u userRow
		var enabled, connected int
		var connectedAt sql.NullString
		var allowedIPs sql.NullString
		var endpoint sql.NullString
		var remainingDays sql.NullInt64
		var remainingTraffic sql.NullInt64
		var peerIcon sql.NullString
		var lastHandshake sql.NullString
		var bytesRx, bytesTx, totalBytesRx, totalBytesTx int64
		if err := rows.Scan(
			&u.ID,
			&u.Username,
			&allowedIPs,
			&endpoint,
			&enabled,
			&connected,
			&bytesRx,
			&bytesTx,
			&totalBytesRx,
			&totalBytesTx,
			&remainingDays,
			&remainingTraffic,
			&connectedAt,
			&lastHandshake,
			&peerIcon,
		); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		u.TotalRxBytes = totalBytesRx + bytesRx
		u.TotalTxBytes = totalBytesTx + bytesTx
		u.IsEnabled = enabled != 0
		u.IsConnected = connected != 0
		if connectedAt.Valid {
			u.ConnectedAt = connectedAt.String
		}
		u.LastHandshakeAgo = relativeAgoLastHandshake(lastHandshake, connectedAt)
		if allowedIPs.Valid {
			// First IP/CIDR is the peer tunnel address.
			first := strings.TrimSpace(allowedIPs.String)
			if i := strings.IndexByte(first, ','); i >= 0 {
				first = strings.TrimSpace(first[:i])
			}
			u.IPAddress = first
		}
		if endpoint.Valid {
			u.Endpoint = endpoint.String
		}
		if remainingDays.Valid {
			u.HasRemainingDays = true
			u.RemainingDaysValue = remainingDays.Int64
		}
		if remainingTraffic.Valid {
			u.HasRemainingTraffic = true
			u.RemainingTrafficBytes = remainingTraffic.Int64
		}
		if peerIcon.Valid {
			u.PeerIcon = peerIcon.String
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	view.Render(w, r, "users.tmpl", view.M{
		"Title": "Users",
		"Users": users,
	})
}

func (h *Handlers) UserCreatePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		http.Redirect(w, r, "/ui/users", http.StatusFound)
		return
	}

	vpnIP := strings.TrimSpace(r.FormValue("vpn_ip"))
	if vpnIP == "" {
		vpnIP = strings.TrimSpace(r.FormValue("allowed_ips"))
	}
	if vpnIP == "" {
		alloc, err := wireguard.NextClientAllowedIP(h.svc.DB)
		if err != nil {
			http.Error(w, "ip allocation failed", http.StatusInternalServerError)
			return
		}
		vpnIP = alloc
	}
	extraAllowed := strings.TrimSpace(r.FormValue("allowed_ips_extra"))
	allowedIPs := vpnIP
	if extraAllowed != "" {
		allowedIPs = vpnIP + ", " + extraAllowed
	}

	privateKey := strings.TrimSpace(r.FormValue("private_key"))
	publicKey := strings.TrimSpace(r.FormValue("public_key"))
	psk := strings.TrimSpace(r.FormValue("preshared_key"))

	if privateKey == "" {
		priv, pub, err := wireguard.GenerateKeyPair()
		if err != nil {
			http.Error(w, "key generation failed", http.StatusInternalServerError)
			return
		}
		privateKey = priv
		publicKey = pub
	} else {
		derivedPub, err := wireguard.DerivePublicKey(privateKey)
		if err != nil {
			http.Error(w, "invalid private key", http.StatusBadRequest)
			return
		}
		if publicKey == "" {
			publicKey = derivedPub
		} else if publicKey != derivedPub {
			http.Error(w, "public key mismatch", http.StatusBadRequest)
			return
		}
	}
	// PSK is optional: only store it if provided/generated by the user.

	var remainingDays any = nil
	if v := strings.TrimSpace(r.FormValue("remaining_days")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			remainingDays = n
		}
	}
	var remainingTrafficBytes any = nil
	if v := strings.TrimSpace(r.FormValue("remaining_traffic_mb")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			const bytesPerMB = 1024 * 1024
			remainingTrafficBytes = n * bytesPerMB
		}
	}
	isEnabled := 1
	if strings.TrimSpace(r.FormValue("is_enabled")) == "" {
		isEnabled = 0
	}

	id := wireguard.NewID()
	_, err := h.svc.DB.Exec(`
		INSERT INTO vpn_users (
		  id, username, allowed_ips, private_key, public_key, preshared_key,
		  remaining_days, remaining_traffic_bytes,
		  server_id, is_enabled
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'wireguard', ?)
	`, id, username, allowedIPs, privateKey, publicKey, nullIfEmpty(psk), remainingDays, remainingTrafficBytes, isEnabled)
	if err != nil {
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}

	if err := h.applyWireGuardFromDB(); err != nil {
		http.Redirect(w, r, "/ui/users?msgType=warning&msg="+urlQueryEscape("User created but WireGuard reload failed: "+err.Error()), http.StatusFound)
		return
	}
	h.reconcilePCQ()

	http.Redirect(w, r, "/ui/users", http.StatusFound)
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func (h *Handlers) AddUserModalPartial(w http.ResponseWriter, r *http.Request) {
	nextIP, _ := wireguard.NextClientAllowedIP(h.svc.DB)
	view.RenderPartial(w, r, "partials/add_user_modal.tmpl", view.M{
		"NextIP": nextIP,
	})
}

func (h *Handlers) EditUserModalPartial(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	var (
		username         string
		privateKey       sql.NullString
		publicKey        sql.NullString
		presharedKey     sql.NullString
		allowed          sql.NullString
		remainingDays    sql.NullInt64
		remainingTraffic sql.NullInt64
		isEnabled        int
	)
	err := h.svc.DB.QueryRow(`
		SELECT username, private_key, public_key, preshared_key, allowed_ips, remaining_days, remaining_traffic_bytes, is_enabled
		FROM vpn_users
		WHERE id = ?
		LIMIT 1
	`, id).Scan(&username, &privateKey, &publicKey, &presharedKey, &allowed, &remainingDays, &remainingTraffic, &isEnabled)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var vpnIP, allowedExtra string
	if allowed.Valid {
		raw := strings.TrimSpace(allowed.String)
		if i := strings.IndexByte(raw, ','); i >= 0 {
			vpnIP = strings.TrimSpace(raw[:i])
			allowedExtra = strings.TrimSpace(raw[i+1:])
		} else {
			vpnIP = raw
		}
	}
	remainingTrafficMB := ""
	if remainingTraffic.Valid && remainingTraffic.Int64 >= 0 {
		remainingTrafficMB = strconv.FormatInt(remainingTraffic.Int64/(1024*1024), 10)
	}
	remainingDaysStr := ""
	if remainingDays.Valid && remainingDays.Int64 >= 0 {
		remainingDaysStr = strconv.FormatInt(remainingDays.Int64, 10)
	}

	privStr := strings.TrimSpace(privateKey.String)
	pubStr := strings.TrimSpace(publicKey.String)
	importedNoPrivKey := privStr == "" && pubStr != ""

	view.RenderPartial(w, r, "partials/edit_user_modal.tmpl", view.M{
		"UserID":             id,
		"Username":           username,
		"PrivateKey":         privStr,
		"PublicKey":          pubStr,
		"PresharedKey":       strings.TrimSpace(presharedKey.String),
		"VPNIP":              vpnIP,
		"AllowedExtra":       allowedExtra,
		"RemainingDays":      remainingDaysStr,
		"RemainingTrafficMB": remainingTrafficMB,
		"IsEnabled":          isEnabled != 0,
		"ImportedNoPrivKey":  importedNoPrivKey,
	})
}

func (h *Handlers) UserUpdatePost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.Header().Set("HX-Trigger", `{"toast":{"type":"danger","message":"Invalid form submission."}}`)
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		w.Header().Set("HX-Trigger", `{"toast":{"type":"danger","message":"Username is required."}}`)
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	var (
		existingAllowed sql.NullString
	)
	err := h.svc.DB.QueryRow(`SELECT allowed_ips FROM vpn_users WHERE id = ? LIMIT 1`, id).Scan(&existingAllowed)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	vpnIP := ""
	if existingAllowed.Valid {
		raw := strings.TrimSpace(existingAllowed.String)
		if i := strings.IndexByte(raw, ','); i >= 0 {
			vpnIP = strings.TrimSpace(raw[:i])
		} else {
			vpnIP = raw
		}
	}

	allowedExtra := strings.TrimSpace(r.FormValue("allowed_ips_extra"))
	allowedIPs := strings.TrimSpace(vpnIP)
	if allowedIPs != "" && allowedExtra != "" {
		allowedIPs = allowedIPs + ", " + allowedExtra
	} else if allowedIPs == "" {
		allowedIPs = allowedExtra
	}

	var remainingDays any = nil
	if v := strings.TrimSpace(r.FormValue("remaining_days")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			remainingDays = n
		}
	}

	var remainingTrafficBytes any = nil
	if v := strings.TrimSpace(r.FormValue("remaining_traffic_mb")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			remainingTrafficBytes = n * 1024 * 1024
		}
	}

	isEnabled := 0
	if r.FormValue("is_enabled") == "on" {
		isEnabled = 1
	}

	// Allow updating keys and PSK at any time (client configs must be updated to match).
	privateKey := strings.TrimSpace(r.FormValue("private_key"))
	publicKey := strings.TrimSpace(r.FormValue("public_key"))
	psk := strings.TrimSpace(r.FormValue("preshared_key"))

	var updatePriv any = nil
	var updatePub any = nil
	var updatePSK any = nil

	if privateKey != "" {
		derivedPub, err := wireguard.DerivePublicKey(privateKey)
		if err != nil {
			w.Header().Set("HX-Trigger", `{"toast":{"type":"danger","message":"Invalid private key."}}`)
			http.Error(w, "invalid private key", http.StatusBadRequest)
			return
		}
		if publicKey != "" && publicKey != derivedPub {
			w.Header().Set("HX-Trigger", `{"toast":{"type":"danger","message":"Public key does not match this private key."}}`)
			http.Error(w, "public key mismatch", http.StatusBadRequest)
			return
		}
		updatePriv = privateKey
		updatePub = derivedPub
	}

	if psk != "" {
		updatePSK = psk
	}

	_, err = h.svc.DB.Exec(`
		UPDATE vpn_users
		SET username = ?,
		    allowed_ips = ?,
		    remaining_days = ?,
		    remaining_traffic_bytes = ?,
		    is_enabled = ?,
		    private_key = COALESCE(?, private_key),
		    public_key = COALESCE(?, public_key),
		    preshared_key = COALESCE(?, preshared_key),
		    updated_at = datetime('now')
		WHERE id = ?
	`, username, nullIfEmpty(allowedIPs), remainingDays, remainingTrafficBytes, isEnabled, updatePriv, updatePub, updatePSK, id)
	if err != nil {
		w.Header().Set("HX-Trigger", `{"toast":{"type":"danger","message":"Failed to save changes."}}`)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}

	toastType := "success"
	toastMsg := "Changes saved."
	if err := h.applyWireGuardFromDB(); err != nil {
		toastType = "warning"
		toastMsg = "Saved to database but WireGuard reload failed: " + err.Error()
	} else {
		h.reconcilePCQ()
	}

	// Close modal and show a toast; then refresh list.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("HX-Trigger", fmt.Sprintf(`{"toast":{"type":"%s","message":%q},"usersReload":true}`, toastType, toastMsg))
	_, _ = w.Write([]byte(""))
}

func (h *Handlers) UserDeleteModalPartial(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	var username string
	err := h.svc.DB.QueryRow(`SELECT username FROM vpn_users WHERE id = ? LIMIT 1`, id).Scan(&username)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	view.RenderPartial(w, r, "partials/delete_user_modal.tmpl", view.M{
		"UserID":   id,
		"Username": username,
	})
}

func (h *Handlers) UserDeletePost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	var username string
	_ = h.svc.DB.QueryRow(`SELECT username FROM vpn_users WHERE id = ? LIMIT 1`, id).Scan(&username)

	res, err := h.svc.DB.Exec(`DELETE FROM vpn_users WHERE id = ?`, id)
	if err != nil {
		w.Header().Set("HX-Trigger", `{"toast":{"type":"danger","message":"Failed to delete user."}}`)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		w.Header().Set("HX-Trigger", `{"toast":{"type":"danger","message":"User not found."}}`)
		http.NotFound(w, r)
		return
	}

	toastType := "success"
	msg := "User deleted."
	if err := h.applyWireGuardFromDB(); err != nil {
		toastType = "warning"
		msg = "User deleted but WireGuard reload failed: " + err.Error()
	} else {
		h.reconcilePCQ()
		if strings.TrimSpace(username) != "" {
			msg = `User "` + username + `" deleted.`
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("HX-Trigger", `{"toast":{"type":"`+toastType+`","message":`+strconv.Quote(msg)+`},"usersReload":true}`)
	_, _ = w.Write([]byte(""))
}

func (h *Handlers) UserConfigAPIGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	conf, filename, err := wireguard.RenderClientConfig(h.svc.DB, id)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"configText": conf,
		"fileName":   filename,
	})
}

func (h *Handlers) UserQRModalPartial(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	conf, filename, err := wireguard.RenderClientConfig(h.svc.DB, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}

		var username string
		var pub sql.NullString
		_ = h.svc.DB.QueryRow(`SELECT username, public_key FROM vpn_users WHERE id = ? LIMIT 1`, id).Scan(&username, &pub)
		hasPeerKey := pub.Valid && strings.TrimSpace(pub.String) != ""

		if errors.Is(err, wireguard.ErrNoClientPrivateKey) {
			view.RenderPartial(w, r, "partials/qr_modal_unavailable.tmpl", view.M{
				"Username": username,
				"IsImport": hasPeerKey,
			})
			return
		}

		view.RenderPartial(w, r, "partials/qr_modal_unavailable.tmpl", view.M{
			"Username": username,
			"Detail":   "The client configuration could not be built. Check server WireGuard settings and that this user has a tunnel address.",
		})
		return
	}

	var (
		username string
		allowed  sql.NullString
	)
	_ = h.svc.DB.QueryRow(`SELECT username, allowed_ips FROM vpn_users WHERE id = ? LIMIT 1`, id).Scan(&username, &allowed)
	ip := ""
	if allowed.Valid {
		raw := strings.TrimSpace(allowed.String)
		if i := strings.IndexByte(raw, ','); i >= 0 {
			ip = strings.TrimSpace(raw[:i])
		} else {
			ip = raw
		}
	}

	var (
		serverName string
		protocol   string
	)
	_ = h.svc.DB.QueryRow(`SELECT name, protocol FROM vpn_servers WHERE id='wireguard' LIMIT 1`).Scan(&serverName, &protocol)
	if strings.TrimSpace(serverName) == "" {
		serverName = "WireGuard Server"
	}
	if strings.TrimSpace(protocol) == "" {
		protocol = "wireguard"
	}

	view.RenderPartial(w, r, "partials/qr_modal.tmpl", view.M{
		"UserID":     id,
		"Username":   username,
		"Server":     serverName,
		"Protocol":   strings.ToUpper(protocol),
		"IP":         ip,
		"FileName":   filename,
		"ConfigText": conf,
	})
}

func (h *Handlers) EmptyPartial(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(""))
}

func (h *Handlers) UsersGenerateKeysAPI(w http.ResponseWriter, r *http.Request) {
	priv, pub, err := wireguard.GenerateKeyPair()
	if err != nil {
		http.Error(w, `{"error":"failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"privateKey": priv, "publicKey": pub})
}

func (h *Handlers) UsersDerivePublicKeyAPI(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		PrivateKey string `json:"privateKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	pub, err := wireguard.DerivePublicKey(payload.PrivateKey)
	if err != nil {
		http.Error(w, `{"error":"invalid key"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"publicKey": pub})
}

func (h *Handlers) UsersGeneratePSKAPI(w http.ResponseWriter, r *http.Request) {
	psk, err := wireguard.GeneratePresharedKey()
	if err != nil {
		http.Error(w, `{"error":"failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"presharedKey": psk})
}

func (h *Handlers) UsersNextIPAPI(w http.ResponseWriter, r *http.Request) {
	ip, err := wireguard.NextClientAllowedIP(h.svc.DB)
	if err != nil {
		http.Error(w, `{"error":"failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"allowedIps": ip})
}

func (h *Handlers) UserTogglePost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Redirect(w, r, "/ui/users", http.StatusFound)
		return
	}
	_, err := h.svc.DB.Exec(`
		UPDATE vpn_users
		SET is_enabled = CASE WHEN is_enabled = 1 THEN 0 ELSE 1 END,
		    updated_at = datetime('now')
		WHERE id = ?
	`, id)
	if err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	if err := h.applyWireGuardFromDB(); err != nil {
		http.Redirect(w, r, "/ui/users?msgType=warning&msg="+urlQueryEscape("User updated but WireGuard reload failed: "+err.Error()), http.StatusFound)
		return
	}
	h.reconcilePCQ()

	http.Redirect(w, r, "/ui/users", http.StatusFound)
}

func (h *Handlers) UserConfigGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	conf, filename, err := wireguard.RenderClientConfig(h.svc.DB, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write([]byte(conf))
}

func (h *Handlers) ConnectionsPage(w http.ResponseWriter, r *http.Request) {
	view.Render(w, r, "connections.tmpl", view.M{
		"Title": "Connections",
	})
}

func (h *Handlers) ServersPage(w http.ResponseWriter, r *http.Request) {
	rows, err := h.svc.DB.Query(`
		SELECT id, name, protocol, host, port, is_active
		FROM vpn_servers
		ORDER BY created_at DESC
		LIMIT 200
	`)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type serverRow struct {
		ID       string
		Name     string
		Protocol string
		Host     string
		Port     string
		IsActive bool
	}
	var servers []serverRow
	for rows.Next() {
		var s serverRow
		var port sql.NullInt64
		var active int
		if err := rows.Scan(&s.ID, &s.Name, &s.Protocol, &s.Host, &port, &active); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if port.Valid {
			s.Port = intToString(int(port.Int64))
		}
		s.IsActive = active != 0
		servers = append(servers, s)
	}

	view.Render(w, r, "servers.tmpl", view.M{
		"Title":   "Servers",
		"Servers": servers,
	})
}

func (h *Handlers) BackupPage(w http.ResponseWriter, r *http.Request) {
	view.Render(w, r, "backup.tmpl", view.M{
		"Title":           "Backup & Restore",
		"SaveMessage":     strings.TrimSpace(r.URL.Query().Get("msg")),
		"SaveMessageType": strings.TrimSpace(r.URL.Query().Get("msgType")),
	})
}

func (h *Handlers) WireGuardPage(w http.ResponseWriter, r *http.Request) {
	cfg, server, live, hostUp, tunUp, err := wireguard.LoadWireGuardState(h.svc.DB, h.svc.Config.WGInterface, h.svc.StartedAt)
	if err != nil {
		view.Render(w, r, "wireguard.tmpl", view.M{
			"Title":     "Wireguard",
			"LoadError": err.Error(),
		})
		return
	}

	msg := strings.TrimSpace(r.URL.Query().Get("msg"))
	msgType := strings.TrimSpace(r.URL.Query().Get("msgType"))

	view.Render(w, r, "wireguard.tmpl", view.M{
		"Title":               "Wireguard",
		"WGConfig":            cfg,
		"WGServer":            server,
		"WGLive":              live,
		"HostUptimeSeconds":   hostUp,
		"TunnelUptimeSeconds": tunUp,
		"SaveMessage":         msg,
		"SaveMessageType":     msgType,
	})
}

func (h *Handlers) SettingsPage(w http.ResponseWriter, r *http.Request) {
	view.Render(w, r, "settings.tmpl", view.M{
		"Title": "Settings",
	})
}

func parseDNSListenPort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return db.DefaultDNSListenPort, nil
	}
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("DNS listen port must be between 1 and 65535")
	}
	return port, nil
}

func (h *Handlers) enrichDNSSettings(cfg db.DNSSettings) db.DNSSettings {
	if strings.TrimSpace(cfg.Binary) == "" {
		fb := strings.TrimSpace(h.svc.Config.CoreDNSBin)
		if fb == "" {
			fb = db.DefaultDNSBinary
		}
		cfg.Binary = fb
	}
	return cfg
}

func (h *Handlers) applyDNSFromDB() error {
	err := dns.ApplyFromDB(h.svc.DNS, h.svc.DB, h.svc.Config.CoreDNSBin)
	if err == nil && h.svc.Logger != nil {
		if st := h.svc.DNS.Status(); st.Running {
			h.svc.Logger.Info("dns apply", "action", "start", "listen", st.ListenAddr)
		} else {
			h.svc.Logger.Info("dns apply", "action", "stop")
		}
	}
	return err
}

func normalizeDNSSection(section string) string {
	switch strings.TrimSpace(section) {
	case "filtering", "rewrites", "rules", "server":
		return strings.TrimSpace(section)
	default:
		return "filtering"
	}
}

func dnsSectionFromRequest(r *http.Request) string {
	if s := strings.TrimSpace(r.URL.Query().Get("section")); s != "" {
		return normalizeDNSSection(s)
	}
	if s := strings.TrimSpace(r.FormValue("dns_section")); s != "" {
		return normalizeDNSSection(s)
	}
	return "filtering"
}

func (h *Handlers) DNSPage(w http.ResponseWriter, r *http.Request) {
	h.renderDNSPage(w, r, strings.TrimSpace(r.URL.Query().Get("msg")), strings.TrimSpace(r.URL.Query().Get("msgType")), dnsSectionFromRequest(r))
}

func (h *Handlers) renderDNSPage(w http.ResponseWriter, r *http.Request, saveMessage, saveMessageType, section string) {
	dnsCfg, _ := db.GetDNSSettings(h.svc.DB)
	dnsCfg = h.enrichDNSSettings(dnsCfg)
	listen, listenErr := wireguard.ResolveDNSListenAddress(h.svc.DB, dnsCfg)
	if listenErr == nil {
		dnsCfg.ListenAddr = listen
	}
	wgDefaultHost, _ := wireguard.DNSServerHost(h.svc.DB)
	clientDNSPlaceholder := wireguard.SuggestDedicatedDNSHost(wgDefaultHost)
	if clientDNSPlaceholder == "" {
		clientDNSPlaceholder = "10.8.0.1"
	}
	listenHostPlaceholder := wgDefaultHost
	if listenHostPlaceholder == "" {
		listenHostPlaceholder = "10.8.0.1"
	}
	clientDNSAddr := ""
	if dnsCfg.Enabled {
		clientDNSAddr, _ = wireguard.DNSResolverHost(h.svc.DB, dnsCfg)
	}
	listenErrMsg := ""
	if listenErr != nil {
		listenErrMsg = listenErr.Error()
	}
	st := dns.Status{}
	if h.svc.DNS != nil {
		st = h.svc.DNS.Status()
	}
	records, _ := db.ListDNSRecords(h.svc.DB)
	rules, _ := db.ListDNSDomainRules(h.svc.DB)
	view.Render(w, r, "dns.tmpl", view.M{
		"Title":                 "DNS",
		"DNSSection":            normalizeDNSSection(section),
		"DNS":                   dnsCfg,
		"DNSRecords":            records,
		"DNSDomainRules":        rules,
		"DNSRecordTypes":        db.DNSRecordTypes,
		"DNSUpstreamPresets":    db.DNSUpstreamPresets,
		"DNSStatus":             st,
		"WGDefaultHost":           wgDefaultHost,
		"ClientDNSAddr":           clientDNSAddr,
		"ClientDNSPlaceholder":    clientDNSPlaceholder,
		"ListenHostPlaceholder":   listenHostPlaceholder,
		"ListenErr":             listenErrMsg,
		"SaveMessage":           saveMessage,
		"SaveMessageType":       saveMessageType,
	})
}

func (h *Handlers) dnsRedirect(w http.ResponseWriter, r *http.Request, toastType, msg string) {
	if h.svc.Logger != nil {
		h.svc.Logger.Info("dns", "toast_type", toastType, "message", msg)
	}
	tt := strings.TrimSpace(toastType)
	if tt == "error" {
		tt = "danger"
	}
	section := dnsSectionFromRequest(r)
	if strings.EqualFold(r.Header.Get("HX-Request"), "true") {
		if strings.TrimSpace(msg) != "" {
			w.Header().Set("HX-Trigger", `{"toast":{"type":`+strconv.Quote(tt)+`,"message":`+strconv.Quote(msg)+`}}`)
		}
		h.renderDNSPage(w, r, "", "", section)
		return
	}
	path := "/ui/dns"
	if strings.TrimSpace(msg) != "" {
		path += "?msgType=" + urlQueryEscape(tt) + "&msg=" + urlQueryEscape(msg)
	}
	path += "#" + section
	http.Redirect(w, r, path, http.StatusFound)
}

func (h *Handlers) DNSSavePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.dnsRedirect(w, r, "error", "Invalid form submission.")
		return
	}
	enabled := r.FormValue("dns_enabled") == "on" || r.FormValue("dns_enabled") == "1"
	port, err := parseDNSListenPort(r.FormValue("dns_listen_port"))
	if err != nil {
		h.dnsRedirect(w, r, "error", err.Error())
		return
	}
	binary := strings.TrimSpace(r.FormValue("dns_binary"))
	if binary == "" {
		binary = db.DefaultDNSBinary
	}
	upstreams := strings.TrimSpace(r.FormValue("dns_forward_upstreams"))
	if upstreams == "" {
		upstreams = db.DefaultDNSSettings().ForwardUpstreams
	}

	var logParts []string
	if enabled {
		logParts = append(logParts, "enable requested")
	} else {
		logParts = append(logParts, "disable requested")
	}
	logParts = append(logParts, fmt.Sprintf("port=%d", port), fmt.Sprintf("binary=%q", binary))

	cacheTTL, err := parseDNSCacheTTL(r.FormValue("dns_cache_ttl"))
	if err != nil {
		h.dnsRedirect(w, r, "error", err.Error())
		return
	}
	blockAddr := strings.TrimSpace(r.FormValue("dns_block_address"))
	if blockAddr == "" {
		blockAddr = db.DefaultDNSBlockAddress
	}

	clientDNSHost := strings.TrimSpace(r.FormValue("dns_client_dns_host"))
	if clientDNSHost != "" {
		if _, err := wireguard.NormalizeDNSHost(clientDNSHost); err != nil {
			h.dnsRedirect(w, r, "error", "Invalid client DNS address: "+err.Error())
			return
		}
	}
	listenHost := strings.TrimSpace(r.FormValue("dns_listen_host"))
	if listenHost != "" {
		if _, err := wireguard.NormalizeDNSHost(listenHost); err != nil {
			h.dnsRedirect(w, r, "error", "Invalid listen address: "+err.Error())
			return
		}
	}

	cfg := db.DNSSettings{
		Enabled:          enabled,
		ClientDNSHost:    clientDNSHost,
		ListenHost:       listenHost,
		ListenPort:       port,
		Binary:           binary,
		ForwardUpstreams: upstreams,
		BlockAdsEnabled:  r.FormValue("dns_block_ads") == "on" || r.FormValue("dns_block_ads") == "1",
		BlocklistURLs:    strings.TrimSpace(r.FormValue("dns_blocklist_urls")),
		BlockAddress:     blockAddr,
		CacheTTL:         cacheTTL,
		QueryLogEnabled:  r.FormValue("dns_query_log") == "on" || r.FormValue("dns_query_log") == "1",
	}
	var autoDNSHost string
	if enabled {
		generated, err := wireguard.EnsureAutoDNSHost(h.svc.DB, &cfg)
		if err != nil {
			h.dnsRedirect(w, r, "error", "Could not assign DNS address: "+err.Error())
			return
		}
		if generated {
			autoDNSHost = cfg.ClientDNSHost
			logParts = append(logParts, "client_dns_host="+autoDNSHost+" (auto)")
		}
		listen, err := wireguard.ResolveDNSListenAddress(h.svc.DB, cfg)
		if err != nil {
			h.dnsRedirect(w, r, "error", "Cannot enable DNS: "+err.Error())
			return
		}
		cfg.ListenAddr = listen
		logParts = append(logParts, "listen="+listen)
		if cfg.ListenHost != "" {
			logParts = append(logParts, "listen_host="+cfg.ListenHost)
		}
	}
	if err := db.UpsertDNSSettings(h.svc.DB, cfg); err != nil {
		if h.svc.Logger != nil {
			h.svc.Logger.Error("dns save", "err", err, "steps", strings.Join(logParts, "; "))
		}
		h.dnsRedirect(w, r, "error", "Could not save DNS settings to the database.")
		return
	}
	logParts = append(logParts, "settings saved")

	if err := h.applyDNSFromDB(); err != nil {
		if h.svc.Logger != nil {
			h.svc.Logger.Warn("dns apply", "err", err, "steps", strings.Join(logParts, "; "))
		}
		h.dnsRedirect(w, r, "warning", "Settings saved, but CoreDNS failed: "+err.Error())
		return
	}

	var msg string
	if enabled {
		st := dns.Status{}
		if h.svc.DNS != nil {
			st = h.svc.DNS.Status()
		}
		if st.Running {
			if st.PID > 0 {
				msg = fmt.Sprintf("DNS enabled — CoreDNS running on %s (pid %d).", st.ListenAddr, st.PID)
			} else {
				msg = fmt.Sprintf("DNS enabled — CoreDNS running on %s.", st.ListenAddr)
			}
			if autoDNSHost != "" {
				msg += fmt.Sprintf(" Assigned client DNS %s automatically.", autoDNSHost)
			}
		} else {
			msg = "DNS enabled in config, but CoreDNS is not running. Check the error below."
			h.dnsRedirect(w, r, "warning", msg)
			return
		}
	} else {
		msg = "DNS disabled — settings saved and CoreDNS stopped."
	}
	if h.svc.Logger != nil {
		h.svc.Logger.Info("dns save", "steps", strings.Join(logParts, "; "), "result", msg)
	}
	h.dnsRedirect(w, r, "success", msg)
}

func parseDNSCacheTTL(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return db.DefaultDNSCacheTTL, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 86400 {
		return 0, errors.New("cache TTL must be between 1 and 86400 seconds")
	}
	return n, nil
}

func parseDNSRecordTTL(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return db.DefaultDNSRewriteTTL, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 2147483647 {
		return 0, errors.New("TTL must be between 1 and 2147483647")
	}
	return n, nil
}

func (h *Handlers) DNSRecordAddPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.dnsRedirect(w, r, "error", "Invalid form submission.")
		return
	}
	ttl, err := parseDNSRecordTTL(r.FormValue("record_ttl"))
	if err != nil {
		h.dnsRedirect(w, r, "error", err.Error())
		return
	}
	rec := db.DNSRecord{
		Name:    r.FormValue("record_name"),
		Type:    r.FormValue("record_type"),
		Value:   r.FormValue("record_value"),
		TTL:     ttl,
		Enabled: true,
	}
	if err := db.ValidateDNSRewrite(rec); err != nil {
		h.dnsRedirect(w, r, "error", err.Error())
		return
	}
	inserted, err := db.InsertDNSRecord(h.svc.DB, rec)
	if err != nil {
		h.dnsRedirect(w, r, "error", "Could not add DNS rewrite.")
		return
	}
	if err := h.applyDNSFromDB(); err != nil {
		h.dnsRedirect(w, r, "warning", "Rewrite added, but CoreDNS failed to reload: "+err.Error())
		return
	}
	h.dnsRedirect(w, r, "success", fmt.Sprintf("Rewrite added: %s → %s (%s).", inserted.Name, inserted.Value, inserted.Type))
}

func (h *Handlers) DNSDomainRuleAddPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.dnsRedirect(w, r, "error", "Invalid form submission.")
		return
	}
	rule := db.DNSDomainRule{
		Domain:   r.FormValue("rule_domain"),
		RuleType: r.FormValue("rule_type"),
		Enabled:  true,
	}
	if err := db.ValidateDNSDomainRule(rule); err != nil {
		h.dnsRedirect(w, r, "error", err.Error())
		return
	}
	inserted, err := db.InsertDNSDomainRule(h.svc.DB, rule)
	if err != nil {
		h.dnsRedirect(w, r, "error", "Could not add domain rule.")
		return
	}
	if err := h.applyDNSFromDB(); err != nil {
		h.dnsRedirect(w, r, "warning", "Rule added, but CoreDNS failed to reload: "+err.Error())
		return
	}
	label := "blocked"
	if inserted.RuleType == "allow" {
		label = "allowed"
	}
	h.dnsRedirect(w, r, "success", fmt.Sprintf("Domain %s (%s).", inserted.Domain, label))
}

func (h *Handlers) DNSDomainRuleDeletePost(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		h.dnsRedirect(w, r, "error", "Rule id is required.")
		return
	}
	if err := db.DeleteDNSDomainRule(h.svc.DB, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.dnsRedirect(w, r, "error", "Domain rule not found.")
			return
		}
		h.dnsRedirect(w, r, "error", "Could not delete domain rule.")
		return
	}
	if err := h.applyDNSFromDB(); err != nil {
		h.dnsRedirect(w, r, "warning", "Rule deleted, but CoreDNS failed to reload: "+err.Error())
		return
	}
	h.dnsRedirect(w, r, "success", "Domain rule deleted.")
}

func (h *Handlers) DNSRecordDeletePost(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		h.dnsRedirect(w, r, "error", "Record id is required.")
		return
	}
	if err := db.DeleteDNSRecord(h.svc.DB, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.dnsRedirect(w, r, "error", "DNS rewrite not found.")
			return
		}
		h.dnsRedirect(w, r, "error", "Could not delete DNS rewrite.")
		return
	}
	if err := h.applyDNSFromDB(); err != nil {
		h.dnsRedirect(w, r, "warning", "Rewrite deleted, but CoreDNS failed to reload: "+err.Error())
		return
	}
	h.dnsRedirect(w, r, "success", "DNS rewrite deleted.")
}

func (h *Handlers) DNSReloadPost(w http.ResponseWriter, r *http.Request) {
	if err := h.applyDNSFromDB(); err != nil {
		h.dnsRedirect(w, r, "warning", "CoreDNS reload failed: "+err.Error())
		return
	}
	dnsCfg, _ := db.GetDNSSettings(h.svc.DB)
	if dnsCfg.Enabled {
		h.dnsRedirect(w, r, "success", "CoreDNS reloaded from saved settings.")
		return
	}
	h.dnsRedirect(w, r, "success", "DNS is disabled — CoreDNS stopped.")
}

func (h *Handlers) WireGuardSavePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	update := wireguard.WireGuardUpdate{
		ServerPrivateKey: strings.TrimSpace(r.FormValue("server_private_key")),
		Config: wireguard.WireGuardConfig{
			Enabled:             true,
			ServerHost:          strings.TrimSpace(r.FormValue("server_host")),
			ServerPort:          mustAtoi(r.FormValue("server_port"), 51820),
			ServerAddress:       strings.TrimSpace(r.FormValue("server_address")),
			ClientAddressRange:  strings.TrimSpace(r.FormValue("client_address_range")),
			DNS:                 strings.TrimSpace(r.FormValue("dns")),
			MTU:                 mustAtoi(r.FormValue("mtu"), 1420),
			PersistentKeepalive: mustAtoi(r.FormValue("persistent_keepalive"), 25),
			AllowedIPs:          strings.TrimSpace(r.FormValue("allowed_ips")),
			PreUp:               r.FormValue("pre_up"),
			PostUp:              r.FormValue("post_up"),
			PreDown:             r.FormValue("pre_down"),
			PostDown:            r.FormValue("post_down"),
		},
	}
	res, err := wireguard.SaveWireGuardState(h.svc.DB, h.svc.Config.DataDir, h.svc.Config.WGInterface, update)
	if err != nil {
		http.Redirect(w, r, "/ui/wireguard?msgType=error&msg="+urlQueryEscape(err.Error()), http.StatusFound)
		return
	}
	h.reconcilePCQ()
	h.applyDNSAfterWireGuard(&res)
	http.Redirect(w, r, "/ui/wireguard?msgType="+urlQueryEscape(res.Type)+"&msg="+urlQueryEscape(res.Text), http.StatusFound)
}

func (h *Handlers) WireGuardReloadPost(w http.ResponseWriter, r *http.Request) {
	res, err := wireguard.ReloadWireGuard(h.svc.DB, h.svc.Config.DataDir, h.svc.Config.WGInterface)
	if err != nil {
		http.Redirect(w, r, "/ui/wireguard?msgType=error&msg="+urlQueryEscape(err.Error()), http.StatusFound)
		return
	}
	h.reconcilePCQ()
	h.applyDNSAfterWireGuard(&res)
	http.Redirect(w, r, "/ui/wireguard?msgType="+urlQueryEscape(res.Type)+"&msg="+urlQueryEscape(res.Text), http.StatusFound)
}

func (h *Handlers) WireGuardRestartPost(w http.ResponseWriter, r *http.Request) {
	res, err := wireguard.RestartWireGuard(h.svc.DB, h.svc.Config.DataDir, h.svc.Config.WGInterface)
	if err != nil {
		http.Redirect(w, r, "/ui/wireguard?msgType=error&msg="+urlQueryEscape(err.Error()), http.StatusFound)
		return
	}
	h.reconcilePCQ()
	h.applyDNSAfterWireGuard(&res)
	http.Redirect(w, r, "/ui/wireguard?msgType="+urlQueryEscape(res.Type)+"&msg="+urlQueryEscape(res.Text), http.StatusFound)
}

func (h *Handlers) applyDNSAfterWireGuard(res *wireguard.SaveResult) {
	if res == nil || !res.Applied {
		return
	}
	if err := h.applyDNSFromDB(); err != nil {
		if h.svc.Logger != nil {
			h.svc.Logger.Warn("dns re-apply after wireguard", "err", err)
		}
		return
	}
	if h.svc.DNS != nil && h.svc.DNS.Status().Running {
		res.Text += " CoreDNS started."
	}
}

func (h *Handlers) wireguardBackupWantsJSON(r *http.Request) bool {
	return r.Header.Get("X-Netplug-Backup") == "1"
}

func (h *Handlers) wireguardBackupError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	if h.wireguardBackupWantsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
		return
	}
	http.Redirect(w, r, "/ui/backup?msgType=error&msg="+urlQueryEscape(msg), http.StatusFound)
}

func (h *Handlers) WireGuardBackupPost(w http.ResponseWriter, r *http.Request) {
	password, err := h.parseWireGuardBackupPassword(r)
	if err != nil {
		h.wireguardBackupError(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	if password != "" {
		if err := wireguard.ValidateBackupPassword(password); err != nil {
			h.wireguardBackupError(w, r, err.Error(), http.StatusBadRequest)
			return
		}
	}
	data, err := wireguard.ExportBackupArchive(h.svc.DB, password)
	if err != nil {
		h.wireguardBackupError(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	encrypted := password != ""
	filename := fmt.Sprintf("netplug-backup-%s.npbk", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if encrypted {
		w.Header().Set("X-Netplug-Backup-Encrypted", "1")
	}
	_, _ = w.Write(data)
}

func (h *Handlers) parseWireGuardBackupPassword(r *http.Request) (string, error) {
	if h.wireguardBackupWantsJSON(r) || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var payload struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return "", errors.New("invalid backup request")
		}
		return strings.TrimSpace(payload.Password), nil
	}

	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			return "", errors.New("invalid backup request")
		}
	} else if err := r.ParseForm(); err != nil {
		return "", errors.New("invalid backup request")
	}
	return strings.TrimSpace(r.FormValue("backup_password")), nil
}

func (h *Handlers) WireGuardRestorePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Redirect(w, r, "/ui/backup?msgType=error&msg="+urlQueryEscape("Invalid backup upload."), http.StatusFound)
		return
	}
	f, _, err := r.FormFile("backup_file")
	if err != nil {
		http.Redirect(w, r, "/ui/backup?msgType=error&msg="+urlQueryEscape("Backup file is required."), http.StatusFound)
		return
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, 32<<20))
	if err != nil {
		http.Redirect(w, r, "/ui/backup?msgType=error&msg="+urlQueryEscape("Could not read backup file."), http.StatusFound)
		return
	}
	password := strings.TrimSpace(r.FormValue("backup_password"))
	file, err := wireguard.ParseBackupArchive(raw, password)
	if err != nil {
		http.Redirect(w, r, "/ui/backup?msgType=error&msg="+urlQueryEscape(err.Error()), http.StatusFound)
		return
	}

	opts := wireguard.RestoreOptions{
		ReplacePeers:  r.FormValue("replace_peers") == "on",
		ReplaceGroups: r.FormValue("replace_groups") == "on",
	}
	if err := wireguard.RestoreBackup(h.svc.DB, h.svc.Config.DataDir, h.svc.Config.WGInterface, file, opts); err != nil {
		http.Redirect(w, r, "/ui/backup?msgType=error&msg="+urlQueryEscape(err.Error()), http.StatusFound)
		return
	}
	h.reconcilePCQ()
	http.Redirect(w, r, "/ui/backup?msgType=success&msg="+urlQueryEscape("Backup restored and WireGuard restarted."), http.StatusFound)
}

func (h *Handlers) applyWireGuardFromDB() error {
	return wireguard.SyncFromDB(h.svc.DB, h.svc.Config.DataDir, h.svc.Config.WGInterface)
}

func (h *Handlers) WireGuardAPIGet(w http.ResponseWriter, r *http.Request) {
	cfg, server, live, hostUp, tunUp, err := wireguard.LoadWireGuardState(h.svc.DB, h.svc.Config.WGInterface, h.svc.StartedAt)
	if err != nil {
		http.Error(w, `{"error":"failed to load"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"config":              cfg,
		"server":              server,
		"live":                live,
		"hostUptimeSeconds":   hostUp,
		"tunnelUptimeSeconds": tunUp,
	})
}

func (h *Handlers) WireGuardAPIPut(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Config           wireguard.WireGuardConfig `json:"config"`
		ServerPrivateKey string                    `json:"serverPrivateKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	res, err := wireguard.SaveWireGuardState(h.svc.DB, h.svc.Config.DataDir, h.svc.Config.WGInterface, wireguard.WireGuardUpdate{
		Config:           payload.Config,
		ServerPrivateKey: payload.ServerPrivateKey,
	})
	if err != nil {
		http.Error(w, `{"error":"save failed"}`, http.StatusInternalServerError)
		return
	}
	h.reconcilePCQ()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message":           res.Text,
		"wireGuardWriteOk":  res.WroteConfig,
		"wireGuardReloaded": res.Applied,
	})
}

func urlQueryEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

type bwSnap struct {
	T time.Time
	D int64
	U int64
}

func parseBandwidthTimestamp(ts string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t, true
	}
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", ts, time.UTC); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func loadBandwidthSnapshots(dbConn *sql.DB, since time.Time) ([]bwSnap, error) {
	sinceSQL := since.UTC().Format("2006-01-02 15:04:05")
	rows, err := dbConn.Query(`
		SELECT timestamp, download_rate, upload_rate
		FROM bandwidth_snapshots
		WHERE timestamp >= ?
		ORDER BY timestamp ASC
	`, sinceSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snaps []bwSnap
	for rows.Next() {
		var ts string
		var d, u int64
		if err := rows.Scan(&ts, &d, &u); err != nil {
			return nil, err
		}
		t, ok := parseBandwidthTimestamp(ts)
		if !ok {
			continue
		}
		snaps = append(snaps, bwSnap{T: t, D: d, U: u})
	}
	return snaps, rows.Err()
}

func integrateBandwidthBytes(snaps []bwSnap, maxGap time.Duration) (download, upload int64) {
	for i := 0; i < len(snaps)-1; i++ {
		a, b := snaps[i], snaps[i+1]
		dt := b.T.Sub(a.T)
		if dt <= 0 {
			continue
		}
		if maxGap > 0 && dt > maxGap {
			dt = maxGap
		}
		sec := int64(dt.Seconds())
		download += a.D * sec
		upload += a.U * sec
	}
	return download, upload
}

func bucketBandwidthRates(snaps []bwSnap, bucket time.Duration, loc *time.Location) []map[string]any {
	if len(snaps) == 0 || bucket <= 0 {
		return nil
	}
	type acc struct {
		dSum, uSum int64
		n          int
	}
	buckets := map[int64]*acc{}
	var order []int64
	for _, s := range snaps {
		t := s.T.In(loc)
		key := t.Truncate(bucket).Unix()
		a, ok := buckets[key]
		if !ok {
			a = &acc{}
			buckets[key] = a
			order = append(order, key)
		}
		a.dSum += s.D
		a.uSum += s.U
		a.n++
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	out := make([]map[string]any, 0, len(order))
	for _, key := range order {
		a := buckets[key]
		if a.n == 0 {
			continue
		}
		t := time.Unix(key, 0).In(loc)
		out = append(out, map[string]any{
			"timestamp":    t.Format(time.RFC3339),
			"label":        t.Format("15:04"),
			"downloadRate": a.dSum / int64(a.n),
			"uploadRate":   a.uSum / int64(a.n),
		})
	}
	return out
}

func peakFromBucketed(bucketed []map[string]any) (peakD, peakU int64) {
	for _, pt := range bucketed {
		d, _ := pt["downloadRate"].(int64)
		u, _ := pt["uploadRate"].(int64)
		if d > peakD {
			peakD = d
		}
		if u > peakU {
			peakU = u
		}
	}
	return peakD, peakU
}

func (h *Handlers) BandwidthHistoryAPI(w http.ResponseWriter, r *http.Request) {
	mode := strings.TrimSpace(r.URL.Query().Get("mode"))
	if mode == "" {
		mode = "hourly"
	}

	type hourlyPoint struct {
		Timestamp    string `json:"timestamp"`
		Label        string `json:"label"`
		DownloadRate int64  `json:"downloadRate"`
		UploadRate   int64  `json:"uploadRate"`
	}
	type dailyPoint struct {
		Day           int    `json:"day"`
		Label         string `json:"label"`
		Timestamp     string `json:"timestamp"`
		DownloadTotal int64  `json:"downloadTotal"`
		UploadTotal   int64  `json:"uploadTotal"`
		CombinedTotal int64  `json:"combinedTotal"`
		IsToday       bool   `json:"isToday"`
	}
	type summary struct {
		DownloadTotal     int64 `json:"downloadTotal"`
		UploadTotal       int64 `json:"uploadTotal"`
		CombinedTotal     int64 `json:"combinedTotal"`
		PeakDownloadRate  int64 `json:"peakDownloadRate"`
		PeakUploadRate    int64 `json:"peakUploadRate"`
		PeakDailyDownload int64 `json:"peakDailyDownload"`
		PeakDailyUpload   int64 `json:"peakDailyUpload"`
		SnapshotCount     int   `json:"snapshotCount"`
		HasData           bool  `json:"hasData"`
	}

	now := time.Now()
	loc := now.Location()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	maxGap := 2 * time.Duration(h.svc.Config.WGInterval) * time.Second
	if maxGap <= 0 {
		maxGap = 60 * time.Second
	}

	writeBW := func(mode string, history any, sum summary) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"mode":    mode,
			"history": history,
			"summary": sum,
		})
	}

	if mode == "daily" {
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
		snaps, err := loadBandwidthSnapshots(h.svc.DB, start)
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
			return
		}

		byDayD := map[int]int64{}
		byDayU := map[int]int64{}
		for i := 0; i < len(snaps)-1; i++ {
			a, b := snaps[i], snaps[i+1]
			dt := b.T.Sub(a.T)
			if dt <= 0 {
				continue
			}
			if dt > maxGap {
				dt = maxGap
			}
			sec := int64(dt.Seconds())
			day := a.T.In(loc).Day()
			byDayD[day] += a.D * sec
			byDayU[day] += a.U * sec
		}

		today := now.Day()
		var out []dailyPoint
		var sumD, sumU int64
		var peakDayD, peakDayU int64
		for day := 1; day <= today; day++ {
			d := byDayD[day]
			u := byDayU[day]
			if d > peakDayD {
				peakDayD = d
			}
			if u > peakDayU {
				peakDayU = u
			}
			sumD += d
			sumU += u
			ts := time.Date(now.Year(), now.Month(), day, 0, 0, 0, 0, loc).Format(time.RFC3339)
			out = append(out, dailyPoint{
				Day:           day,
				Label:         strconv.Itoa(day),
				Timestamp:     ts,
				DownloadTotal: d,
				UploadTotal:   u,
				CombinedTotal: d + u,
				IsToday:       day == today,
			})
		}

		writeBW("daily", out, summary{
			DownloadTotal:     sumD,
			UploadTotal:       sumU,
			CombinedTotal:     sumD + sumU,
			PeakDailyDownload: peakDayD,
			PeakDailyUpload:   peakDayU,
			SnapshotCount:     len(snaps),
			HasData:           len(snaps) > 0,
		})
		return
	}

	hours := 24
	if v := strings.TrimSpace(r.URL.Query().Get("hours")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 24*14 {
			hours = n
		}
	}
	since := now.Add(-time.Duration(hours) * time.Hour)
	snaps, err := loadBandwidthSnapshots(h.svc.DB, since)
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}

	dTotal, uTotal := integrateBandwidthBytes(snaps, maxGap)

	bucketed := bucketBandwidthRates(snaps, 15*time.Minute, loc)
	peakD, peakU := peakFromBucketed(bucketed)
	var out []hourlyPoint
	for _, pt := range bucketed {
		out = append(out, hourlyPoint{
			Timestamp:    pt["timestamp"].(string),
			Label:        pt["label"].(string),
			DownloadRate: pt["downloadRate"].(int64),
			UploadRate:   pt["uploadRate"].(int64),
		})
	}

	writeBW("hourly", out, summary{
		DownloadTotal:    dTotal,
		UploadTotal:      uTotal,
		CombinedTotal:    dTotal + uTotal,
		PeakDownloadRate: peakD,
		PeakUploadRate:   peakU,
		SnapshotCount:    len(snaps),
		HasData:          len(snaps) > 0,
	})
}

func (h *Handlers) UIStatsPartial(w http.ResponseWriter, r *http.Request) {
	type stats struct {
		TotalUsers     int
		EnabledUsers   int
		ConnectedUsers int
		ActiveServers  int
	}
	var s stats
	_ = h.svc.DB.QueryRow(`SELECT COUNT(*) FROM vpn_users`).Scan(&s.TotalUsers)
	_ = h.svc.DB.QueryRow(`SELECT COUNT(*) FROM vpn_users WHERE is_enabled = 1`).Scan(&s.EnabledUsers)
	_ = h.svc.DB.QueryRow(`SELECT COUNT(*) FROM vpn_users WHERE is_connected = 1`).Scan(&s.ConnectedUsers)
	_ = h.svc.DB.QueryRow(`SELECT COUNT(*) FROM vpn_servers WHERE is_active = 1`).Scan(&s.ActiveServers)

	view.RenderPartial(w, r, "partials/ui_stats.tmpl", view.M{
		"Stats": s,
	})
}

func (h *Handlers) ActiveConnectionsPartial(w http.ResponseWriter, r *http.Request) {
	rows, err := h.svc.DB.Query(`
		SELECT u.username, u.endpoint, u.last_handshake, u.total_bytes_received, u.total_bytes_sent,
		  s.name, s.protocol, s.port
		FROM vpn_users u
		LEFT JOIN vpn_servers s ON s.id = u.server_id
		WHERE u.is_connected = 1 AND u.is_enabled = 1
		ORDER BY u.connected_at DESC
		LIMIT 200
	`)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type row struct {
		Username       string
		Endpoint       string
		LastHandshake  string
		TotalRx        int64
		TotalTx        int64
		ServerTitle    string
		ServerSubtitle string
	}
	var out []row
	for rows.Next() {
		var rec row
		var endpoint, hs sql.NullString
		var serverName, serverProto sql.NullString
		var serverPort sql.NullInt64
		if err := rows.Scan(
			&rec.Username, &endpoint, &hs,
			&rec.TotalRx, &rec.TotalTx,
			&serverName, &serverProto, &serverPort,
		); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if endpoint.Valid {
			rec.Endpoint = endpoint.String
		}
		if hs.Valid {
			rec.LastHandshake = hs.String
		}
		rec.ServerTitle = "WireGuard Server"
		if serverName.Valid && strings.TrimSpace(serverName.String) != "" {
			rec.ServerTitle = strings.TrimSpace(serverName.String)
		}
		proto := "wireguard"
		if serverProto.Valid && strings.TrimSpace(serverProto.String) != "" {
			proto = strings.TrimSpace(serverProto.String)
		}
		rec.ServerSubtitle = strings.ToUpper(proto)
		if serverPort.Valid {
			rec.ServerSubtitle += fmt.Sprintf(" • Port %d", serverPort.Int64)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	view.RenderPartial(w, r, "partials/active_connections.tmpl", view.M{
		"Connections": out,
	})
}

func intToString(n int) string {
	return strconv.Itoa(n)
}

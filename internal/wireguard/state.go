package wireguard

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"netplug-go/internal/db"
)

type WireGuardConfig struct {
	Enabled             bool   `json:"enabled"`
	ServerHost          string `json:"serverHost"`
	ServerPort          int    `json:"serverPort"`
	ServerAddress       string `json:"serverAddress"`
	ClientAddressRange  string `json:"clientAddressRange"`
	DNS                 string `json:"dns"`
	MTU                 int    `json:"mtu"`
	PersistentKeepalive int    `json:"persistentKeepalive"`
	AllowedIPs          string `json:"allowedIps"`
	PreUp               string `json:"preUp,omitempty"`
	PreDown             string `json:"preDown,omitempty"`
	PostUp              string `json:"postUp,omitempty"`
	PostDown            string `json:"postDown,omitempty"`
}

type WireGuardServer struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Protocol   string  `json:"protocol"`
	Host       string  `json:"host"`
	Port       int     `json:"port"`
	ConfigPath string  `json:"configPath"`
	IsActive   bool    `json:"isActive"`
	PrivateKey *string `json:"privateKey"`
	PublicKey  *string `json:"publicKey"`
}

type WireGuardLiveStatus struct {
	Up            bool    `json:"up"`
	InterfaceName *string `json:"interfaceName,omitempty"`
	ListenPort    *int    `json:"listenPort,omitempty"`
}

type WireGuardUpdate struct {
	Config           WireGuardConfig
	ServerPrivateKey string
}

type SaveResult struct {
	Type       string
	Text       string
	WroteConfig bool
	Applied    bool
}

func LoadWireGuardState(sqlDB *sql.DB, configuredInterface string, startedAt time.Time) (cfg WireGuardConfig, server *WireGuardServer, live WireGuardLiveStatus, hostUptimeSeconds int64, tunnelUptimeSeconds *int64, err error) {
	sys, err := db.GetSystemConfig(sqlDB)
	if err != nil {
		return cfg, nil, live, 0, nil, err
	}
	if !sys.IsSetupComplete {
		return cfg, nil, live, 0, nil, errors.New("WireGuard is not configured yet. Finish setup first.")
	}
	if len(sys.VPNConfigJSON) == 0 {
		return cfg, nil, live, 0, nil, errors.New("WireGuard configuration is missing from the server.")
	}
	var wrap struct {
		WireGuard WireGuardConfig `json:"wireGuard"`
	}
	if err := json.Unmarshal(sys.VPNConfigJSON, &wrap); err != nil {
		return cfg, nil, live, 0, nil, err
	}
	cfg = wrap.WireGuard
	if !cfg.Enabled {
		return cfg, nil, live, 0, nil, errors.New("WireGuard is disabled.")
	}

	srv, err := loadServer(sqlDB)
	if err == nil {
		server = &srv
	}

	live = GetLiveStatus(configuredInterface)
	hostUptimeSeconds = int64(time.Since(startedAt).Seconds())
	tunnelUptimeSeconds = GetTunnelUptimeSeconds(live)
	return cfg, server, live, hostUptimeSeconds, tunnelUptimeSeconds, nil
}

func SaveWireGuardState(sqlDB *sql.DB, dataDir string, configuredInterface string, upd WireGuardUpdate) (SaveResult, error) {
	if sqlDB == nil {
		return SaveResult{}, errors.New("db is nil")
	}
	upd.Config.Enabled = true

	// Update system_config JSON.
	payload := map[string]any{
		"wireGuard": upd.Config,
	}
	if err := db.UpsertSystemConfig(sqlDB, true, payload); err != nil {
		return SaveResult{}, err
	}

	// Update server record.
	if err := upsertServerFromConfig(sqlDB, dataDir, upd.Config, upd.ServerPrivateKey); err != nil {
		return SaveResult{}, err
	}

	writeErr := WriteWireGuardConfig(sqlDB, dataDir)
	appliedErr := ApplyConfig(dataDir, configuredInterface)

	res := SaveResult{
		Type:        "success",
		Text:        "Configuration saved successfully!",
		WroteConfig: writeErr == nil,
		Applied:     appliedErr == nil,
	}
	if writeErr != nil || appliedErr != nil {
		res.Type = "error"
		if writeErr != nil {
			res.Text = "Saved, but failed to write wg0.conf: " + writeErr.Error()
		} else {
			res.Text = "Saved, but failed to reload WireGuard: " + appliedErr.Error()
		}
	}
	return res, nil
}

func ReloadWireGuard(sqlDB *sql.DB, dataDir string, configuredInterface string) (SaveResult, error) {
	if err := WriteWireGuardConfig(sqlDB, dataDir); err != nil {
		return SaveResult{}, err
	}
	if err := ApplyConfig(dataDir, configuredInterface); err != nil {
		return SaveResult{}, err
	}
	return SaveResult{
		Type:        "success",
		Text:        "WireGuard reloaded. Peer and key changes are now active.",
		WroteConfig: true,
		Applied:     true,
	}, nil
}

func RestartWireGuard(sqlDB *sql.DB, dataDir string, configuredInterface string) (SaveResult, error) {
	if err := WriteWireGuardConfig(sqlDB, dataDir); err != nil {
		return SaveResult{}, err
	}
	if err := RestartConfig(dataDir, configuredInterface); err != nil {
		return SaveResult{}, err
	}
	return SaveResult{
		Type:        "success",
		Text:        "WireGuard restarted. All settings are now active.",
		WroteConfig: true,
		Applied:     true,
	}, nil
}

func loadServer(sqlDB *sql.DB) (WireGuardServer, error) {
	var (
		id, name, protocol, host, configPath string
		port                                  sql.NullInt64
		isActive                               int
		priv, pub                              sql.NullString
	)
	err := sqlDB.QueryRow(`
		SELECT id, name, protocol, host, port, config_path, is_active, private_key, public_key
		FROM vpn_servers
		WHERE id='wireguard'
		LIMIT 1
	`).Scan(&id, &name, &protocol, &host, &port, &configPath, &isActive, &priv, &pub)
	if err != nil {
		return WireGuardServer{}, err
	}
	var pk *string
	var pubk *string
	if priv.Valid && priv.String != "" {
		s := priv.String
		pk = &s
	}
	if pub.Valid && pub.String != "" {
		s := pub.String
		pubk = &s
	}
	p := 0
	if port.Valid {
		p = int(port.Int64)
	}
	return WireGuardServer{
		ID:         id,
		Name:       name,
		Protocol:   protocol,
		Host:       host,
		Port:       p,
		ConfigPath: configPath,
		IsActive:   isActive != 0,
		PrivateKey: pk,
		PublicKey:  pubk,
	}, nil
}

func upsertServerFromConfig(sqlDB *sql.DB, dataDir string, cfg WireGuardConfig, serverPrivateKey string) error {
	if stringsTrim(serverPrivateKey) == "" {
		// keep existing key if not provided
		_, err := sqlDB.Exec(`
			UPDATE vpn_servers
			SET host=?, port=?, updated_at=datetime('now')
			WHERE id='wireguard'
		`, cfg.ServerHost, cfg.ServerPort)
		return err
	}

	k, err := wgtypes.ParseKey(serverPrivateKey)
	if err != nil {
		return errors.New("invalid server private key")
	}
	pub := k.PublicKey().String()
	_, err = sqlDB.Exec(`
		UPDATE vpn_servers
		SET host=?, port=?, private_key=?, public_key=?, updated_at=datetime('now')
		WHERE id='wireguard'
	`, cfg.ServerHost, cfg.ServerPort, serverPrivateKey, pub)
	if err != nil {
		return err
	}
	return nil
}

func stringsTrim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}


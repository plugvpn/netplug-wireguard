package wireguard

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"netplug-go/internal/db"
)

const BackupVersion = 1

type BackupFile struct {
	Version          int             `json:"version"`
	ExportedAt       string          `json:"exportedAt"`
	VPNConfiguration json.RawMessage `json:"vpnConfiguration"`
	Server           BackupServer    `json:"server"`
	Peers            []BackupPeer    `json:"peers"`
	Groups           []BackupGroup   `json:"groups,omitempty"`
}

type BackupServer struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	PrivateKey string `json:"privateKey,omitempty"`
	PublicKey  string `json:"publicKey,omitempty"`
}

type BackupPeer struct {
	Username               string  `json:"username"`
	AllowedIPs             string  `json:"allowedIps"`
	PrivateKey             string  `json:"privateKey,omitempty"`
	PublicKey              string  `json:"publicKey"`
	PresharedKey           string  `json:"presharedKey,omitempty"`
	IsEnabled              bool    `json:"isEnabled"`
	RemainingDays          *int    `json:"remainingDays,omitempty"`
	RemainingTrafficBytes  *int64  `json:"remainingTrafficBytes,omitempty"`
	Endpoint               string  `json:"endpoint,omitempty"`
	LastHandshake          string  `json:"lastHandshake,omitempty"`
	BytesReceived          int64   `json:"bytesReceived,omitempty"`
	BytesSent              int64   `json:"bytesSent,omitempty"`
	TotalBytesReceived     int64   `json:"totalBytesReceived,omitempty"`
	TotalBytesSent         int64   `json:"totalBytesSent,omitempty"`
	IsConnected            bool    `json:"isConnected,omitempty"`
	ConnectedAt            string  `json:"connectedAt,omitempty"`
}

type BackupGroup struct {
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Members     []string            `json:"members"`
	PCQ         *BackupGroupPCQ     `json:"pcq,omitempty"`
}

type BackupGroupPCQ struct {
	DownloadLimitKbps  *int   `json:"downloadLimitKbps,omitempty"`
	UploadLimitKbps    *int   `json:"uploadLimitKbps,omitempty"`
	BurstDownloadKbps  *int   `json:"burstDownloadKbps,omitempty"`
	BurstUploadKbps    *int   `json:"burstUploadKbps,omitempty"`
	Classifier         string `json:"classifier,omitempty"`
	IsDisabled         bool   `json:"isDisabled"`
}

type RestoreOptions struct {
	ReplacePeers  bool
	ReplaceGroups bool
}

func ExportBackup(sqlDB *sql.DB) (BackupFile, error) {
	if sqlDB == nil {
		return BackupFile{}, errors.New("db is nil")
	}

	sys, err := db.GetSystemConfig(sqlDB)
	if err != nil {
		return BackupFile{}, err
	}
	if len(sys.VPNConfigJSON) == 0 {
		return BackupFile{}, errors.New("wireguard is not configured")
	}

	var (
		name, protocol, host string
		port                 sql.NullInt64
		priv, pub            sql.NullString
	)
	err = sqlDB.QueryRow(`
		SELECT name, protocol, host, port, private_key, public_key
		FROM vpn_servers WHERE id = 'wireguard' LIMIT 1
	`).Scan(&name, &protocol, &host, &port, &priv, &pub)
	if err != nil {
		return BackupFile{}, fmt.Errorf("wireguard server record: %w", err)
	}

	server := BackupServer{
		Name:     name,
		Protocol: protocol,
		Host:     host,
	}
	if port.Valid {
		server.Port = int(port.Int64)
	}
	if priv.Valid {
		server.PrivateKey = priv.String
	}
	if pub.Valid {
		server.PublicKey = pub.String
	}

	peers, err := exportPeers(sqlDB)
	if err != nil {
		return BackupFile{}, err
	}
	groups, err := exportGroups(sqlDB)
	if err != nil {
		return BackupFile{}, err
	}

	return BackupFile{
		Version:          BackupVersion,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		VPNConfiguration: append(json.RawMessage(nil), sys.VPNConfigJSON...),
		Server:           server,
		Peers:            peers,
		Groups:           groups,
	}, nil
}

// ExportBackupArchive builds a full backup. When password is non-empty the file is encrypted.
func ExportBackupArchive(sqlDB *sql.DB, password string) ([]byte, error) {
	file, err := ExportBackup(sqlDB)
	if err != nil {
		return nil, err
	}
	plain, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, err
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return plain, nil
	}
	if err := ValidateBackupPassword(password); err != nil {
		return nil, err
	}
	return EncryptBackupPayload(plain, password)
}

// ParseBackupArchive reads an encrypted or plain full backup file.
func ParseBackupArchive(data []byte, password string) (BackupFile, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return BackupFile{}, errors.New("backup file is empty")
	}

	var plain []byte
	if IsEncryptedBackupEnvelope(data) {
		var err error
		plain, err = DecryptBackupPayload(data, password)
		if err != nil {
			return BackupFile{}, err
		}
	} else {
		plain = data
	}

	var file BackupFile
	if err := json.Unmarshal(plain, &file); err != nil {
		return BackupFile{}, errors.New("invalid backup file")
	}
	if file.Version != BackupVersion {
		return BackupFile{}, fmt.Errorf("unsupported backup version %d", file.Version)
	}
	return file, nil
}

func exportPeers(sqlDB *sql.DB) ([]BackupPeer, error) {
	rows, err := sqlDB.Query(`
		SELECT username, allowed_ips, private_key, public_key, preshared_key,
		       is_enabled, remaining_days, remaining_traffic_bytes,
		       endpoint, last_handshake, bytes_received, bytes_sent,
		       total_bytes_received, total_bytes_sent, is_connected, connected_at
		FROM vpn_users WHERE server_id = 'wireguard'
		ORDER BY username ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peers []BackupPeer
	for rows.Next() {
		var p BackupPeer
		var allowed, priv, pub, psk sql.NullString
		var remDays sql.NullInt64
		var remTraffic sql.NullInt64
		var isEnabled int

		var endpoint, lastHS, connectedAt sql.NullString
		var isConnected int
		if err := rows.Scan(
			&p.Username, &allowed, &priv, &pub, &psk,
			&isEnabled, &remDays, &remTraffic,
			&endpoint, &lastHS, &p.BytesReceived, &p.BytesSent,
			&p.TotalBytesReceived, &p.TotalBytesSent, &isConnected, &connectedAt,
		); err != nil {
			return nil, err
		}
		if endpoint.Valid {
			p.Endpoint = endpoint.String
		}
		if lastHS.Valid {
			p.LastHandshake = lastHS.String
		}
		if connectedAt.Valid {
			p.ConnectedAt = connectedAt.String
		}
		p.IsConnected = isConnected != 0

		if allowed.Valid {
			p.AllowedIPs = allowed.String
		}
		if priv.Valid {
			p.PrivateKey = priv.String
		}
		if pub.Valid {
			p.PublicKey = pub.String
		}
		if psk.Valid {
			p.PresharedKey = psk.String
		}
		p.IsEnabled = isEnabled != 0
		if remDays.Valid {
			n := int(remDays.Int64)
			p.RemainingDays = &n
		}
		if remTraffic.Valid {
			n := remTraffic.Int64
			p.RemainingTrafficBytes = &n
		}
		peers = append(peers, p)
	}
	return peers, rows.Err()
}

func exportGroups(sqlDB *sql.DB) ([]BackupGroup, error) {
	rows, err := sqlDB.Query(`
		SELECT g.id, g.name, COALESCE(g.description, ''), u.username
		FROM vpn_groups g
		LEFT JOIN vpn_group_members m ON m.group_id = g.id
		LEFT JOIN vpn_users u ON u.id = m.vpn_user_id
		ORDER BY g.name ASC, u.username ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byName := map[string]*BackupGroup{}
	var order []string
	for rows.Next() {
		var gid, name, desc, username string
		if err := rows.Scan(&gid, &name, &desc, &username); err != nil {
			return nil, err
		}
		g, ok := byName[name]
		if !ok {
			g = &BackupGroup{Name: name, Description: desc}
			byName[name] = g
			order = append(order, name)
		}
		if strings.TrimSpace(username) != "" {
			g.Members = append(g.Members, username)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, name := range order {
		g := byName[name]
		pcq, err := loadGroupPCQ(sqlDB, name)
		if err != nil {
			return nil, err
		}
		g.PCQ = pcq
	}

	out := make([]BackupGroup, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out, nil
}

func loadGroupPCQ(sqlDB *sql.DB, groupName string) (*BackupGroupPCQ, error) {
	var (
		dl, ul, bdl, bul sql.NullInt64
		classifier       string
		isDisabled       int
	)
	err := sqlDB.QueryRow(`
		SELECT p.download_limit_kbps, p.upload_limit_kbps,
		       p.burst_download_kbps, p.burst_upload_kbps,
		       p.pcq_classifier, p.is_disabled
		FROM vpn_group_pcq p
		JOIN vpn_groups g ON g.id = p.group_id
		WHERE g.name = ?
		LIMIT 1
	`, groupName).Scan(&dl, &ul, &bdl, &bul, &classifier, &isDisabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pcq := &BackupGroupPCQ{Classifier: classifier, IsDisabled: isDisabled != 0}
	if dl.Valid {
		n := int(dl.Int64)
		pcq.DownloadLimitKbps = &n
	}
	if ul.Valid {
		n := int(ul.Int64)
		pcq.UploadLimitKbps = &n
	}
	if bdl.Valid {
		n := int(bdl.Int64)
		pcq.BurstDownloadKbps = &n
	}
	if bul.Valid {
		n := int(bul.Int64)
		pcq.BurstUploadKbps = &n
	}
	return pcq, nil
}

func RestoreBackup(sqlDB *sql.DB, dataDir string, configuredInterface string, file BackupFile, opts RestoreOptions) error {
	if sqlDB == nil {
		return errors.New("db is nil")
	}
	if file.Version != BackupVersion {
		return fmt.Errorf("unsupported backup version %d", file.Version)
	}
	if len(file.VPNConfiguration) == 0 {
		return errors.New("backup is missing vpn configuration")
	}
	if strings.TrimSpace(file.Server.Host) == "" {
		return errors.New("backup is missing server host")
	}

	var wrap struct {
		WireGuard WireGuardConfig `json:"wireGuard"`
	}
	if err := json.Unmarshal(file.VPNConfiguration, &wrap); err != nil {
		return fmt.Errorf("invalid vpn configuration: %w", err)
	}
	if err := db.UpsertSystemConfig(sqlDB, true, map[string]any{"wireGuard": wrap.WireGuard}); err != nil {
		return err
	}

	if err := restoreServer(sqlDB, dataDir, wrap.WireGuard, file.Server); err != nil {
		return err
	}

	tx, err := sqlDB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if opts.ReplacePeers {
		if _, err := tx.Exec(`DELETE FROM vpn_users WHERE server_id = 'wireguard'`); err != nil {
			return err
		}
	}
	if opts.ReplaceGroups {
		if _, err := tx.Exec(`DELETE FROM vpn_group_members`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM vpn_group_pcq`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM vpn_groups`); err != nil {
			return err
		}
	}

	for _, p := range file.Peers {
		if err := restorePeer(tx, p); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	if len(file.Groups) > 0 {
		if err := restoreGroups(sqlDB, file.Groups); err != nil {
			return err
		}
	}

	if err := WriteWireGuardConfig(sqlDB, dataDir); err != nil {
		return err
	}
	return RestartConfig(dataDir, configuredInterface)
}

func restoreServer(sqlDB *sql.DB, dataDir string, cfg WireGuardConfig, server BackupServer) error {
	host := strings.TrimSpace(cfg.ServerHost)
	if host == "" {
		host = strings.TrimSpace(server.Host)
	}
	port := cfg.ServerPort
	if port == 0 {
		port = server.Port
	}
	priv := strings.TrimSpace(server.PrivateKey)
	if priv != "" {
		k, err := wgtypes.ParseKey(priv)
		if err != nil {
			return errors.New("invalid server private key in backup")
		}
		pub := k.PublicKey().String()
		_, err = sqlDB.Exec(`
			UPDATE vpn_servers
			SET host=?, port=?, private_key=?, public_key=?, updated_at=datetime('now')
			WHERE id='wireguard'
		`, host, port, priv, pub)
		return err
	}
	configPath := filepath.Join(dataDir, "wg0.conf")
	_, err := sqlDB.Exec(`
		INSERT INTO vpn_servers (id, name, protocol, host, port, config_path, is_active)
		VALUES ('wireguard', 'WireGuard Server', 'wireguard', ?, ?, ?, 1)
		ON CONFLICT(id) DO UPDATE SET
		  host = excluded.host,
		  port = excluded.port,
		  config_path = excluded.config_path,
		  is_active = 1,
		  updated_at = datetime('now')
	`, host, port, configPath)
	return err
}

func restorePeer(tx *sql.Tx, p BackupPeer) error {
	pub := strings.TrimSpace(p.PublicKey)
	allowed := strings.TrimSpace(p.AllowedIPs)
	if pub == "" || allowed == "" {
		return nil
	}
	username := strings.TrimSpace(p.Username)
	if username == "" {
		username = pub
	}
	isEnabled := 0
	if p.IsEnabled {
		isEnabled = 1
	}

	_, err := tx.Exec(`
		INSERT INTO vpn_users (
		  id, username, allowed_ips, private_key, public_key, preshared_key,
		  remaining_days, remaining_traffic_bytes, endpoint, last_handshake,
		  bytes_received, bytes_sent, total_bytes_received, total_bytes_sent,
		  is_connected, connected_at, server_id, is_enabled
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'wireguard', ?)
		ON CONFLICT(username) DO UPDATE SET
		  allowed_ips = excluded.allowed_ips,
		  private_key = COALESCE(excluded.private_key, vpn_users.private_key),
		  public_key = excluded.public_key,
		  preshared_key = excluded.preshared_key,
		  remaining_days = excluded.remaining_days,
		  remaining_traffic_bytes = excluded.remaining_traffic_bytes,
		  endpoint = excluded.endpoint,
		  last_handshake = excluded.last_handshake,
		  bytes_received = excluded.bytes_received,
		  bytes_sent = excluded.bytes_sent,
		  total_bytes_received = excluded.total_bytes_received,
		  total_bytes_sent = excluded.total_bytes_sent,
		  is_connected = excluded.is_connected,
		  connected_at = excluded.connected_at,
		  server_id = 'wireguard',
		  is_enabled = excluded.is_enabled,
		  updated_at = datetime('now')
	`, NewID(), username, allowed, nullStr(p.PrivateKey), pub, nullStr(p.PresharedKey),
		p.RemainingDays, p.RemainingTrafficBytes, nullStr(p.Endpoint), nullStr(p.LastHandshake),
		p.BytesReceived, p.BytesSent, p.TotalBytesReceived, p.TotalBytesSent,
		boolInt(p.IsConnected), nullStr(p.ConnectedAt), isEnabled)
	return err
}

func restoreGroups(sqlDB *sql.DB, groups []BackupGroup) error {
	for _, g := range groups {
		name := strings.TrimSpace(g.Name)
		if name == "" {
			continue
		}
		groupID := NewID()
		_, err := sqlDB.Exec(`
			INSERT INTO vpn_groups (id, name, description)
			VALUES (?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET
			  description = excluded.description,
			  updated_at = datetime('now')
		`, groupID, name, strings.TrimSpace(g.Description))
		if err != nil {
			return err
		}
		var resolvedID string
		if err := sqlDB.QueryRow(`SELECT id FROM vpn_groups WHERE name = ? LIMIT 1`, name).Scan(&resolvedID); err != nil {
			return err
		}

		for _, member := range g.Members {
			member = strings.TrimSpace(member)
			if member == "" {
				continue
			}
			var userID string
			if err := sqlDB.QueryRow(`SELECT id FROM vpn_users WHERE username = ? LIMIT 1`, member).Scan(&userID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				return err
			}
			_, err = sqlDB.Exec(`
				INSERT INTO vpn_group_members (group_id, vpn_user_id)
				VALUES (?, ?)
				ON CONFLICT(group_id, vpn_user_id) DO NOTHING
			`, resolvedID, userID)
			if err != nil {
				return err
			}
		}

		if g.PCQ != nil {
			p := g.PCQ
			_, err = sqlDB.Exec(`
				INSERT INTO vpn_group_pcq (
				  group_id, download_limit_kbps, upload_limit_kbps,
				  burst_download_kbps, burst_upload_kbps, pcq_classifier, is_disabled
				)
				VALUES (?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(group_id) DO UPDATE SET
				  download_limit_kbps = excluded.download_limit_kbps,
				  upload_limit_kbps = excluded.upload_limit_kbps,
				  burst_download_kbps = excluded.burst_download_kbps,
				  burst_upload_kbps = excluded.burst_upload_kbps,
				  pcq_classifier = excluded.pcq_classifier,
				  is_disabled = excluded.is_disabled,
				  updated_at = datetime('now')
			`, resolvedID, p.DownloadLimitKbps, p.UploadLimitKbps,
				p.BurstDownloadKbps, p.BurstUploadKbps, defaultClassifier(p.Classifier), boolInt(p.IsDisabled))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func nullStr(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return s
}

func defaultClassifier(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return "dual"
	}
	return c
}

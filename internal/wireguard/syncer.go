package wireguard

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Syncer struct {
	db  *sql.DB
	wgInterface string
	intervalSec int

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewSyncer(db *sql.DB, wgInterface string, intervalSec int) *Syncer {
	return &Syncer{db: db, wgInterface: wgInterface, intervalSec: intervalSec}
}

func (s *Syncer) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.loop(ctx)
	}()
}

func (s *Syncer) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

func (s *Syncer) loop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(s.intervalSec) * time.Second)
	defer ticker.Stop()

	// initial tick
	_ = s.syncOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.syncOnce(ctx)
		}
	}
}

type peer struct {
	PublicKey         string
	Endpoint          string
	AllowedIPs        string
	LatestHandshake   int64
	TransferRx        int64
	TransferTx        int64
	PersistentKeepAlv int64
}

func (s *Syncer) syncOnce(ctx context.Context) error {
	iface, err := actualInterface(ctx, s.wgInterface)
	if err != nil {
		if !errors.Is(err, errNoWG) {
			log.Printf("[wireguard] interface lookup error: %v", err)
		}
		return err
	}
	if iface == "" {
		return nil
	}

	out, err := execWG(ctx, "wg", "show", iface, "dump")
	if err != nil {
		log.Printf("[wireguard] wg show dump failed: %v", err)
		return err
	}

	status, err := parseDump(out)
	if err != nil {
		log.Printf("[wireguard] parse dump failed: %v", err)
		return err
	}

	peerByKey := make(map[string]peer, len(status))
	for _, p := range status {
		peerByKey[p.PublicKey] = p
	}

	now := time.Now()
	timeoutSec := int64(120)
	intervalSec := int64(max(1, s.intervalSec))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, username, public_key, is_connected,
		       bytes_received, bytes_sent, prev_bytes_received, prev_bytes_sent,
		       total_bytes_received, total_bytes_sent,
		       remaining_days, remaining_traffic_bytes, last_day_check, is_enabled
		FROM vpn_users
		WHERE server_id IN (SELECT id FROM vpn_servers WHERE protocol = 'wireguard')
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var (
		totalDownloadRate int64
		totalUploadRate   int64
	)

	for rows.Next() {
		var (
			id, username         string
			publicKey            sql.NullString
			isConnected          int
			bytesRx, bytesTx     int64
			prevRx, prevTx       int64
			totalRx, totalTx     int64
			remainingDays        sql.NullInt64
			remainingTraffic     sql.NullInt64
			lastDayCheck         sql.NullString
			isEnabled            int
		)
		if err := rows.Scan(
			&id, &username, &publicKey, &isConnected,
			&bytesRx, &bytesTx, &prevRx, &prevTx,
			&totalRx, &totalTx,
			&remainingDays, &remainingTraffic, &lastDayCheck, &isEnabled,
		); err != nil {
			return err
		}
		if !publicKey.Valid || publicKey.String == "" {
			continue
		}

		p, ok := peerByKey[publicKey.String]
		if !ok {
			if isConnected != 0 {
				if _, err := tx.ExecContext(ctx, `UPDATE vpn_users SET is_connected = 0, endpoint = NULL, last_handshake = NULL, updated_at = datetime('now') WHERE id = ?`, id); err != nil {
					return err
				}
			}
			continue
		}

		handshakeAge := int64(0)
		if p.LatestHandshake > 0 {
			handshakeAge = time.Now().Unix() - p.LatestHandshake
		}
		connected := p.LatestHandshake > 0 && handshakeAge < timeoutSec
		shouldUpdateConnectedAt := connected && isConnected == 0

		var newConnectedAt any = nil
		if shouldUpdateConnectedAt {
			newConnectedAt = now.UTC().Format(time.RFC3339)
		}

		var lastHandshake any = nil
		if p.LatestHandshake > 0 {
			lastHandshake = time.Unix(p.LatestHandshake, 0).UTC().Format(time.RFC3339)
		}

		// detect counter reset (reconnect / wg restart)
		newTotalRx := totalRx
		newTotalTx := totalTx
		if p.TransferRx < bytesRx || p.TransferTx < bytesTx {
			newTotalRx = totalRx + bytesRx
			newTotalTx = totalTx + bytesTx
		}

		// rate (B/s) based on last tick
		var rxRate, txRate int64
		deltaRx := p.TransferRx - prevRx
		deltaTx := p.TransferTx - prevTx
		if deltaRx >= 0 && deltaTx >= 0 {
			rxRate = deltaRx / intervalSec
			txRate = deltaTx / intervalSec
		}

		// daily decrement remainingDays (best-effort parity)
		var newRemainingDays any = nil
		var newLastDayCheck any = nil
		if remainingDays.Valid {
			rd := remainingDays.Int64
			newRemainingDays = rd
			if rd > 0 {
				if lastDayCheck.Valid {
					if t, err := time.Parse(time.RFC3339, lastDayCheck.String); err == nil {
						days := int64(now.Sub(t).Hours() / 24)
						if days >= 1 {
							newRemainingDays = max64(0, rd-days)
							newLastDayCheck = now.UTC().Format(time.RFC3339)
						} else {
							newLastDayCheck = lastDayCheck.String
						}
					} else {
						newLastDayCheck = now.UTC().Format(time.RFC3339)
					}
				} else {
					newLastDayCheck = now.UTC().Format(time.RFC3339)
				}
			} else {
				newLastDayCheck = lastDayCheck.String
			}
		}

		// traffic quota decrement (best-effort parity)
		var newRemainingTraffic any = nil
		disable := false
		enable := false

		if remainingTraffic.Valid {
			prevTotalUsage := totalRx + totalTx + bytesRx + bytesTx
			curTotalUsage := newTotalRx + newTotalTx + p.TransferRx + p.TransferTx
			usageInc := curTotalUsage - prevTotalUsage
			rem := remainingTraffic.Int64 - usageInc
			if rem <= 0 {
				rem = 0
				disable = true
			}
			newRemainingTraffic = rem
		}

		if remainingDays.Valid {
			if v := asInt64(newRemainingDays); v <= 0 {
				disable = true
			}
		}
		if isEnabled == 0 && !disable {
			hasTraffic := !remainingTraffic.Valid || asInt64(newRemainingTraffic) > 0
			hasDays := !remainingDays.Valid || asInt64(newRemainingDays) > 0
			if hasTraffic && hasDays {
				enable = true
			}
		}

		newIsEnabled := isEnabled
		if disable && isEnabled != 0 {
			newIsEnabled = 0
		}
		if enable && isEnabled == 0 {
			newIsEnabled = 1
		}

		// Note: download=user bytesSentRate; upload=user bytesReceivedRate (matches TS note)
		if connected && newIsEnabled != 0 {
			totalDownloadRate += txRate
			totalUploadRate += rxRate
		}

		_, err = tx.ExecContext(ctx, `
			UPDATE vpn_users SET
			  is_connected = ?,
			  connected_at = COALESCE(?, connected_at),
			  endpoint = ?,
			  last_handshake = ?,
			  bytes_received = ?,
			  bytes_sent = ?,
			  prev_bytes_received = ?,
			  prev_bytes_sent = ?,
			  bytes_received_rate = ?,
			  bytes_sent_rate = ?,
			  total_bytes_received = ?,
			  total_bytes_sent = ?,
			  remaining_days = COALESCE(?, remaining_days),
			  remaining_traffic_bytes = COALESCE(?, remaining_traffic_bytes),
			  last_day_check = COALESCE(?, last_day_check),
			  is_enabled = ?,
			  updated_at = datetime('now')
			WHERE id = ?
		`,
			boolInt(connected),
			newConnectedAt,
			nullIfEmpty(p.Endpoint),
			lastHandshake,
			p.TransferRx,
			p.TransferTx,
			p.TransferRx,
			p.TransferTx,
			rxRate,
			txRate,
			newTotalRx,
			newTotalTx,
			newRemainingDays,
			newRemainingTraffic,
			newLastDayCheck,
			newIsEnabled,
			id,
		)
		if err != nil {
			_ = username
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// snapshot + cleanup (keep ~35 days for monthly dashboard charts)
	_, _ = tx.ExecContext(ctx, `
		INSERT INTO bandwidth_snapshots (id, download_rate, upload_rate, timestamp)
		VALUES (?, ?, ?, datetime('now'))
	`, uuid.NewString(), totalDownloadRate, totalUploadRate)
	_, _ = tx.ExecContext(ctx, `
		DELETE FROM bandwidth_snapshots
		WHERE timestamp < datetime('now', '-35 days')
	`)

	return tx.Commit()
}

var errNoWG = errors.New("wg not available")

func execWG(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", errNoWG
		}
		return "", errors.New(strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func actualInterface(ctx context.Context, configured string) (string, error) {
	out, err := execWG(ctx, "wg", "show", "interfaces")
	if err != nil {
		return "", err
	}
	parts := strings.Fields(strings.TrimSpace(out))
	if len(parts) == 0 {
		return "", nil
	}
	for _, p := range parts {
		if p == configured {
			return p, nil
		}
	}
	// On macOS, wg0 maps to utunX. Best-effort: pick first interface.
	return parts[0], nil
}

func parseDump(output string) ([]peer, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, errors.New("empty dump")
	}
	if len(lines) == 1 {
		return []peer{}, nil
	}
	var peers []peer
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			return nil, errors.New("unexpected peer line format")
		}
		p := peer{
			PublicKey:       fields[0],
			Endpoint:        normalizeNone(fields[2]),
			AllowedIPs:      fields[3],
			LatestHandshake: parseI64(fields[4]),
			TransferRx:      parseI64(fields[5]),
			TransferTx:      parseI64(fields[6]),
			PersistentKeepAlv: parseI64(fields[7]),
		}
		peers = append(peers, p)
	}
	return peers, nil
}

func normalizeNone(v string) string {
	if v == "(none)" {
		return ""
	}
	return v
}

func parseI64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func asInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case nil:
		return 0
	default:
		return 0
	}
}


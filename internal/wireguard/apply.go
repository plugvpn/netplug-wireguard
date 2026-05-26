package wireguard

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ApplyConfig reloads the running WireGuard interface without tearing it down.
// Peer changes (allowed IPs, keys, add/remove) are applied via wg syncconf when the
// interface is already up; otherwise wg-quick up is used.
func ApplyConfig(dataDir string, configuredInterface string) error {
	return reloadConfig(dataDir, configuredInterface)
}

// RestartConfig tears the interface down and brings it back up so interface-level
// settings (listen port, address, hooks, MTU) take effect.
func RestartConfig(dataDir string, configuredInterface string) error {
	confPath := confPathFor(dataDir)
	if _, err := os.Stat(confPath); err != nil {
		return err
	}
	ensureConfigPermissions(confPath)

	iface := activeInterface(confPath, configuredInterface)
	if iface != "" {
		if _, err := execOutTimeout(120*time.Second, "wg-quick", "down", confPath); err != nil {
			if !isInterfaceDown(err) {
				return err
			}
		}
	}
	_, err := execOutTimeout(180*time.Second, "wg-quick", "up", confPath)
	return err
}

// SyncFromDB writes wg0.conf from the database and reloads the running interface.
func SyncFromDB(sqlDB *sql.DB, dataDir string, configuredInterface string) error {
	if err := WriteWireGuardConfig(sqlDB, dataDir); err != nil {
		return err
	}
	return ApplyConfig(dataDir, configuredInterface)
}

func reloadConfig(dataDir string, configuredInterface string) error {
	confPath := confPathFor(dataDir)
	if _, err := os.Stat(confPath); err != nil {
		return err
	}
	ensureConfigPermissions(confPath)

	iface := activeInterface(confPath, configuredInterface)
	if iface == "" {
		_, err := execOutTimeout(180*time.Second, "wg-quick", "up", confPath)
		return err
	}
	return syncconf(iface, confPath)
}

func confPathFor(dataDir string) string {
	return filepath.Join(dataDir, "wg0.conf")
}

func interfaceFromConf(confPath string) string {
	base := filepath.Base(confPath)
	ext := filepath.Ext(base)
	if ext == "" {
		return base
	}
	return strings.TrimSuffix(base, ext)
}

func activeInterface(confPath string, configuredInterface string) string {
	ifaces, _ := execOut("wg", "show", "interfaces")
	return pickInterface(ifaces, configuredInterface, interfaceFromConf(confPath))
}

func syncconf(iface string, confPath string) error {
	ensureConfigPermissions(confPath)
	out, err := execStdoutTimeout(30*time.Second, "wg-quick", "strip", confPath)
	if err != nil {
		return err
	}
	out = cleanWGQuickStripOutput(out)
	if strings.TrimSpace(out) == "" {
		return errors.New("wg-quick strip produced empty peer configuration")
	}
	tmp := confPath + ".peers.tmp"
	if err := os.WriteFile(tmp, []byte(out), 0o600); err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	_, err = execOutTimeout(30*time.Second, "wg", "syncconf", iface, tmp)
	return err
}

func ensureConfigPermissions(confPath string) {
	_ = os.Chmod(confPath, 0o600)
}

func cleanWGQuickStripOutput(raw string) string {
	var b strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "warning:") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func pickInterface(raw string, preferred string, confIface string) string {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 0 {
		return ""
	}
	for _, want := range []string{preferred, confIface} {
		want = strings.TrimSpace(want)
		if want == "" {
			continue
		}
		for _, p := range parts {
			if p == want {
				return p
			}
		}
	}
	return parts[0]
}

func isInterfaceDown(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "is not a wireguard interface") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no such device")
}

func execOut(name string, args ...string) (string, error) {
	return execOutTimeout(10*time.Second, name, args...)
}

func execOutTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	return execStdoutTimeout(timeout, name, args...)
}

func execStdoutTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = os.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg == "" {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				msg = "command timed out"
			} else {
				msg = err.Error()
			}
		}
		return "", errors.New(msg)
	}
	return stdout.String(), nil
}

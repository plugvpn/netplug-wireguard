package dns

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"netplug-go/internal/db"
	"netplug-go/internal/wireguard"
)

// Status is the runtime view of the managed CoreDNS process.
type Status struct {
	Running   bool
	PID       int
	ListenAddr string
	Binary    string
	Corefile  string
	LastError string
}

// Manager starts and stops a CoreDNS instance using a generated Corefile.
type Manager struct {
	mu      sync.Mutex
	dataDir string
	bin     string
	wgIface string
	sqlDB   *sql.DB

	cmd       *exec.Cmd
	running   bool
	lastError string
	listen    string
	corefile  string
}

func NewManager(dataDir, coreDNSBin, wgIface string, sqlDB *sql.DB) *Manager {
	bin := strings.TrimSpace(coreDNSBin)
	if bin == "" {
		bin = "coredns"
	}
	return &Manager{
		dataDir: dataDir,
		bin:     bin,
		wgIface: strings.TrimSpace(wgIface),
		sqlDB:   sqlDB,
	}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{
		Running:   m.running,
		ListenAddr: m.listen,
		Binary:    m.bin,
		Corefile:  m.corefile,
		LastError: m.lastError,
	}
	if m.cmd != nil && m.cmd.Process != nil {
		st.PID = m.cmd.Process.Pid
	}
	return st
}

func (m *Manager) Apply(cfg db.DNSSettings, records []db.DNSRecord, rules []db.DNSDomainRule) error {
	if !cfg.Enabled {
		return m.Stop()
	}
	return m.Start(cfg, records, rules)
}

func (m *Manager) Start(cfg db.DNSSettings, records []db.DNSRecord, rules []db.DNSDomainRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.stopLocked(); err != nil {
		return err
	}

	binRef := strings.TrimSpace(cfg.Binary)
	if binRef == "" {
		binRef = strings.TrimSpace(m.bin)
	}
	if binRef == "" {
		binRef = "coredns"
	}
	bin, err := resolveCoreDNSBinary(binRef)
	if err != nil {
		m.lastError = err.Error()
		return errors.New(m.lastError)
	}
	m.bin = bin

	listen := strings.TrimSpace(cfg.ListenAddr)
	if listen == "" {
		m.lastError = "DNS listen address is not set"
		return errors.New(m.lastError)
	}
	host, port, err := splitListenAddr(listen)
	if err != nil {
		m.lastError = err.Error()
		return err
	}

	if err := wireguard.EnsureDNSInterfaceAlias(wireguard.DNSIfaceOpts{
		DataDir:             m.dataDir,
		ConfiguredInterface: m.wgIface,
		SQLDB:               m.sqlDB,
		Settings:            cfg,
	}); err != nil {
		m.lastError = err.Error()
		return err
	}

	dir := filepath.Join(m.dataDir, "dns")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		m.lastError = err.Error()
		return err
	}

	files, err := prepareZoneFiles(dir, cfg, records, rules, m.dataDir)
	if err != nil {
		m.lastError = err.Error()
		return err
	}

	corefile := filepath.Join(dir, "Corefile")
	body := renderCorefile(host, port, cfg, files)
	if err := os.WriteFile(corefile, []byte(body), 0o644); err != nil {
		m.lastError = err.Error()
		return err
	}

	cmd := exec.Command(bin, "-conf", corefile)
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		m.lastError = err.Error()
		return fmt.Errorf("start coredns: %w", err)
	}

	m.cmd = cmd
	m.running = true
	m.lastError = ""
	m.listen = listen
	m.corefile = corefile

	go m.watchProcess(cmd)
	log.Printf("dns: CoreDNS started (pid %d) listening on %s", cmd.Process.Pid, listen)
	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.stopLocked(); err != nil {
		return err
	}
	if m.sqlDB != nil {
		cfg, err := db.GetDNSSettings(m.sqlDB)
		if err == nil {
			_ = wireguard.RemoveDNSInterfaceAlias(wireguard.DNSIfaceOpts{
				DataDir:             m.dataDir,
				ConfiguredInterface: m.wgIface,
				SQLDB:               m.sqlDB,
				Settings:            cfg,
			})
		}
	}
	return nil
}

func (m *Manager) stopLocked() error {
	if m.cmd == nil || m.cmd.Process == nil {
		m.running = false
		m.cmd = nil
		return nil
	}
	proc := m.cmd.Process
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		_ = proc.Kill()
	}
	done := make(chan error, 1)
	go func() {
		done <- m.cmd.Wait()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = proc.Kill()
		<-done
	}
	m.cmd = nil
	m.running = false
	log.Printf("dns: CoreDNS stopped")
	return nil
}

func (m *Manager) watchProcess(cmd *exec.Cmd) {
	err := cmd.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == cmd {
		m.running = false
		m.cmd = nil
		if err != nil {
			m.lastError = err.Error()
			log.Printf("dns: CoreDNS exited: %v", err)
		}
	}
}

func resolveCoreDNSBinary(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("CoreDNS binary is not set")
	}
	if filepath.IsAbs(name) {
		st, err := os.Stat(name)
		if err != nil {
			return "", fmt.Errorf("CoreDNS binary %q not found", name)
		}
		if st.IsDir() {
			return "", fmt.Errorf("CoreDNS binary %q is a directory", name)
		}
		return name, nil
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("CoreDNS binary %q not found on PATH", name)
	}
	return path, nil
}

func splitListenAddr(addr string) (host, port string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", errors.New("listen address is empty")
	}
	if strings.HasPrefix(addr, ":") {
		return "0.0.0.0", strings.TrimPrefix(addr, ":"), nil
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return host, port, nil
}

func renderCorefile(host, port string, cfg db.DNSSettings, files zoneFiles) string {
	upstreams := strings.TrimSpace(cfg.ForwardUpstreams)
	if upstreams == "" {
		upstreams = "1.1.1.1 1.0.0.1"
	}
	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = db.DefaultDNSCacheTTL
	}
	bindLine := ""
	rootZone := ".:" + port
	if host != "" && host != "0.0.0.0" && host != "::" {
		rootZone = host + ":" + port
		bindLine = "    bind " + host + "\n"
	}
	var blocks strings.Builder
	for _, zb := range files.zoneBlocks {
		if zb.zone == "" || zb.file == "" {
			continue
		}
		zoneListen := zb.zone + ":" + port
		if host != "" && host != "0.0.0.0" && host != "::" {
			zoneListen = host + ":" + port
		}
		fmt.Fprintf(&blocks, `%s {
%s    file %s
    log
    errors
}

`, zoneListen, bindLine, zb.file)
	}
	blockLine := ""
	if strings.TrimSpace(files.blockHosts) != "" {
		blockLine = fmt.Sprintf("    hosts %s {\n        fallthrough\n    }\n", files.blockHosts)
	}
	rewriteLine := ""
	if strings.TrimSpace(files.rewriteHosts) != "" {
		rewriteLine = fmt.Sprintf("    hosts %s {\n        fallthrough\n    }\n", files.rewriteHosts)
	}
	logLine := ""
	if cfg.QueryLogEnabled {
		logLine = "    log\n"
	}
	return fmt.Sprintf(`# Generated by NetPlug — do not edit manually
%s%s {
%s%s%s    forward . %s
    cache %d
%s    errors
}
`, blocks.String(), rootZone, bindLine, blockLine, rewriteLine, upstreams, cacheTTL, logLine)
}

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	systemdUnitName = "pmux-agent.service"
)

// systemdManager manages the agent as a Linux systemd user service.
type systemdManager struct {
	pmuxPath  string
	configDir string
	unitDir   string // override for testing; empty means ~/.config/systemd/user
}

func newSystemdManager(pmuxPath, configDir string) *systemdManager {
	return &systemdManager{pmuxPath: pmuxPath, configDir: configDir}
}

func (m *systemdManager) unitPath() string {
	dir := m.unitDir
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config", "systemd", "user")
	}
	return filepath.Join(dir, systemdUnitName)
}

func (m *systemdManager) generateUnit() string {
	return fmt.Sprintf(`[Unit]
Description=PocketMux Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s agent run
Restart=on-failure
RestartSec=5s
StartLimitBurst=5
StartLimitIntervalSec=60

[Install]
WantedBy=default.target
`, m.pmuxPath)
}

func (m *systemdManager) writeUnit() error {
	path := m.unitPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create systemd user directory: %w", err)
	}
	return os.WriteFile(path, []byte(m.generateUnit()), 0644)
}

func (m *systemdManager) Install() error {
	if err := m.writeUnit(); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	// Reload units, enable, and start
	if err := m.systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := m.systemctl("enable", systemdUnitName); err != nil {
		return err
	}
	return m.systemctl("start", systemdUnitName)
}

func (m *systemdManager) Uninstall() error {
	m.systemctl("stop", systemdUnitName)    //nolint:errcheck
	m.systemctl("disable", systemdUnitName) //nolint:errcheck

	if err := os.Remove(m.unitPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}

	m.systemctl("daemon-reload") //nolint:errcheck
	return nil
}

func (m *systemdManager) Start() error {
	return m.systemctl("start", systemdUnitName)
}

func (m *systemdManager) Stop() error {
	return m.systemctl("stop", systemdUnitName)
}

func (m *systemdManager) Status() (Status, error) {
	cmd := exec.Command("systemctl", "--user", "show", systemdUnitName,
		"--property=ActiveState,MainPID")
	out, err := cmd.Output()
	if err != nil {
		if !m.IsInstalled() {
			return Status{Installed: false}, nil
		}
		return Status{Installed: true, Running: false}, nil
	}

	s := Status{Installed: m.IsInstalled()}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "ActiveState=active") {
			s.Running = true
		}
		if strings.HasPrefix(line, "MainPID=") {
			pidStr := strings.TrimPrefix(line, "MainPID=")
			if pid, err := strconv.Atoi(strings.TrimSpace(pidStr)); err == nil && pid > 0 {
				s.PID = pid
			}
		}
	}
	return s, nil
}

func (m *systemdManager) IsInstalled() bool {
	_, err := os.Stat(m.unitPath())
	return err == nil
}

func (m *systemdManager) systemctl(args ...string) error {
	fullArgs := append([]string{"--user"}, args...)
	cmd := exec.Command("systemctl", fullArgs...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

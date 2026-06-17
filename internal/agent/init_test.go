package agent

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

func TestRunInit_IdentityAlreadyExists(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	cfg := config.Defaults()
	cfg.Name = "existing-host"

	// Pre-generate identity so HasIdentity returns true
	id, err := auth.GenerateIdentity(paths.KeysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	var out bytes.Buffer
	err = RunInit(paths, cfg, store, "/usr/bin/tmux", strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("RunInit: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Identity already exists.") {
		t.Errorf("expected 'Identity already exists.' message, got: %s", output)
	}
	if !strings.Contains(output, id.DeviceID) {
		t.Errorf("expected device ID %q in output, got: %s", id.DeviceID, output)
	}
	if !strings.Contains(output, "Host name: existing-host") {
		t.Errorf("expected host name in output, got: %s", output)
	}
	// Should NOT contain generation messages
	if strings.Contains(output, "Identity generated.") {
		t.Errorf("should not generate new identity, got: %s", output)
	}
}

func TestRunInit_IdentityAlreadyExists_NoName(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	cfg := config.Defaults()
	cfg.Name = "" // no host name configured

	// Pre-generate identity
	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	var out bytes.Buffer
	err := RunInit(paths, cfg, store, "/usr/bin/tmux", strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("RunInit: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Identity already exists.") {
		t.Errorf("expected 'Identity already exists.' message, got: %s", output)
	}
	// Should NOT print host name when cfg.Name is empty
	if strings.Contains(output, "Host name:") {
		t.Errorf("should not print host name when empty, got: %s", output)
	}
}

func TestRunInit_FreshInit_CustomHostname(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	cfg := config.Defaults()
	var out bytes.Buffer
	err := RunInit(paths, cfg, store, "/usr/local/bin/tmux", strings.NewReader("myhost\n"), &out)
	if err != nil {
		t.Fatalf("RunInit: %v", err)
	}

	output := out.String()

	// Should contain generation messages
	if !strings.Contains(output, "Identity generated.") {
		t.Errorf("expected 'Identity generated.' message, got: %s", output)
	}
	if !strings.Contains(output, "Device ID:") {
		t.Errorf("expected 'Device ID:' in output, got: %s", output)
	}
	if !strings.Contains(output, "Host name: myhost") {
		t.Errorf("expected 'Host name: myhost' in output, got: %s", output)
	}
	if !strings.Contains(output, "Keys saved to:") {
		t.Errorf("expected 'Keys saved to:' in output, got: %s", output)
	}

	// Verify config file was written with correct content
	data, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, `name = "myhost"`) {
		t.Errorf("config should contain name = \"myhost\", got: %s", content)
	}
	if !strings.Contains(content, `tmux_path = "/usr/local/bin/tmux"`) {
		t.Errorf("config should contain tmux_path, got: %s", content)
	}
}

func TestRunInit_FreshInit_DefaultHostname(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	cfg := config.Defaults()

	// Empty input → uses default hostname
	var out bytes.Buffer
	err := RunInit(paths, cfg, store, "/usr/bin/tmux", strings.NewReader("\n"), &out)
	if err != nil {
		t.Fatalf("RunInit: %v", err)
	}

	output := out.String()

	defaultName := config.DefaultHostName()
	if !strings.Contains(output, fmt.Sprintf("Host name: %s", defaultName)) {
		t.Errorf("expected default hostname %q in output, got: %s", defaultName, output)
	}

	// Verify config file uses default hostname
	data, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	content := string(data)
	expected := fmt.Sprintf("name = %q", defaultName)
	if !strings.Contains(content, expected) {
		t.Errorf("config should contain %s, got: %s", expected, content)
	}
}

func TestRunInit_EmptyTmuxPath(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	cfg := config.Defaults()
	var out bytes.Buffer
	err := RunInit(paths, cfg, store, "", strings.NewReader("testhost\n"), &out)
	if err != nil {
		t.Fatalf("RunInit: %v", err)
	}

	// Verify config file does NOT contain tmux_path when empty
	data, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	content := string(data)
	// Should not contain an uncommented tmux_path line (comments like "# tmux_path" are OK)
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "tmux_path =") {
			t.Errorf("config should not contain uncommented tmux_path when empty, got line: %s", line)
		}
	}
}

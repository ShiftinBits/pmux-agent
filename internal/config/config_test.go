package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.Server.URL != "https://signal.pmux.io" {
		t.Errorf("Server.URL = %q, want %q", cfg.Server.URL, "https://signal.pmux.io")
	}
	if cfg.Identity.KeyPath != "~/.config/pmux/keys/" {
		t.Errorf("Identity.KeyPath = %q, want %q", cfg.Identity.KeyPath, "~/.config/pmux/keys/")
	}
	if cfg.Connection.ReconnectInterval != "5s" {
		t.Errorf("Connection.ReconnectInterval = %q, want %q", cfg.Connection.ReconnectInterval, "5s")
	}
	if cfg.Connection.KeepaliveInterval != "30s" {
		t.Errorf("Connection.KeepaliveInterval = %q, want %q", cfg.Connection.KeepaliveInterval, "30s")
	}
	if cfg.Connection.MaxMobileConnections != 1 {
		t.Errorf("Connection.MaxMobileConnections = %d, want %d", cfg.Connection.MaxMobileConnections, 1)
	}
	if cfg.Tmux.SocketName != "pmux" {
		t.Errorf("Tmux.SocketName = %q, want %q", cfg.Tmux.SocketName, "pmux")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
}

func TestLoadConfig_Nonexistent(t *testing.T) {
	// Ensure env vars don't interfere
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}

	cfg, err := LoadConfig("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfig() returned error for nonexistent file: %v", err)
	}

	// Should return defaults
	defaults := Defaults()
	if cfg.Server.URL != defaults.Server.URL {
		t.Errorf("Server.URL = %q, want default %q", cfg.Server.URL, defaults.Server.URL)
	}
	if cfg.Connection.MaxMobileConnections != defaults.Connection.MaxMobileConnections {
		t.Errorf("MaxMobileConnections = %d, want default %d", cfg.Connection.MaxMobileConnections, defaults.Connection.MaxMobileConnections)
	}
	if cfg.Tmux.SocketName != defaults.Tmux.SocketName {
		t.Errorf("Tmux.SocketName = %q, want default %q", cfg.Tmux.SocketName, defaults.Tmux.SocketName)
	}
}

func TestLoadConfig_FileOverridesDefaults(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	content := `
name = "work-laptop"
log_level = "debug"

[server]
url = "https://custom.example.com"

[connection]
keepalive_interval = "15s"
max_mobile_connections = 10

[tmux]
socket_name = "custom-socket"
tmux_path = "/usr/local/bin/tmux"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}

	// File values should override defaults
	if cfg.Name != "work-laptop" {
		t.Errorf("Name = %q, want %q", cfg.Name, "work-laptop")
	}
	if cfg.Server.URL != "https://custom.example.com" {
		t.Errorf("Server.URL = %q, want %q", cfg.Server.URL, "https://custom.example.com")
	}
	if cfg.Connection.KeepaliveInterval != "15s" {
		t.Errorf("KeepaliveInterval = %q, want %q", cfg.Connection.KeepaliveInterval, "15s")
	}
	if cfg.Connection.MaxMobileConnections != 10 {
		t.Errorf("MaxMobileConnections = %d, want %d", cfg.Connection.MaxMobileConnections, 10)
	}
	if cfg.Tmux.SocketName != "custom-socket" {
		t.Errorf("Tmux.SocketName = %q, want %q", cfg.Tmux.SocketName, "custom-socket")
	}
	if cfg.Tmux.TmuxPath != "/usr/local/bin/tmux" {
		t.Errorf("Tmux.TmuxPath = %q, want %q", cfg.Tmux.TmuxPath, "/usr/local/bin/tmux")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}

	// Unset file values should retain defaults
	if cfg.Connection.ReconnectInterval != "5s" {
		t.Errorf("ReconnectInterval = %q, want default %q", cfg.Connection.ReconnectInterval, "5s")
	}
	if cfg.Identity.KeyPath != "~/.config/pmux/keys/" {
		t.Errorf("Identity.KeyPath = %q, want default %q", cfg.Identity.KeyPath, "~/.config/pmux/keys/")
	}
}

func TestLoadConfig_EnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	content := `
[server]
url = "https://from-file.example.com"

[connection]
max_mobile_connections = 10

[tmux]
socket_name = "from-file"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	t.Setenv(EnvNewServerURL, "https://from-env.example.com")
	t.Setenv(EnvSocketName, "from-env")
	t.Setenv(EnvMaxConnections, "3")
	t.Setenv(EnvKeyPath, "/custom/keys/")
	t.Setenv(EnvTmuxPath, "")
	t.Setenv(EnvLogLevel, "warn")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}

	// Env vars should override file values
	if cfg.Server.URL != "https://from-env.example.com" {
		t.Errorf("Server.URL = %q, want %q", cfg.Server.URL, "https://from-env.example.com")
	}
	if cfg.Tmux.SocketName != "from-env" {
		t.Errorf("Tmux.SocketName = %q, want %q", cfg.Tmux.SocketName, "from-env")
	}
	if cfg.Connection.MaxMobileConnections != 3 {
		t.Errorf("MaxMobileConnections = %d, want %d", cfg.Connection.MaxMobileConnections, 3)
	}
	if cfg.Identity.KeyPath != "/custom/keys/" {
		t.Errorf("Identity.KeyPath = %q, want %q", cfg.Identity.KeyPath, "/custom/keys/")
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "warn")
	}
}

func TestLoadConfig_TmuxPathEnvOverride(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[tmux]
tmux_path = "/from/file/tmux"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	// Env should override file
	t.Setenv(EnvTmuxPath, "/from/env/tmux")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Tmux.TmuxPath != "/from/env/tmux" {
		t.Errorf("Tmux.TmuxPath = %q, want %q", cfg.Tmux.TmuxPath, "/from/env/tmux")
	}
}

func TestLoadConfig_LegacyEnvVar(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}

	// Legacy PMUX_AGENT_SIGNAL_URL should work when PMUX_SERVER_URL is not set
	t.Setenv(EnvServerURL, "https://legacy.example.com")

	cfg, err := LoadConfig("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Server.URL != "https://legacy.example.com" {
		t.Errorf("Server.URL = %q, want %q", cfg.Server.URL, "https://legacy.example.com")
	}
}

func TestLoadConfig_NewEnvOverridesLegacy(t *testing.T) {
	// When both are set, PMUX_SERVER_URL takes precedence
	t.Setenv(EnvServerURL, "https://legacy.example.com")
	t.Setenv(EnvNewServerURL, "https://new.example.com")

	cfg, err := LoadConfig("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Server.URL != "https://new.example.com" {
		t.Errorf("Server.URL = %q, want %q", cfg.Server.URL, "https://new.example.com")
	}
}

func TestLoadConfig_InvalidMaxConnectionsEnvIgnored(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName} {
		t.Setenv(env, "")
	}
	t.Setenv(EnvMaxConnections, "notanumber")

	cfg, err := LoadConfig("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	// Should keep default since env value can't be parsed
	if cfg.Connection.MaxMobileConnections != 1 {
		t.Errorf("MaxMobileConnections = %d, want default %d", cfg.Connection.MaxMobileConnections, 1)
	}
}

func TestLoadConfig_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	if err := os.WriteFile(path, []byte("this is not valid toml [[["), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig() expected error for invalid TOML, got nil")
	}
}

func TestValidate_ValidDefaults(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() on defaults returned error: %v", err)
	}
}

func TestValidate_InvalidURL_Empty(t *testing.T) {
	cfg := Defaults()
	cfg.Server.URL = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for empty URL, got nil")
	}
}

func TestValidate_InvalidURL_WrongScheme(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"ftp", "ftp://example.com"},
		{"no_scheme", "example.com"},
		{"ssh", "ssh://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Server.URL = tt.url
			if err := cfg.Validate(); err == nil {
				t.Errorf("Validate() expected error for URL %q, got nil", tt.url)
			}
		})
	}
}

func TestValidate_ValidURLSchemes(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"https", "https://signal.pmux.io"},
		{"http", "http://localhost:8787"},
		{"wss", "wss://signal.pmux.io"},
		{"ws", "ws://localhost:8787"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Server.URL = tt.url
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() unexpected error for URL %q: %v", tt.url, err)
			}
		})
	}
}

func TestValidate_InvalidDuration(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{"reconnect_bad_format", "reconnect", "notaduration"},
		{"reconnect_empty", "reconnect", ""},
		{"keepalive_bad_format", "keepalive", "abc"},
		{"keepalive_empty", "keepalive", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			switch tt.field {
			case "reconnect":
				cfg.Connection.ReconnectInterval = tt.value
			case "keepalive":
				cfg.Connection.KeepaliveInterval = tt.value
			}
			if err := cfg.Validate(); err == nil {
				t.Errorf("Validate() expected error for %s = %q, got nil", tt.field, tt.value)
			}
		})
	}
}

func TestValidate_MaxConnectionsRange(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"zero", 0, true},
		{"negative", -1, true},
		{"one", 1, false},
		{"two", 2, true},
		{"five", 5, true},
		{"twenty", 20, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Connection.MaxMobileConnections = tt.value
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() with max_mobile_connections=%d: err=%v, wantErr=%v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestValidate_EmptySocketName(t *testing.T) {
	cfg := Defaults()
	cfg.Tmux.SocketName = ""

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for empty socket_name, got nil")
	}
}

func TestReconnectInterval(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		expect time.Duration
	}{
		{"5s", "5s", 5 * time.Second},
		{"1m", "1m", 1 * time.Minute},
		{"500ms", "500ms", 500 * time.Millisecond},
		{"invalid_fallback", "bad", 5 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Connection.ReconnectInterval = tt.value
			got := cfg.ReconnectInterval()
			if got != tt.expect {
				t.Errorf("ReconnectInterval() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestKeepaliveInterval(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		expect      time.Duration
		wantClamped bool
	}{
		{"30s", "30s", 30 * time.Second, false},
		{"over_cap_clamped", "1m", MaxKeepaliveInterval, true},
		{"10s", "10s", 10 * time.Second, false},
		{"invalid_fallback", "bad", 30 * time.Second, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Connection.KeepaliveInterval = tt.value
			if got := cfg.KeepaliveInterval(); got != tt.expect {
				t.Errorf("KeepaliveInterval() = %v, want %v", got, tt.expect)
			}
			if got := cfg.KeepaliveClamped(); got != tt.wantClamped {
				t.Errorf("KeepaliveClamped() = %v, want %v", got, tt.wantClamped)
			}
		})
	}
}

func TestUpdateCheckInterval(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		expect time.Duration
	}{
		{"24h", "24h", 24 * time.Hour},
		{"1h", "1h", 1 * time.Hour},
		{"30m", "30m", 30 * time.Minute},
		{"empty_fallback", "", 24 * time.Hour},
		{"invalid_fallback", "bad", 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Update.CheckInterval = tt.value
			got := cfg.UpdateCheckInterval()
			if got != tt.expect {
				t.Errorf("UpdateCheckInterval() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestValidate_UpdateCheckInterval(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid_24h", "24h", false},
		{"valid_1h", "1h", false},
		{"valid_empty", "", false}, // empty is allowed (uses default)
		{"invalid", "notaduration", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Update.CheckInterval = tt.value
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() with check_interval=%q: err=%v, wantErr=%v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfigWithSources_AllFieldsFromFile(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel, EnvSecretBackend, EnvUpdateEnabled, EnvUpdateInterval, EnvKeepAwake} {
		t.Setenv(env, "")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	content := `
name = "test-machine"
log_level = "debug"

[server]
url = "https://custom.example.com"

[identity]
key_path = "/custom/keys/"
secret_backend = "file"

[connection]
reconnect_interval = "10s"
keepalive_interval = "15s"
max_mobile_connections = 1

[tmux]
socket_name = "custom-socket"
tmux_path = "/usr/local/bin/tmux"

[update]
enabled = false
check_interval = "12h"

[power]
keep_awake = true
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	_, sources, err := LoadConfigWithSources(path)
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}

	// All fields set in file should have sourceFile
	if sources.Name != sourceFile {
		t.Errorf("Name source = %v, want file", sources.Name)
	}
	if sources.LogLevel != sourceFile {
		t.Errorf("LogLevel source = %v, want file", sources.LogLevel)
	}
	if sources.ServerURL != sourceFile {
		t.Errorf("ServerURL source = %v, want file", sources.ServerURL)
	}
	if sources.KeyPath != sourceFile {
		t.Errorf("KeyPath source = %v, want file", sources.KeyPath)
	}
	if sources.SecretBackend != sourceFile {
		t.Errorf("SecretBackend source = %v, want file", sources.SecretBackend)
	}
	if sources.ReconnectInterval != sourceFile {
		t.Errorf("ReconnectInterval source = %v, want file", sources.ReconnectInterval)
	}
	if sources.KeepaliveInterval != sourceFile {
		t.Errorf("KeepaliveInterval source = %v, want file", sources.KeepaliveInterval)
	}
	if sources.MaxMobileConnections != sourceFile {
		t.Errorf("MaxMobileConnections source = %v, want file", sources.MaxMobileConnections)
	}
	if sources.SocketName != sourceFile {
		t.Errorf("SocketName source = %v, want file", sources.SocketName)
	}
	if sources.TmuxPath != sourceFile {
		t.Errorf("TmuxPath source = %v, want file", sources.TmuxPath)
	}
	if sources.UpdateCheckInterval != sourceFile {
		t.Errorf("UpdateCheckInterval source = %v, want file", sources.UpdateCheckInterval)
	}
	if sources.UpdateEnabled != sourceFile {
		t.Errorf("UpdateEnabled source = %v, want file", sources.UpdateEnabled)
	}
	if sources.KeepAwake != sourceFile {
		t.Errorf("KeepAwake source = %v, want file", sources.KeepAwake)
	}
}

func TestLoadConfigWithSources_AllFieldsFromEnv(t *testing.T) {
	t.Setenv(EnvNewServerURL, "https://env.example.com")
	t.Setenv(EnvKeyPath, "/env/keys/")
	t.Setenv(EnvSocketName, "env-socket")
	t.Setenv(EnvMaxConnections, "1")
	t.Setenv(EnvTmuxPath, "/env/tmux")
	t.Setenv(EnvSecretBackend, "keyring")
	t.Setenv(EnvLogLevel, "error")
	t.Setenv(EnvUpdateEnabled, "false")
	t.Setenv(EnvUpdateInterval, "6h")
	t.Setenv(EnvKeepAwake, "true")

	_, sources, err := LoadConfigWithSources("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}

	if sources.ServerURL != sourceEnv {
		t.Errorf("ServerURL source = %v, want env", sources.ServerURL)
	}
	if sources.KeyPath != sourceEnv {
		t.Errorf("KeyPath source = %v, want env", sources.KeyPath)
	}
	if sources.SocketName != sourceEnv {
		t.Errorf("SocketName source = %v, want env", sources.SocketName)
	}
	if sources.MaxMobileConnections != sourceEnv {
		t.Errorf("MaxMobileConnections source = %v, want env", sources.MaxMobileConnections)
	}
	if sources.TmuxPath != sourceEnv {
		t.Errorf("TmuxPath source = %v, want env", sources.TmuxPath)
	}
	if sources.SecretBackend != sourceEnv {
		t.Errorf("SecretBackend source = %v, want env", sources.SecretBackend)
	}
	if sources.LogLevel != sourceEnv {
		t.Errorf("LogLevel source = %v, want env", sources.LogLevel)
	}
	if sources.UpdateEnabled != sourceEnv {
		t.Errorf("UpdateEnabled source = %v, want env", sources.UpdateEnabled)
	}
	if sources.UpdateCheckInterval != sourceEnv {
		t.Errorf("UpdateCheckInterval source = %v, want env", sources.UpdateCheckInterval)
	}
	if sources.KeepAwake != sourceEnv {
		t.Errorf("KeepAwake source = %v, want env", sources.KeepAwake)
	}
}

func TestLoadConfig_UpdateConfigFromFile(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel, EnvUpdateEnabled, EnvUpdateInterval} {
		t.Setenv(env, "")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	content := `
[update]
enabled = false
check_interval = "12h"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Update.Enabled {
		t.Error("Update.Enabled should be false")
	}
	if cfg.Update.CheckInterval != "12h" {
		t.Errorf("Update.CheckInterval = %q, want %q", cfg.Update.CheckInterval, "12h")
	}
}

func TestLoadConfig_UpdateConfigFromEnv(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}

	t.Setenv(EnvUpdateEnabled, "true")
	t.Setenv(EnvUpdateInterval, "6h")

	cfg, err := LoadConfig("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if !cfg.Update.Enabled {
		t.Error("Update.Enabled should be true from env")
	}
	if cfg.Update.CheckInterval != "6h" {
		t.Errorf("Update.CheckInterval = %q, want %q", cfg.Update.CheckInterval, "6h")
	}
}

func TestLoadConfig_ForceRelayFromFile(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel, EnvUpdateEnabled, EnvUpdateInterval, EnvForceRelay} {
		t.Setenv(env, "")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	content := `
[connection]
force_relay = true
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	cfg, sources, err := LoadConfigWithSources(path)
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}
	if !cfg.Connection.ForceRelay {
		t.Error("Connection.ForceRelay should be true from file")
	}
	if sources.ForceRelay != sourceFile {
		t.Errorf("ForceRelay source = %v, want file", sources.ForceRelay)
	}
}

func TestLoadConfig_ForceRelayDefaultsFalse(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel, EnvUpdateEnabled, EnvUpdateInterval, EnvForceRelay} {
		t.Setenv(env, "")
	}

	// Config file with a [connection] section but no force_relay key — must
	// stay false rather than being clobbered by the zero value.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[connection]
reconnect_interval = "10s"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Connection.ForceRelay {
		t.Error("Connection.ForceRelay should default to false when absent")
	}
}

func TestLoadConfig_ForceRelayFromEnv(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel, EnvUpdateEnabled, EnvUpdateInterval} {
		t.Setenv(env, "")
	}

	t.Setenv(EnvForceRelay, "1")

	cfg, sources, err := LoadConfigWithSources("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}
	if !cfg.Connection.ForceRelay {
		t.Error("Connection.ForceRelay should be true from env (PMUX_FORCE_RELAY=1)")
	}
	if sources.ForceRelay != sourceEnv {
		t.Errorf("ForceRelay source = %v, want env", sources.ForceRelay)
	}
}

func TestLoadConfig_KeepAwakeFromFile(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel, EnvUpdateEnabled, EnvUpdateInterval, EnvKeepAwake} {
		t.Setenv(env, "")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[power]
keep_awake = true
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	cfg, sources, err := LoadConfigWithSources(path)
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}
	if !cfg.Power.KeepAwake {
		t.Error("Power.KeepAwake should be true from file")
	}
	if sources.KeepAwake != sourceFile {
		t.Errorf("KeepAwake source = %v, want file", sources.KeepAwake)
	}
}

func TestLoadConfig_KeepAwakeDefaultsFalse(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel, EnvUpdateEnabled, EnvUpdateInterval, EnvKeepAwake} {
		t.Setenv(env, "")
	}

	// Config file with a [power] section but no keep_awake key — must stay false.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[power]
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Power.KeepAwake {
		t.Error("Power.KeepAwake should default to false when absent")
	}
}

func TestLoadConfig_KeepAwakeFromEnv(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel, EnvUpdateEnabled, EnvUpdateInterval} {
		t.Setenv(env, "")
	}

	t.Setenv(EnvKeepAwake, "1")

	cfg, sources, err := LoadConfigWithSources("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}
	if !cfg.Power.KeepAwake {
		t.Error("Power.KeepAwake should be true from env (PMUX_KEEP_AWAKE=1)")
	}
	if sources.KeepAwake != sourceEnv {
		t.Errorf("KeepAwake source = %v, want env", sources.KeepAwake)
	}
}

// An over-cap keepalive_interval must NOT fail validation (that would hard-fail
// the agent on startup after an upgrade); it is clamped to MaxKeepaliveInterval
// instead, and KeepaliveClamped reports the clamp.
func TestValidate_KeepaliveIntervalMax(t *testing.T) {
	tests := []struct {
		name        string
		interval    string
		wantClamped bool
		wantEffect  time.Duration
	}{
		{"default 30s", "30s", false, 30 * time.Second},
		{"at the 45s cap", "45s", false, 45 * time.Second},
		{"just over the cap", "46s", true, MaxKeepaliveInterval},
		{"well over the cap", "120s", true, MaxKeepaliveInterval},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Connection.KeepaliveInterval = tt.interval
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() with keepalive_interval=%q: unexpected error: %v", tt.interval, err)
			}
			if got := cfg.KeepaliveClamped(); got != tt.wantClamped {
				t.Errorf("KeepaliveClamped() = %v, want %v", got, tt.wantClamped)
			}
			if got := cfg.KeepaliveInterval(); got != tt.wantEffect {
				t.Errorf("KeepaliveInterval() = %v, want %v", got, tt.wantEffect)
			}
		})
	}
}

func TestValidate_SecretBackend(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"auto", "auto", false},
		{"keyring", "keyring", false},
		{"file", "file", false},
		{"invalid", "custom", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Identity.SecretBackend = tt.value
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() with secret_backend=%q: err=%v, wantErr=%v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestServerURL_Method(t *testing.T) {
	cfg := Defaults()
	if cfg.ServerURL() != "https://signal.pmux.io" {
		t.Errorf("ServerURL() = %q, want %q", cfg.ServerURL(), "https://signal.pmux.io")
	}

	cfg.Server.URL = "https://custom.example.com"
	if cfg.ServerURL() != "https://custom.example.com" {
		t.Errorf("ServerURL() = %q, want %q", cfg.ServerURL(), "https://custom.example.com")
	}
}

func TestDefaults_APIVersion(t *testing.T) {
	cfg := Defaults()
	if cfg.Server.APIVersion != "v1" {
		t.Errorf("Server.APIVersion = %q, want %q", cfg.Server.APIVersion, "v1")
	}
}

func TestAPIBaseURL_Method(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		apiVersion string
		want       string
	}{
		{
			name:       "v1 appends prefix",
			url:        "https://signal.pmux.io",
			apiVersion: "v1",
			want:       "https://signal.pmux.io/v1",
		},
		{
			name:       "empty version returns bare URL",
			url:        "https://signal.pmux.io",
			apiVersion: "",
			want:       "https://signal.pmux.io",
		},
		{
			name:       "trailing slash stripped before prefix",
			url:        "https://signal.pmux.io/",
			apiVersion: "v1",
			want:       "https://signal.pmux.io/v1",
		},
		{
			name:       "trailing slash stripped with empty version",
			url:        "https://signal.pmux.io/",
			apiVersion: "",
			want:       "https://signal.pmux.io",
		},
		{
			name:       "custom host with v1",
			url:        "http://localhost:8787",
			apiVersion: "v1",
			want:       "http://localhost:8787/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Server.URL = tt.url
			cfg.Server.APIVersion = tt.apiVersion
			if got := cfg.APIBaseURL(); got != tt.want {
				t.Errorf("APIBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadConfig_APIVersionDefault(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvAPIVersion, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}
	// Unset EnvAPIVersion entirely so the env override short-circuits via LookupEnv.
	os.Unsetenv(EnvAPIVersion)

	cfg, err := LoadConfig("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Server.APIVersion != "v1" {
		t.Errorf("Server.APIVersion = %q, want %q", cfg.Server.APIVersion, "v1")
	}
}

func TestLoadConfig_APIVersionFromFile(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}
	os.Unsetenv(EnvAPIVersion)

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	// File sets api_version to "" explicitly, which must override the "v1"
	// default (covers the legacy-server compatibility case).
	content := `
[server]
api_version = ""
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Server.APIVersion != "" {
		t.Errorf("Server.APIVersion = %q, want %q", cfg.Server.APIVersion, "")
	}
	// APIBaseURL should collapse to the bare URL when api_version is empty.
	if cfg.APIBaseURL() != cfg.Server.URL {
		t.Errorf("APIBaseURL() = %q, want bare URL %q", cfg.APIBaseURL(), cfg.Server.URL)
	}
}

func TestLoadConfig_APIVersionFromFile_ExplicitV1(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}
	os.Unsetenv(EnvAPIVersion)

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	content := `
[server]
api_version = "v1"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	cfg, sources, err := LoadConfigWithSources(path)
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}
	if cfg.Server.APIVersion != "v1" {
		t.Errorf("Server.APIVersion = %q, want %q", cfg.Server.APIVersion, "v1")
	}
	if sources.APIVersion != sourceFile {
		t.Errorf("APIVersion source = %v, want file", sources.APIVersion)
	}
}

func TestLoadConfig_APIVersionFromEnv(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}
	t.Setenv(EnvAPIVersion, "v1")

	cfg, sources, err := LoadConfigWithSources("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}
	if cfg.Server.APIVersion != "v1" {
		t.Errorf("Server.APIVersion = %q, want %q", cfg.Server.APIVersion, "v1")
	}
	if sources.APIVersion != sourceEnv {
		t.Errorf("APIVersion source = %v, want env", sources.APIVersion)
	}
}

func TestLoadConfig_APIVersionEnvEmptyOverridesDefault(t *testing.T) {
	// An explicit empty string via env must override the "v1" default so
	// operators can point at a legacy signaling server without editing TOML.
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}
	t.Setenv(EnvAPIVersion, "")

	cfg, err := LoadConfig("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Server.APIVersion != "" {
		t.Errorf("Server.APIVersion = %q, want %q", cfg.Server.APIVersion, "")
	}
}

func TestLoadConfig_APIVersionEnvOverridesFile(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[server]
api_version = ""
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	t.Setenv(EnvAPIVersion, "v1")

	cfg, sources, err := LoadConfigWithSources(path)
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}
	if cfg.Server.APIVersion != "v1" {
		t.Errorf("Server.APIVersion = %q, want %q", cfg.Server.APIVersion, "v1")
	}
	if sources.APIVersion != sourceEnv {
		t.Errorf("APIVersion source = %v, want env", sources.APIVersion)
	}
}

func TestValidate_APIVersion(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"v1", "v1", false},
		{"empty", "", false},
		{"v2_not_yet_supported", "v2", true},
		{"unknown", "custom", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Server.APIVersion = tt.value
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() with api_version=%q: err=%v, wantErr=%v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	want := Config{Name: "my-workstation"}
	if err := saveConfig(path, want); err != nil {
		t.Fatalf("saveConfig() error: %v", err)
	}

	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if got.Name != want.Name {
		t.Errorf("Name = %q, want %q", got.Name, want.Name)
	}
}

func TestSaveConfigFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	if err := saveConfig(path, Config{Name: "test"}); err != nil {
		t.Fatalf("saveConfig() error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestDefaultHostName(t *testing.T) {
	name := DefaultHostName()
	if name == "" {
		t.Error("DefaultHostName() returned empty string")
	}
}

func TestLoadConfigWithSources_AllDefaults(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}

	cfg, sources, err := LoadConfigWithSources("/nonexistent/config.toml")
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}

	// All sources should be default
	if sources.ServerURL != sourceDefault {
		t.Errorf("ServerURL source = %v, want default", sources.ServerURL)
	}
	if sources.SocketName != sourceDefault {
		t.Errorf("SocketName source = %v, want default", sources.SocketName)
	}

	// Values should be defaults
	if cfg.Server.URL != DefaultServerURL {
		t.Errorf("Server.URL = %q, want %q", cfg.Server.URL, DefaultServerURL)
	}
}

func TestLoadConfigWithSources_FileSources(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath, EnvLogLevel} {
		t.Setenv(env, "")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	content := `
[connection]
keepalive_interval = "15s"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	_, sources, err := LoadConfigWithSources(path)
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}

	if sources.KeepaliveInterval != sourceFile {
		t.Errorf("KeepaliveInterval source = %v, want file", sources.KeepaliveInterval)
	}
	// Unset values remain default
	if sources.ServerURL != sourceDefault {
		t.Errorf("ServerURL source = %v, want default", sources.ServerURL)
	}
}

func TestLoadConfigWithSources_EnvSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	content := `
[connection]
keepalive_interval = "15s"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	t.Setenv(EnvNewServerURL, "https://env.example.com")
	t.Setenv(EnvKeyPath, "")
	t.Setenv(EnvSocketName, "")
	t.Setenv(EnvMaxConnections, "")
	t.Setenv(EnvTmuxPath, "")

	_, sources, err := LoadConfigWithSources(path)
	if err != nil {
		t.Fatalf("LoadConfigWithSources() error: %v", err)
	}

	if sources.ServerURL != sourceEnv {
		t.Errorf("ServerURL source = %v, want env", sources.ServerURL)
	}
	if sources.KeepaliveInterval != sourceFile {
		t.Errorf("KeepaliveInterval source = %v, want file", sources.KeepaliveInterval)
	}
	if sources.SocketName != sourceDefault {
		t.Errorf("SocketName source = %v, want default", sources.SocketName)
	}
}

func TestFormatEffective(t *testing.T) {
	cfg := Defaults()
	sources := ConfigSources{}

	output := FormatEffective(cfg, sources)

	// Check that it contains expected strings
	if !containsAll(output, []string{
		`server.url = "https://signal.pmux.io"  (default)`,
		`server.api_version = "v1"  (default)`,
		`tmux.socket_name = "pmux"  (default)`,
		`tmux.tmux_path = ""  (default)`,
		`connection.max_mobile_connections = 1  (default)`,
		`log_level = "info"  (default)`,
		`power.keep_awake = false  (default)`,
	}) {
		t.Errorf("FormatEffective() output missing expected content:\n%s", output)
	}
}

func TestCommentedDefaultConfig(t *testing.T) {
	content := CommentedDefaultConfig()

	expectedStrings := []string{
		"[server]",
		"[identity]",
		"[connection]",
		"[tmux]",
		"[power]",
		"PMUX_KEEP_AWAKE",
		"# keep_awake = false",
		"PMUX_SERVER_URL",
		"PMUX_API_VERSION",
		"PMUX_KEY_PATH",
		`# url = "https://signal.pmux.io"`,
		`# api_version = "v1"`,
		`# socket_name = "pmux"`,
		`PMUX_TMUX_PATH`,
		`# tmux_path = "/opt/homebrew/bin/tmux"`,
		"PMUX_LOG_LEVEL",
		`# log_level = "info"`,
	}

	for _, s := range expectedStrings {
		if !containsStr(content, s) {
			t.Errorf("CommentedDefaultConfig() missing %q", s)
		}
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  slog.Level
	}{
		{"debug", "debug", slog.LevelDebug},
		{"info", "info", slog.LevelInfo},
		{"warn", "warn", slog.LevelWarn},
		{"error", "error", slog.LevelError},
		{"uppercase", "INFO", slog.LevelInfo},
		{"mixed_case", "Debug", slog.LevelDebug},
		{"invalid_fallback", "verbose", slog.LevelInfo},
		{"empty_fallback", "", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.LogLevel = tt.value
			got := cfg.ParseLogLevel()
			if got != tt.want {
				t.Errorf("ParseLogLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidate_InvalidLogLevel(t *testing.T) {
	cfg := Defaults()
	cfg.LogLevel = "verbose"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for invalid log_level, got nil")
	}
}

func TestValidate_ValidLogLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			cfg := Defaults()
			cfg.LogLevel = level
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() unexpected error for log_level %q: %v", level, err)
			}
		})
	}
}

func TestConfigSource_String(t *testing.T) {
	tests := []struct {
		source configSource
		want   string
	}{
		{sourceDefault, "default"},
		{sourceFile, "file"},
		{sourceEnv, "env"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.source.String(); got != tt.want {
				t.Errorf("configSource(%d).String() = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

func TestDefaultPaths(t *testing.T) {
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatalf("DefaultPaths() error: %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir() error: %v", err)
	}

	wantConfigDir := filepath.Join(home, ".config", "pmux")
	if paths.ConfigDir != wantConfigDir {
		t.Errorf("ConfigDir = %q, want %q", paths.ConfigDir, wantConfigDir)
	}
	if paths.KeysDir != filepath.Join(wantConfigDir, "keys") {
		t.Errorf("KeysDir = %q, want %q", paths.KeysDir, filepath.Join(wantConfigDir, "keys"))
	}
	if paths.PairedDevices != filepath.Join(wantConfigDir, "paired_devices.json") {
		t.Errorf("PairedDevices = %q, want %q", paths.PairedDevices, filepath.Join(wantConfigDir, "paired_devices.json"))
	}
	if paths.ConfigFile != filepath.Join(wantConfigDir, "config.toml") {
		t.Errorf("ConfigFile = %q, want %q", paths.ConfigFile, filepath.Join(wantConfigDir, "config.toml"))
	}
}

func TestEnsureDirs(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		ConfigDir:     filepath.Join(dir, "pmux"),
		KeysDir:       filepath.Join(dir, "pmux", "keys"),
		PairedDevices: filepath.Join(dir, "pmux", "paired_devices.json"),
		ConfigFile:    filepath.Join(dir, "pmux", "config.toml"),
	}

	if err := paths.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs() error: %v", err)
	}

	// Verify KeysDir was created (EnsureDirs uses MkdirAll on KeysDir which also creates ConfigDir)
	if info, err := os.Stat(paths.KeysDir); err != nil {
		t.Errorf("KeysDir not created: %v", err)
	} else if !info.IsDir() {
		t.Errorf("KeysDir is not a directory")
	}

	// Verify directory permissions are 0700
	if info, err := os.Stat(paths.KeysDir); err == nil {
		if perm := info.Mode().Perm(); perm != 0700 {
			t.Errorf("KeysDir permissions = %o, want 0700", perm)
		}
	}

	// Calling EnsureDirs again should be idempotent
	if err := paths.EnsureDirs(); err != nil {
		t.Errorf("EnsureDirs() second call error: %v", err)
	}
}

// containsAll checks that s contains all of the given substrings.
func containsAll(s string, subs []string) bool {
	for _, sub := range subs {
		if !containsStr(s, sub) {
			return false
		}
	}
	return true
}

// containsStr checks if s contains sub.
func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsIndex(s, sub))
}

func containsIndex(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

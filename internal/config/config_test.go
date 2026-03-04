package config

import (
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
}

func TestLoadConfig_Nonexistent(t *testing.T) {
	// Ensure env vars don't interfere
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath} {
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
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath} {
		t.Setenv(env, "")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	content := `
name = "work-laptop"

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
}

func TestLoadConfig_TmuxPathEnvOverride(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath} {
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
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath} {
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
		name   string
		value  string
		expect time.Duration
	}{
		{"30s", "30s", 30 * time.Second},
		{"1m", "1m", 1 * time.Minute},
		{"10s", "10s", 10 * time.Second},
		{"invalid_fallback", "bad", 30 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Connection.KeepaliveInterval = tt.value
			got := cfg.KeepaliveInterval()
			if got != tt.expect {
				t.Errorf("KeepaliveInterval() = %v, want %v", got, tt.expect)
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

func TestSaveAndLoadConfig(t *testing.T) {
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath} {
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
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath} {
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
	for _, env := range []string{EnvNewServerURL, EnvServerURL, EnvKeyPath, EnvSocketName, EnvMaxConnections, EnvTmuxPath} {
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
		`tmux.socket_name = "pmux"  (default)`,
		`tmux.tmux_path = ""  (default)`,
		`connection.max_mobile_connections = 1  (default)`,
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
		"PMUX_SERVER_URL",
		"PMUX_KEY_PATH",
		`# url = "https://signal.pmux.io"`,
		`# socket_name = "pmux"`,
		`PMUX_TMUX_PATH`,
		`# tmux_path = "/opt/homebrew/bin/tmux"`,
	}

	for _, s := range expectedStrings {
		if !containsStr(content, s) {
			t.Errorf("CommentedDefaultConfig() missing %q", s)
		}
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

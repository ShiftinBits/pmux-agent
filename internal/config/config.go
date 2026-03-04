// Package config handles configuration file parsing, defaults, and path resolution.
// Config stored at ~/.config/pmux/config.toml.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"
)

const (
	appDir            = "pmux"
	keysDir           = "keys"
	pairedDevicesFile = "paired_devices.json"
	configFile        = "config.toml"

	// DefaultServerURL is the production signaling server base URL.
	// Used for both HTTP endpoints and WebSocket (signaling.go converts to wss://).
	DefaultServerURL = "https://signal.pmux.io"

	// EnvServerURL is the legacy environment variable to override the signaling server URL.
	// Kept for backward compatibility; PMUX_SERVER_URL takes precedence if both are set.
	EnvServerURL = "PMUX_AGENT_SIGNAL_URL"

	// Environment variable names for config overrides.
	EnvNewServerURL    = "PMUX_SERVER_URL"
	EnvKeyPath         = "PMUX_KEY_PATH"
	EnvSocketName      = "PMUX_SOCKET_NAME"
	EnvMaxConnections  = "PMUX_MAX_CONNECTIONS"
	EnvSecretBackend   = "PMUX_SECRET_BACKEND"
	EnvTmuxPath        = "PMUX_TMUX_PATH"
)

// Config holds user-editable PocketMux configuration from config.toml.
type Config struct {
	Name       string           `toml:"name,omitempty"`
	Server     ServerConfig     `toml:"server"`
	Identity   IdentityConfig   `toml:"identity"`
	Connection ConnectionConfig `toml:"connection"`
	Tmux       TmuxConfig       `toml:"tmux"`
}

// ServerConfig holds signaling server configuration.
type ServerConfig struct {
	URL string `toml:"url"`
}

// IdentityConfig holds Ed25519 identity path and secret storage configuration.
type IdentityConfig struct {
	KeyPath       string `toml:"key_path"`
	SecretBackend string `toml:"secret_backend"` // "auto", "keyring", or "file"
}

// ConnectionConfig holds connection tuning parameters.
type ConnectionConfig struct {
	ReconnectInterval    string `toml:"reconnect_interval"`     // duration string, e.g., "5s"
	KeepaliveInterval    string `toml:"keepalive_interval"`     // duration string, e.g., "30s"
	MaxMobileConnections int    `toml:"max_mobile_connections"` // 1-20
}

// TmuxConfig holds tmux-related configuration.
type TmuxConfig struct {
	SocketName string `toml:"socket_name"`
	TmuxPath   string `toml:"tmux_path"` // Absolute path to tmux binary (resolved at init time)
}

// configSource tracks where each config value originated.
type configSource int

const (
	sourceDefault configSource = iota
	sourceFile
	sourceEnv
)

func (s configSource) String() string {
	switch s {
	case sourceFile:
		return "file"
	case sourceEnv:
		return "env"
	default:
		return "default"
	}
}

// ConfigSources records the origin of each config field for display.
type ConfigSources struct {
	ServerURL            configSource
	KeyPath              configSource
	SecretBackend        configSource
	ReconnectInterval    configSource
	KeepaliveInterval    configSource
	MaxMobileConnections configSource
	SocketName           configSource
	TmuxPath             configSource
	Name                 configSource
}

// Defaults returns the default configuration.
// The server URL uses https:// as the base URL; signaling.go converts to wss:// for WebSocket.
func Defaults() Config {
	return Config{
		Server:   ServerConfig{URL: DefaultServerURL},
		Identity: IdentityConfig{KeyPath: "~/.config/pmux/keys/", SecretBackend: "auto"},
		Connection: ConnectionConfig{
			ReconnectInterval:    "5s",
			KeepaliveInterval:    "30s",
			MaxMobileConnections: 1,
		},
		Tmux: TmuxConfig{SocketName: "pmux"},
	}
}

// LoadConfig reads the TOML config file and overlays defaults, file values,
// and environment variables. Returns a zero Config (not an error) if the file
// doesn't exist yet.
func LoadConfig(path string) (Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No file: apply env overrides on top of defaults
			applyEnvOverrides(&cfg)
			return cfg, nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	// Parse file into a separate struct so we can overlay non-zero values
	var fileCfg Config
	if err := toml.Unmarshal(data, &fileCfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	overlayFile(&cfg, &fileCfg)
	applyEnvOverrides(&cfg)

	return cfg, nil
}

// LoadConfigWithSources works like LoadConfig but also returns source annotations.
func LoadConfigWithSources(path string) (Config, ConfigSources, error) {
	cfg := Defaults()
	sources := ConfigSources{} // all default initially

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			applyEnvOverridesTracked(&cfg, &sources)
			return cfg, sources, nil
		}
		return Config{}, ConfigSources{}, fmt.Errorf("read config: %w", err)
	}

	var fileCfg Config
	if err := toml.Unmarshal(data, &fileCfg); err != nil {
		return Config{}, ConfigSources{}, fmt.Errorf("parse config: %w", err)
	}

	overlayFileTracked(&cfg, &fileCfg, &sources)
	applyEnvOverridesTracked(&cfg, &sources)

	return cfg, sources, nil
}

// overlayFile overlays non-zero file values onto defaults.
func overlayFile(cfg *Config, fileCfg *Config) {
	if fileCfg.Name != "" {
		cfg.Name = fileCfg.Name
	}
	if fileCfg.Server.URL != "" {
		cfg.Server.URL = fileCfg.Server.URL
	}
	if fileCfg.Identity.KeyPath != "" {
		cfg.Identity.KeyPath = fileCfg.Identity.KeyPath
	}
	if fileCfg.Identity.SecretBackend != "" {
		cfg.Identity.SecretBackend = fileCfg.Identity.SecretBackend
	}
	if fileCfg.Connection.ReconnectInterval != "" {
		cfg.Connection.ReconnectInterval = fileCfg.Connection.ReconnectInterval
	}
	if fileCfg.Connection.KeepaliveInterval != "" {
		cfg.Connection.KeepaliveInterval = fileCfg.Connection.KeepaliveInterval
	}
	if fileCfg.Connection.MaxMobileConnections != 0 {
		cfg.Connection.MaxMobileConnections = fileCfg.Connection.MaxMobileConnections
	}
	if fileCfg.Tmux.SocketName != "" {
		cfg.Tmux.SocketName = fileCfg.Tmux.SocketName
	}
	if fileCfg.Tmux.TmuxPath != "" {
		cfg.Tmux.TmuxPath = fileCfg.Tmux.TmuxPath
	}
}

// overlayFileTracked is like overlayFile but also records source annotations.
func overlayFileTracked(cfg *Config, fileCfg *Config, sources *ConfigSources) {
	if fileCfg.Name != "" {
		cfg.Name = fileCfg.Name
		sources.Name = sourceFile
	}
	if fileCfg.Server.URL != "" {
		cfg.Server.URL = fileCfg.Server.URL
		sources.ServerURL = sourceFile
	}
	if fileCfg.Identity.KeyPath != "" {
		cfg.Identity.KeyPath = fileCfg.Identity.KeyPath
		sources.KeyPath = sourceFile
	}
	if fileCfg.Identity.SecretBackend != "" {
		cfg.Identity.SecretBackend = fileCfg.Identity.SecretBackend
		sources.SecretBackend = sourceFile
	}
	if fileCfg.Connection.ReconnectInterval != "" {
		cfg.Connection.ReconnectInterval = fileCfg.Connection.ReconnectInterval
		sources.ReconnectInterval = sourceFile
	}
	if fileCfg.Connection.KeepaliveInterval != "" {
		cfg.Connection.KeepaliveInterval = fileCfg.Connection.KeepaliveInterval
		sources.KeepaliveInterval = sourceFile
	}
	if fileCfg.Connection.MaxMobileConnections != 0 {
		cfg.Connection.MaxMobileConnections = fileCfg.Connection.MaxMobileConnections
		sources.MaxMobileConnections = sourceFile
	}
	if fileCfg.Tmux.SocketName != "" {
		cfg.Tmux.SocketName = fileCfg.Tmux.SocketName
		sources.SocketName = sourceFile
	}
	if fileCfg.Tmux.TmuxPath != "" {
		cfg.Tmux.TmuxPath = fileCfg.Tmux.TmuxPath
		sources.TmuxPath = sourceFile
	}
}

// applyEnvOverrides overlays environment variable values onto the config.
func applyEnvOverrides(cfg *Config) {
	// PMUX_SERVER_URL takes precedence over PMUX_AGENT_SIGNAL_URL (legacy)
	if v := os.Getenv(EnvNewServerURL); v != "" {
		cfg.Server.URL = v
	} else if v := os.Getenv(EnvServerURL); v != "" {
		cfg.Server.URL = v
	}
	if v := os.Getenv(EnvKeyPath); v != "" {
		cfg.Identity.KeyPath = v
	}
	if v := os.Getenv(EnvSocketName); v != "" {
		cfg.Tmux.SocketName = v
	}
	if v := os.Getenv(EnvTmuxPath); v != "" {
		cfg.Tmux.TmuxPath = v
	}
	if v := os.Getenv(EnvSecretBackend); v != "" {
		cfg.Identity.SecretBackend = v
	}
	if v := os.Getenv(EnvMaxConnections); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Connection.MaxMobileConnections = n
		}
	}
}

// applyEnvOverridesTracked is like applyEnvOverrides but records source annotations.
func applyEnvOverridesTracked(cfg *Config, sources *ConfigSources) {
	if v := os.Getenv(EnvNewServerURL); v != "" {
		cfg.Server.URL = v
		sources.ServerURL = sourceEnv
	} else if v := os.Getenv(EnvServerURL); v != "" {
		cfg.Server.URL = v
		sources.ServerURL = sourceEnv
	}
	if v := os.Getenv(EnvKeyPath); v != "" {
		cfg.Identity.KeyPath = v
		sources.KeyPath = sourceEnv
	}
	if v := os.Getenv(EnvSocketName); v != "" {
		cfg.Tmux.SocketName = v
		sources.SocketName = sourceEnv
	}
	if v := os.Getenv(EnvTmuxPath); v != "" {
		cfg.Tmux.TmuxPath = v
		sources.TmuxPath = sourceEnv
	}
	if v := os.Getenv(EnvSecretBackend); v != "" {
		cfg.Identity.SecretBackend = v
		sources.SecretBackend = sourceEnv
	}
	if v := os.Getenv(EnvMaxConnections); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Connection.MaxMobileConnections = n
			sources.MaxMobileConnections = sourceEnv
		}
	}
}

// Validate checks that the config values are well-formed.
func (c *Config) Validate() error {
	// server.url must start with a valid scheme
	if c.Server.URL == "" {
		return fmt.Errorf("server.url must not be empty")
	}
	validScheme := strings.HasPrefix(c.Server.URL, "ws://") ||
		strings.HasPrefix(c.Server.URL, "wss://") ||
		strings.HasPrefix(c.Server.URL, "http://") ||
		strings.HasPrefix(c.Server.URL, "https://")
	if !validScheme {
		return fmt.Errorf("server.url must start with http://, https://, ws://, or wss://, got %q", c.Server.URL)
	}

	// secret_backend must be a known value
	switch c.Identity.SecretBackend {
	case "auto", "keyring", "file":
		// valid
	default:
		return fmt.Errorf("identity.secret_backend must be %q, %q, or %q, got %q",
			"auto", "keyring", "file", c.Identity.SecretBackend)
	}

	// Durations must parse
	if _, err := time.ParseDuration(c.Connection.ReconnectInterval); err != nil {
		return fmt.Errorf("connection.reconnect_interval: %w", err)
	}
	if _, err := time.ParseDuration(c.Connection.KeepaliveInterval); err != nil {
		return fmt.Errorf("connection.keepalive_interval: %w", err)
	}

	// max_mobile_connections must be exactly 1 (single-pairing mode)
	if c.Connection.MaxMobileConnections != 1 {
		return fmt.Errorf("connection.max_mobile_connections must be 1 (single-pairing mode)")
	}

	// socket_name must be non-empty
	if c.Tmux.SocketName == "" {
		return fmt.Errorf("tmux.socket_name must not be empty")
	}

	return nil
}

// ReconnectInterval returns the parsed reconnect interval duration.
// Falls back to 5s if parsing fails.
func (c *Config) ReconnectInterval() time.Duration {
	d, err := time.ParseDuration(c.Connection.ReconnectInterval)
	if err != nil {
		return 5 * time.Second
	}
	return d
}

// KeepaliveInterval returns the parsed keepalive interval duration.
// Falls back to 30s if parsing fails.
func (c *Config) KeepaliveInterval() time.Duration {
	d, err := time.ParseDuration(c.Connection.KeepaliveInterval)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

// ServerURL returns the effective signaling server URL from the config.
// This replaces the old standalone ServerURL() function.
// The URL is resolved from: defaults → config file → env vars.
func (c *Config) ServerURL() string {
	return c.Server.URL
}

// FormatEffective returns a formatted string showing all config values with sources.
func FormatEffective(cfg Config, sources ConfigSources) string {
	var b strings.Builder
	fmt.Fprintf(&b, "name = %q  (%s)\n", cfg.Name, sources.Name)
	fmt.Fprintf(&b, "server.url = %q  (%s)\n", cfg.Server.URL, sources.ServerURL)
	fmt.Fprintf(&b, "identity.key_path = %q  (%s)\n", cfg.Identity.KeyPath, sources.KeyPath)
	fmt.Fprintf(&b, "identity.secret_backend = %q  (%s)\n", cfg.Identity.SecretBackend, sources.SecretBackend)
	fmt.Fprintf(&b, "connection.reconnect_interval = %q  (%s)\n", cfg.Connection.ReconnectInterval, sources.ReconnectInterval)
	fmt.Fprintf(&b, "connection.keepalive_interval = %q  (%s)\n", cfg.Connection.KeepaliveInterval, sources.KeepaliveInterval)
	fmt.Fprintf(&b, "connection.max_mobile_connections = %d  (%s)\n", cfg.Connection.MaxMobileConnections, sources.MaxMobileConnections)
	fmt.Fprintf(&b, "tmux.socket_name = %q  (%s)\n", cfg.Tmux.SocketName, sources.SocketName)
	fmt.Fprintf(&b, "tmux.tmux_path = %q  (%s)\n", cfg.Tmux.TmuxPath, sources.TmuxPath)
	return b.String()
}

// CommentedDefaultConfig returns a well-commented default config.toml for use
// by `pmux init`. Values are commented out so they act as documentation without
// overriding defaults.
func CommentedDefaultConfig() string {
	return `# PocketMux Agent Configuration

[server]
# Signaling server URL (env: PMUX_SERVER_URL)
# url = "https://signal.pmux.io"

[identity]
# Path to Ed25519 keypair (env: PMUX_KEY_PATH)
# key_path = "~/.config/pmux/keys/"
# Secret storage backend: "auto", "keyring", or "file" (env: PMUX_SECRET_BACKEND)
# auto = use system keychain if available, fall back to encrypted file
# keyring = require system keychain (macOS Keychain, Linux SecretService)
# file = always use encrypted file
# secret_backend = "auto"

[connection]
# reconnect_interval = "5s"
# keepalive_interval = "30s"
# max_mobile_connections = 1

[tmux]
# socket_name = "pmux"
# Absolute path to tmux binary (env: PMUX_TMUX_PATH)
# Resolved automatically during 'pmux init'. Set manually if tmux moves.
# tmux_path = "/opt/homebrew/bin/tmux"
`
}

// Paths holds resolved filesystem paths for PocketMux configuration and keys.
type Paths struct {
	ConfigDir     string // ~/.config/pmux
	KeysDir       string // ~/.config/pmux/keys
	PairedDevices string // ~/.config/pmux/paired_devices.json
	ConfigFile    string // ~/.config/pmux/config.toml
}

// DefaultPaths returns the standard PocketMux directory paths based on $HOME.
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("determine home directory: %w", err)
	}

	configDir := filepath.Join(home, ".config", appDir)
	return Paths{
		ConfigDir:     configDir,
		KeysDir:       filepath.Join(configDir, keysDir),
		PairedDevices: filepath.Join(configDir, pairedDevicesFile),
		ConfigFile:    filepath.Join(configDir, configFile),
	}, nil
}

// EnsureDirs creates the config and keys directories if they don't exist.
func (p Paths) EnsureDirs() error {
	if err := os.MkdirAll(p.KeysDir, 0700); err != nil {
		return fmt.Errorf("create keys directory: %w", err)
	}
	return nil
}

// saveConfig writes the config to a TOML file with 0600 permissions.
func saveConfig(path string, cfg Config) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// DefaultHostName returns the OS hostname as a default host name.
func DefaultHostName() string {
	name, err := os.Hostname()
	if err != nil {
		return "my-host"
	}
	return name
}

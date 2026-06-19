// Package config handles configuration file parsing, defaults, and path resolution.
// Config stored at ~/.config/pmux/config.toml.
package config

import (
	"fmt"
	"log/slog"
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
	EnvNewServerURL   = "PMUX_SERVER_URL"
	EnvAPIVersion     = "PMUX_API_VERSION"
	EnvKeyPath        = "PMUX_KEY_PATH"
	EnvSocketName     = "PMUX_SOCKET_NAME"
	EnvMaxConnections = "PMUX_MAX_CONNECTIONS"
	EnvSecretBackend  = "PMUX_SECRET_BACKEND"
	EnvTmuxPath       = "PMUX_TMUX_PATH"
	EnvLogLevel       = "PMUX_LOG_LEVEL"
	EnvUpdateEnabled  = "PMUX_UPDATE_ENABLED"
	EnvUpdateInterval = "PMUX_UPDATE_INTERVAL"
	EnvForceRelay     = "PMUX_FORCE_RELAY"
	EnvKeepAwake      = "PMUX_KEEP_AWAKE"
)

// Config holds user-editable Pocketmux configuration from config.toml.
type Config struct {
	Name       string           `toml:"name,omitempty"`
	LogLevel   string           `toml:"log_level,omitempty"`
	Server     ServerConfig     `toml:"server"`
	Identity   IdentityConfig   `toml:"identity"`
	Connection ConnectionConfig `toml:"connection"`
	Tmux       TmuxConfig       `toml:"tmux"`
	Update     UpdateConfig     `toml:"update"`
	Power      PowerConfig      `toml:"power"`
}

// PowerConfig holds power-management configuration.
type PowerConfig struct {
	// KeepAwake, when true, prevents the host from sleeping/idle-suspending
	// while the agent runs, so the mobile can reach it on demand. Best-effort:
	// macOS clamshell (lid-closed) sleep and forced low-battery sleep are not
	// inhibited, and non-systemd Linux has no inhibitor. Default false.
	KeepAwake bool `toml:"keep_awake"`
}

// filePowerConfig is used for TOML unmarshaling so we can distinguish
// "keep_awake absent" (nil) from "keep_awake = false" (pointer to false).
type filePowerConfig struct {
	KeepAwake *bool `toml:"keep_awake"`
}

// UpdateConfig holds auto-update configuration.
type UpdateConfig struct {
	Enabled       bool   `toml:"enabled"`        // default true
	CheckInterval string `toml:"check_interval"` // duration string, e.g., "24h"
}

// fileUpdateConfig is used for TOML unmarshaling so we can distinguish
// "enabled absent" (nil) from "enabled = false" (pointer to false).
type fileUpdateConfig struct {
	Enabled       *bool  `toml:"enabled"`
	CheckInterval string `toml:"check_interval"`
}

// fileServerConfig is used for TOML unmarshaling so we can distinguish
// "api_version absent" (nil) from "api_version = """ (pointer to empty string).
// Clients that set api_version = "" explicitly opt out of the versioned URL
// prefix, which is required for compatibility with older signaling servers.
type fileServerConfig struct {
	URL        string  `toml:"url"`
	APIVersion *string `toml:"api_version"`
}

// fileConfig mirrors Config but uses fileUpdateConfig for the [update] section
// and fileServerConfig for the [server] section. Only used during TOML parsing.
type fileConfig struct {
	Name       string               `toml:"name,omitempty"`
	LogLevel   string               `toml:"log_level,omitempty"`
	Server     fileServerConfig     `toml:"server"`
	Identity   IdentityConfig       `toml:"identity"`
	Connection fileConnectionConfig `toml:"connection"`
	Tmux       TmuxConfig           `toml:"tmux"`
	Update     fileUpdateConfig     `toml:"update"`
	Power      filePowerConfig      `toml:"power"`
}

// ServerConfig holds signaling server configuration.
type ServerConfig struct {
	URL        string `toml:"url"`
	APIVersion string `toml:"api_version"`
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
	ForceRelay           bool   `toml:"force_relay"`            // testing: force ICE relay-only (TURN)
}

// fileConnectionConfig is used for TOML unmarshaling so we can distinguish
// "force_relay absent" (nil) from "force_relay = false" (pointer to false).
type fileConnectionConfig struct {
	ReconnectInterval    string `toml:"reconnect_interval"`
	KeepaliveInterval    string `toml:"keepalive_interval"`
	MaxMobileConnections int    `toml:"max_mobile_connections"`
	ForceRelay           *bool  `toml:"force_relay"`
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
	APIVersion           configSource
	KeyPath              configSource
	SecretBackend        configSource
	ReconnectInterval    configSource
	KeepaliveInterval    configSource
	MaxMobileConnections configSource
	ForceRelay           configSource
	SocketName           configSource
	TmuxPath             configSource
	Name                 configSource
	LogLevel             configSource
	UpdateEnabled        configSource
	UpdateCheckInterval  configSource
	KeepAwake            configSource
}

// Defaults returns the default configuration.
// The server URL uses https:// as the base URL; signaling.go converts to wss:// for WebSocket.
func Defaults() Config {
	return Config{
		LogLevel: "info",
		Server:   ServerConfig{URL: DefaultServerURL, APIVersion: "v1"},
		Identity: IdentityConfig{KeyPath: "~/.config/pmux/keys/", SecretBackend: "auto"},
		Connection: ConnectionConfig{
			ReconnectInterval:    "5s",
			KeepaliveInterval:    "30s",
			MaxMobileConnections: 1,
		},
		Tmux:   TmuxConfig{SocketName: "pmux"},
		Update: UpdateConfig{Enabled: true, CheckInterval: "24h"},
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

	// Parse file into a separate struct so we can overlay non-zero values.
	// Uses fileConfig (not Config) to distinguish absent bools from false.
	var fileCfg fileConfig
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

	var fileCfg fileConfig
	if err := toml.Unmarshal(data, &fileCfg); err != nil {
		return Config{}, ConfigSources{}, fmt.Errorf("parse config: %w", err)
	}

	overlayFileTracked(&cfg, &fileCfg, &sources)
	applyEnvOverridesTracked(&cfg, &sources)

	return cfg, sources, nil
}

// overlayFile overlays non-zero file values onto defaults.
func overlayFile(cfg *Config, fileCfg *fileConfig) {
	if fileCfg.Name != "" {
		cfg.Name = fileCfg.Name
	}
	if fileCfg.LogLevel != "" {
		cfg.LogLevel = fileCfg.LogLevel
	}
	if fileCfg.Server.URL != "" {
		cfg.Server.URL = fileCfg.Server.URL
	}
	if fileCfg.Server.APIVersion != nil {
		cfg.Server.APIVersion = *fileCfg.Server.APIVersion
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
	if fileCfg.Connection.ForceRelay != nil {
		cfg.Connection.ForceRelay = *fileCfg.Connection.ForceRelay
	}
	if fileCfg.Tmux.SocketName != "" {
		cfg.Tmux.SocketName = fileCfg.Tmux.SocketName
	}
	if fileCfg.Tmux.TmuxPath != "" {
		cfg.Tmux.TmuxPath = fileCfg.Tmux.TmuxPath
	}
	if fileCfg.Update.CheckInterval != "" {
		cfg.Update.CheckInterval = fileCfg.Update.CheckInterval
	}
	if fileCfg.Update.Enabled != nil {
		cfg.Update.Enabled = *fileCfg.Update.Enabled
	}
	if fileCfg.Power.KeepAwake != nil {
		cfg.Power.KeepAwake = *fileCfg.Power.KeepAwake
	}
}

// overlayFileTracked is like overlayFile but also records source annotations.
func overlayFileTracked(cfg *Config, fileCfg *fileConfig, sources *ConfigSources) {
	if fileCfg.Name != "" {
		cfg.Name = fileCfg.Name
		sources.Name = sourceFile
	}
	if fileCfg.LogLevel != "" {
		cfg.LogLevel = fileCfg.LogLevel
		sources.LogLevel = sourceFile
	}
	if fileCfg.Server.URL != "" {
		cfg.Server.URL = fileCfg.Server.URL
		sources.ServerURL = sourceFile
	}
	if fileCfg.Server.APIVersion != nil {
		cfg.Server.APIVersion = *fileCfg.Server.APIVersion
		sources.APIVersion = sourceFile
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
	if fileCfg.Connection.ForceRelay != nil {
		cfg.Connection.ForceRelay = *fileCfg.Connection.ForceRelay
		sources.ForceRelay = sourceFile
	}
	if fileCfg.Tmux.SocketName != "" {
		cfg.Tmux.SocketName = fileCfg.Tmux.SocketName
		sources.SocketName = sourceFile
	}
	if fileCfg.Tmux.TmuxPath != "" {
		cfg.Tmux.TmuxPath = fileCfg.Tmux.TmuxPath
		sources.TmuxPath = sourceFile
	}
	if fileCfg.Update.CheckInterval != "" {
		cfg.Update.CheckInterval = fileCfg.Update.CheckInterval
		sources.UpdateCheckInterval = sourceFile
	}
	if fileCfg.Update.Enabled != nil {
		cfg.Update.Enabled = *fileCfg.Update.Enabled
		sources.UpdateEnabled = sourceFile
	}
	if fileCfg.Power.KeepAwake != nil {
		cfg.Power.KeepAwake = *fileCfg.Power.KeepAwake
		sources.KeepAwake = sourceFile
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
	// PMUX_API_VERSION uses LookupEnv so an explicit empty string (""),
	// which disables the versioned URL prefix for legacy server compatibility,
	// can be distinguished from "unset".
	if v, ok := os.LookupEnv(EnvAPIVersion); ok {
		cfg.Server.APIVersion = v
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
	if v := os.Getenv(EnvLogLevel); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv(EnvUpdateEnabled); v != "" {
		cfg.Update.Enabled = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv(EnvUpdateInterval); v != "" {
		cfg.Update.CheckInterval = v
	}
	if v := os.Getenv(EnvForceRelay); v != "" {
		cfg.Connection.ForceRelay = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv(EnvKeepAwake); v != "" {
		cfg.Power.KeepAwake = v == "true" || v == "1" || v == "yes"
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
	if v, ok := os.LookupEnv(EnvAPIVersion); ok {
		cfg.Server.APIVersion = v
		sources.APIVersion = sourceEnv
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
	if v := os.Getenv(EnvLogLevel); v != "" {
		cfg.LogLevel = v
		sources.LogLevel = sourceEnv
	}
	if v := os.Getenv(EnvUpdateEnabled); v != "" {
		cfg.Update.Enabled = v == "true" || v == "1" || v == "yes"
		sources.UpdateEnabled = sourceEnv
	}
	if v := os.Getenv(EnvUpdateInterval); v != "" {
		cfg.Update.CheckInterval = v
		sources.UpdateCheckInterval = sourceEnv
	}
	if v := os.Getenv(EnvForceRelay); v != "" {
		cfg.Connection.ForceRelay = v == "true" || v == "1" || v == "yes"
		sources.ForceRelay = sourceEnv
	}
	if v := os.Getenv(EnvKeepAwake); v != "" {
		cfg.Power.KeepAwake = v == "true" || v == "1" || v == "yes"
		sources.KeepAwake = sourceEnv
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

	// api_version must be "" (legacy/unversioned) or "v1". Additional versions
	// can be added as the signaling server evolves.
	switch c.Server.APIVersion {
	case "", "v1":
		// valid
	default:
		return fmt.Errorf("server.api_version must be %q or %q, got %q", "", "v1", c.Server.APIVersion)
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
	// Note: an over-cap keepalive_interval is NOT a validation error — it would
	// hard-fail the agent on startup after an upgrade for anyone who tuned it up.
	// KeepaliveInterval() clamps it to MaxKeepaliveInterval instead.

	// max_mobile_connections must be exactly 1 (single-pairing mode)
	if c.Connection.MaxMobileConnections != 1 {
		return fmt.Errorf("connection.max_mobile_connections must be 1 (single-pairing mode)")
	}

	// socket_name must be non-empty
	if c.Tmux.SocketName == "" {
		return fmt.Errorf("tmux.socket_name must not be empty")
	}

	// update.check_interval must parse if non-empty
	if c.Update.CheckInterval != "" {
		if _, err := time.ParseDuration(c.Update.CheckInterval); err != nil {
			return fmt.Errorf("update.check_interval: %w", err)
		}
	}

	// log_level must be a recognized value
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("log_level must be %q, %q, %q, or %q, got %q",
			"debug", "info", "warn", "error", c.LogLevel)
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

// MaxKeepaliveInterval caps the presence-heartbeat interval. The signaling
// server reaps a host as offline after 90s of silence (WS_IDLE_TIMEOUT_MS), so
// keepalive must stay <= half that — otherwise a single dropped heartbeat would
// flap a live host offline.
const MaxKeepaliveInterval = 45 * time.Second

// parsedKeepalive returns the configured keepalive duration and whether it
// parsed. Centralizing the parse keeps KeepaliveInterval and KeepaliveClamped
// from drifting.
func (c *Config) parsedKeepalive() (time.Duration, bool) {
	d, err := time.ParseDuration(c.Connection.KeepaliveInterval)
	return d, err == nil
}

// KeepaliveInterval returns the configured keepalive interval duration, clamped
// to MaxKeepaliveInterval. Falls back to 30s if parsing fails. Call
// KeepaliveClamped to detect whether the configured value was capped.
func (c *Config) KeepaliveInterval() time.Duration {
	d, ok := c.parsedKeepalive()
	if !ok {
		return 30 * time.Second
	}
	if d > MaxKeepaliveInterval {
		return MaxKeepaliveInterval
	}
	return d
}

// KeepaliveClamped reports whether the configured keepalive_interval exceeds
// MaxKeepaliveInterval and was therefore clamped by KeepaliveInterval. An
// unparseable value falls back to 30s and is not considered clamped.
func (c *Config) KeepaliveClamped() bool {
	d, ok := c.parsedKeepalive()
	return ok && d > MaxKeepaliveInterval
}

// UpdateCheckInterval returns the parsed update check interval duration.
// Falls back to 24h if parsing fails.
func (c *Config) UpdateCheckInterval() time.Duration {
	d, err := time.ParseDuration(c.Update.CheckInterval)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

// ServerURL returns the effective signaling server URL from the config.
// This replaces the old standalone ServerURL() function.
// The URL is resolved from: defaults → config file → env vars.
//
// Use ServerURL for QR code payloads and user-facing display (the bare host
// URL, with no version prefix). For HTTP/WS calls to the signaling server,
// use APIBaseURL so requests are routed through the configured API version.
func (c *Config) ServerURL() string {
	return c.Server.URL
}

// APIBaseURL returns the server URL with the configured API version suffix
// (e.g., "https://signal.pmux.io/v1"). When APIVersion is empty, it returns
// the bare server URL so legacy deployments without version prefixes still
// work. Callers pass this value to HTTP/WebSocket helpers as the serverURL
// argument so every request path picks up the prefix automatically.
func (c *Config) APIBaseURL() string {
	base := strings.TrimRight(c.Server.URL, "/")
	if c.Server.APIVersion == "" {
		return base
	}
	return base + "/" + c.Server.APIVersion
}

// ParseLogLevel returns the slog.Level corresponding to the configured log level.
// Accepted values (case-insensitive): "debug", "info", "warn", "error".
// Falls back to slog.LevelInfo for unrecognized values.
func (c *Config) ParseLogLevel() slog.Level {
	switch strings.ToLower(c.LogLevel) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// FormatEffective returns a formatted string showing all config values with sources.
func FormatEffective(cfg Config, sources ConfigSources) string {
	var b strings.Builder
	fmt.Fprintf(&b, "name = %q  (%s)\n", cfg.Name, sources.Name)
	fmt.Fprintf(&b, "log_level = %q  (%s)\n", cfg.LogLevel, sources.LogLevel)
	fmt.Fprintf(&b, "server.url = %q  (%s)\n", cfg.Server.URL, sources.ServerURL)
	fmt.Fprintf(&b, "server.api_version = %q  (%s)\n", cfg.Server.APIVersion, sources.APIVersion)
	fmt.Fprintf(&b, "identity.key_path = %q  (%s)\n", cfg.Identity.KeyPath, sources.KeyPath)
	fmt.Fprintf(&b, "identity.secret_backend = %q  (%s)\n", cfg.Identity.SecretBackend, sources.SecretBackend)
	fmt.Fprintf(&b, "connection.reconnect_interval = %q  (%s)\n", cfg.Connection.ReconnectInterval, sources.ReconnectInterval)
	keepaliveNote := ""
	if cfg.KeepaliveClamped() {
		keepaliveNote = fmt.Sprintf(" [clamped to %s]", MaxKeepaliveInterval)
	}
	fmt.Fprintf(&b, "connection.keepalive_interval = %q%s  (%s)\n", cfg.Connection.KeepaliveInterval, keepaliveNote, sources.KeepaliveInterval)
	fmt.Fprintf(&b, "connection.max_mobile_connections = %d  (%s)\n", cfg.Connection.MaxMobileConnections, sources.MaxMobileConnections)
	fmt.Fprintf(&b, "connection.force_relay = %v  (%s)\n", cfg.Connection.ForceRelay, sources.ForceRelay)
	fmt.Fprintf(&b, "tmux.socket_name = %q  (%s)\n", cfg.Tmux.SocketName, sources.SocketName)
	fmt.Fprintf(&b, "tmux.tmux_path = %q  (%s)\n", cfg.Tmux.TmuxPath, sources.TmuxPath)
	fmt.Fprintf(&b, "update.enabled = %v  (%s)\n", cfg.Update.Enabled, sources.UpdateEnabled)
	fmt.Fprintf(&b, "update.check_interval = %q  (%s)\n", cfg.Update.CheckInterval, sources.UpdateCheckInterval)
	fmt.Fprintf(&b, "power.keep_awake = %v  (%s)\n", cfg.Power.KeepAwake, sources.KeepAwake)
	return b.String()
}

// CommentedDefaultConfig returns a well-commented default config.toml for use
// by `pmux init`. Values are commented out so they act as documentation without
// overriding defaults.
func CommentedDefaultConfig() string {
	return `# Pocketmux Agent Configuration

# Log level: "debug", "info", "warn", or "error" (env: PMUX_LOG_LEVEL)
# log_level = "info"

[server]
# Signaling server URL (env: PMUX_SERVER_URL)
# url = "https://signal.pmux.io"
# Signaling server API version prefix (env: PMUX_API_VERSION)
# Accepted values: "v1" (default) or "" (legacy, unversioned paths)
# All HTTP/WebSocket endpoints are prefixed with /<api_version> when non-empty.
# Set to "" only when pointing at a signaling server that predates API versioning.
# api_version = "v1"

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
# How often the agent sends a presence heartbeat. Values above 45s are clamped
# to 45s — the signaling server marks a host offline after 90s of silence.
# keepalive_interval = "30s"
# max_mobile_connections = 1
# Force ICE into relay-only (TURN) mode for testing/debugging (env: PMUX_FORCE_RELAY).
# When true, the agent gathers only TURN-relayed candidates — a successful connection
# proves the TURN path works; a failure isolates TURN as the problem. Leave false in
# normal use, as it disables direct peer-to-peer connections.
# force_relay = false

[tmux]
# socket_name = "pmux"
# Absolute path to tmux binary (env: PMUX_TMUX_PATH)
# Resolved automatically during 'pmux init'. Set manually if tmux moves.
# tmux_path = "/opt/homebrew/bin/tmux"

[update]
# Enable automatic update checking (env: PMUX_UPDATE_ENABLED)
# Defaults to true. Set to false to disable update notifications.
# enabled = true
# How often the agent checks for updates (env: PMUX_UPDATE_INTERVAL)
# check_interval = "24h"

[power]
# Keep the host awake while the agent is running (env: PMUX_KEEP_AWAKE).
# Prevents idle sleep so the mobile app can reach this host on demand — a
# sleeping machine drops off the network and shows offline shortly after.
# Best-effort: on macOS this does NOT override closing the laptop lid
# (clamshell sleep) or forced low-battery sleep; on Linux it requires systemd.
# Defaults to false.
# keep_awake = false
`
}

// Paths holds resolved filesystem paths for Pocketmux configuration and keys.
type Paths struct {
	ConfigDir     string // ~/.config/pmux
	KeysDir       string // ~/.config/pmux/keys
	PairedDevices string // ~/.config/pmux/paired_devices.json
	ConfigFile    string // ~/.config/pmux/config.toml
}

// DefaultPaths returns the standard Pocketmux directory paths based on $HOME.
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

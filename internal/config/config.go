// Package config handles configuration file parsing and path defaults.
// Config stored at ~/.config/pocketmux/config.toml.
package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	appDir  = "pocketmux"
	keysDir = "keys"
)

// Paths holds resolved filesystem paths for PocketMux configuration and keys.
type Paths struct {
	ConfigDir string // ~/.config/pocketmux
	KeysDir   string // ~/.config/pocketmux/keys
}

// DefaultPaths returns the standard PocketMux directory paths based on $HOME.
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("determine home directory: %w", err)
	}

	configDir := filepath.Join(home, ".config", appDir)
	return Paths{
		ConfigDir: configDir,
		KeysDir:   filepath.Join(configDir, keysDir),
	}, nil
}

// EnsureDirs creates the config and keys directories if they don't exist.
func (p Paths) EnsureDirs() error {
	if err := os.MkdirAll(p.KeysDir, 0700); err != nil {
		return fmt.Errorf("create keys directory: %w", err)
	}
	return nil
}

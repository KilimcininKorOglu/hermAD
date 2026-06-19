// Package config defines the runtime-editable application configuration and its
// JSON persistence. The configuration is stored as a single document inside the
// data directory and is edited at runtime through the admin page.
//
// The active configuration is shared between the HTTP handlers and the
// background ticker, so it is guarded by an atomic pointer: readers call Get
// (which returns an immutable snapshot) and writers call Save (which persists
// the document and atomically swaps the snapshot).
package config

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// ServerConfig describes a single AdGuard Home instance the panel manages.
type ServerConfig struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Auth bool   `json:"auth"`
	User string `json:"user"`
	Pass string `json:"pass"`
}

// AutoSync controls the optional periodic rule synchronization performed by the
// background ticker. Direction is "master_to_backup" or "backup_to_master".
type AutoSync struct {
	Enabled         bool   `json:"enabled"`
	Direction       string `json:"direction"`
	IntervalMinutes int    `json:"interval_minutes"`
}

// Config is the full, runtime-editable application configuration.
type Config struct {
	AuthEnabled          bool                    `json:"auth_enabled"`
	PanelUser            string                  `json:"panel_user"`
	PanelPass            string                  `json:"panel_pass"`
	BackupServer         bool                    `json:"backup_server"`
	UptimeRetentionHours int                     `json:"uptime_retention_hours"`
	UptimeIntervalMin    int                     `json:"uptime_interval_minutes"`
	Language             string                  `json:"language"`
	AutoSync             AutoSync                `json:"auto_sync"`
	Servers              map[string]ServerConfig `json:"servers"`
}

// Default returns the built-in configuration written on first run.
func Default() *Config {
	return &Config{
		AuthEnabled:          false,
		PanelUser:            "admin",
		PanelPass:            "",
		BackupServer:         true,
		UptimeRetentionHours: 24,
		UptimeIntervalMin:    5,
		Language:             "tr",
		AutoSync:             AutoSync{Enabled: false, Direction: "master_to_backup", IntervalMinutes: 60},
		Servers: map[string]ServerConfig{
			"master": {Name: "Master DNS", URL: "http://192.168.1.100", Auth: true, User: "adguard", Pass: "adguard1"},
			"backup": {Name: "Backup DNS", URL: "http://192.168.1.101:8080", Auth: false, User: "adguard", Pass: "adguard1"},
		},
	}
}

// Clone returns a deep copy safe to mutate before passing to Save. The snapshot
// returned by Get must never be mutated in place.
func (c *Config) Clone() *Config {
	cp := *c
	cp.Servers = maps.Clone(c.Servers)
	return &cp
}

// HasBackup reports whether the backup server is active (enabled and defined).
func (c *Config) HasBackup() bool {
	if !c.BackupServer {
		return false
	}
	_, ok := c.Servers["backup"]
	return ok
}

// ServerKeys returns the active server keys in display order (master first),
// honoring the BackupServer flag.
func (c *Config) ServerKeys() []string {
	keys := make([]string, 0, 2)
	if _, ok := c.Servers["master"]; ok {
		keys = append(keys, "master")
	}
	if c.HasBackup() {
		keys = append(keys, "backup")
	}
	return keys
}

// normalize clamps values to sane ranges and guarantees required maps exist.
func (c *Config) normalize() {
	if c.Servers == nil {
		c.Servers = map[string]ServerConfig{}
	}
	if c.Language != "en" && c.Language != "tr" {
		c.Language = "tr"
	}
	if c.UptimeIntervalMin < 1 {
		c.UptimeIntervalMin = 5
	}
	if c.UptimeRetentionHours < 0 {
		c.UptimeRetentionHours = 0
	}
	if c.AutoSync.Direction != "backup_to_master" {
		c.AutoSync.Direction = "master_to_backup"
	}
	if c.AutoSync.IntervalMinutes < 1 {
		c.AutoSync.IntervalMinutes = 60
	}
}

// Manager owns the active configuration snapshot and its persistence.
type Manager struct {
	path    string
	saveMu  sync.Mutex
	current atomic.Pointer[Config]
}

// NewManager loads the configuration from path, creating it with defaults when
// it does not exist.
func NewManager(path string) (*Manager, error) {
	m := &Manager{path: path}
	cfg, err := load(path)
	if err != nil {
		return nil, err
	}
	m.current.Store(cfg)
	return m, nil
}

// Get returns the current immutable configuration snapshot.
func (m *Manager) Get() *Config { return m.current.Load() }

// Save persists cfg and atomically publishes it as the active snapshot.
func (m *Manager) Save(cfg *Config) error {
	cfg.normalize()
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	if err := save(m.path, cfg); err != nil {
		return err
	}
	m.current.Store(cfg)
	return nil
}

func load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg := Default()
		if err := save(path, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	cfg := Default()
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	cfg.normalize()
	return cfg, nil
}

func save(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// Credentials live in this file, so keep it owner-only and write atomically.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Package store persists uptime history and the last-sync marker as a single
// JSON document in the data directory. Every access is synchronized because the
// store is written by the background ticker and read/written by HTTP handlers.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Sample is one uptime observation for a server.
type Sample struct {
	Time int64 `json:"time"`
	Up   bool  `json:"up"`
}

type data struct {
	Uptime   map[string][]Sample `json:"uptime"`
	LastSync string              `json:"last_sync"`
}

// Store holds the persisted panel data behind a mutex.
type Store struct {
	path string
	mu   sync.Mutex
	d    data
}

// New loads the store from path, starting empty when the file does not exist.
func New(path string) (*Store, error) {
	s := &Store{path: path, d: data{Uptime: map[string][]Sample{}}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.d); err != nil {
		return nil, err
	}
	if s.d.Uptime == nil {
		s.d.Uptime = map[string][]Sample{}
	}
	return s, nil
}

// AppendUptime records a sample for key, prunes history to the retention window,
// and persists the result.
func (s *Store) AppendUptime(key string, up bool, retentionHours int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Uptime[key] = append(s.d.Uptime[key], Sample{Time: time.Now().Unix(), Up: up})
	s.prune(retentionHours)
	return s.save()
}

// History returns a copy of key's samples within the retention window.
func (s *Store) History(key string, retentionHours int) []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := windowStart(retentionHours)
	src := s.d.Uptime[key]
	out := make([]Sample, 0, len(src))
	for _, smp := range src {
		if smp.Time >= limit {
			out = append(out, smp)
		}
	}
	return out
}

// SetLastSync records and persists a human-readable last-sync marker.
func (s *Store) SetLastSync(v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.LastSync = v
	return s.save()
}

// LastSync returns the last-sync marker.
func (s *Store) LastSync() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.LastSync
}

// Raw returns the full persisted document as pretty JSON for export.
func (s *Store) Raw() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.MarshalIndent(s.d, "", "  ")
}

// prune drops samples older than the retention window. Caller holds the lock.
func (s *Store) prune(retentionHours int) {
	if retentionHours <= 0 {
		return
	}
	limit := windowStart(retentionHours)
	for k, samples := range s.d.Uptime {
		kept := make([]Sample, 0, len(samples))
		for _, smp := range samples {
			if smp.Time >= limit {
				kept = append(kept, smp)
			}
		}
		s.d.Uptime[k] = kept
	}
}

// save writes the document atomically. Caller holds the lock.
func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// windowStart returns the unix cutoff for the retention window. A non-positive
// retention keeps everything.
func windowStart(retentionHours int) int64 {
	if retentionHours <= 0 {
		return 0
	}
	return time.Now().Add(-time.Duration(retentionHours) * time.Hour).Unix()
}

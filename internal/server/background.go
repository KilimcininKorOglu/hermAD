package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/sinezty/hermad/internal/config"
)

// StartBackground launches the periodic worker that records uptime samples and,
// when enabled, performs auto-sync. It re-reads the live config every tick so
// changes from the admin page take effect without a restart. The worker stops
// when ctx is cancelled.
func (s *Server) StartBackground(ctx context.Context) {
	go func() {
		// Record one sample immediately so the dashboard has data on first load,
		// but only when uptime collection is enabled (mirrors the loop's guard).
		if cfg := s.cfg.Get(); cfg.UptimeRetentionHours > 0 {
			s.collectUptime(cfg)
		}

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		lastUptime := time.Now()
		lastSync := time.Now()

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				cfg := s.cfg.Get()
				if cfg.UptimeRetentionHours > 0 && cfg.UptimeIntervalMin > 0 &&
					now.Sub(lastUptime) >= time.Duration(cfg.UptimeIntervalMin)*time.Minute {
					s.collectUptime(cfg)
					lastUptime = now
				}
				if cfg.HasBackup() && cfg.AutoSync.Enabled && cfg.AutoSync.IntervalMinutes > 0 &&
					now.Sub(lastSync) >= time.Duration(cfg.AutoSync.IntervalMinutes)*time.Minute {
					if err := s.runSync(cfg, cfg.AutoSync.Direction, true); err != nil {
						log.Printf("auto-sync: %v", err)
					}
					lastSync = now
				}
			}
		}
	}()
}

// collectUptime probes every active server's status and appends a sample.
func (s *Server) collectUptime(cfg *config.Config) {
	for _, k := range cfg.ServerKeys() {
		st, err := s.ag.Status(toAG(cfg.Servers[k]))
		up := err == nil && st.Running
		if err := s.store.AppendUptime(k, up, cfg.UptimeRetentionHours); err != nil {
			log.Printf("uptime store (%s): %v", k, err)
		}
	}
}

// runSync copies the source server's user rules to the destination and records
// the result. direction is "master_to_backup" or "backup_to_master"; auto marks
// scheduled runs in the last-sync marker.
func (s *Server) runSync(cfg *config.Config, direction string, auto bool) error {
	var srcKey, dstKey, label string
	switch direction {
	case "master_to_backup":
		srcKey, dstKey, label = "master", "backup", "Master -> Backup"
	case "backup_to_master":
		srcKey, dstKey, label = "backup", "master", "Backup -> Master"
	default:
		return fmt.Errorf("invalid sync direction %q", direction)
	}

	filtering, err := s.ag.Filtering(toAG(cfg.Servers[srcKey]))
	if err != nil {
		return err
	}
	// Refuse to push an empty rule set: set_rules overwrites the destination
	// wholesale, so syncing from a source that returned no rules (e.g. a freshly
	// reinstalled or misbehaving AdGuard) would silently wipe the other HA copy.
	if len(filtering.UserRules) == 0 {
		return fmt.Errorf("refusing to sync %s: source %q returned no rules (would wipe destination)", label, srcKey)
	}
	if err := s.ag.SetRules(toAG(cfg.Servers[dstKey]), filtering.UserRules); err != nil {
		return err
	}

	marker := fmt.Sprintf("%s (%s)", time.Now().Format("2006-01-02 15:04:05"), label)
	if auto {
		marker += " [auto]"
	}
	return s.store.SetLastSync(marker)
}

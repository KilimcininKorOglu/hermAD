// Package adguard is a minimal client for the AdGuard Home control API. It
// covers only the endpoints the panel needs: status, statistics, the user-rules
// section of the filtering config, and protection toggling.
package adguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Server identifies a target AdGuard Home instance and its optional Basic auth.
type Server struct {
	URL  string
	Auth bool
	User string
	Pass string
}

// Status mirrors the relevant fields of GET /control/status.
//
// Current AdGuard Home (v0.107.x) reports a timed pause as
// ProtectionDisabledDuration: the remaining milliseconds. Older builds instead
// returned ProtectionDisabledUntil as either a millisecond epoch or an RFC3339
// string. Remaining handles all three. ProtectionDisabledUntil is decoded as a
// generic value because its historical type varied.
type Status struct {
	Running                    bool    `json:"running"`
	ProtectionEnabled          bool    `json:"protection_enabled"`
	ProtectionDisabledDuration float64 `json:"protection_disabled_duration"`
	ProtectionDisabledUntil    any     `json:"protection_disabled_until"`
}

// Remaining returns the time left on a timed pause, preferring the current
// duration-in-milliseconds field and falling back to the legacy
// protection_disabled_until value. It returns 0 when protection is active or no
// pause is in effect.
func (s *Status) Remaining() time.Duration {
	if s.ProtectionDisabledDuration > 0 {
		return time.Duration(s.ProtectionDisabledDuration) * time.Millisecond
	}
	return RemainingPause(s.ProtectionDisabledUntil)
}

// Stats mirrors the relevant fields of GET /control/stats. The query and block
// series are decoded as floats because AdGuard returns numeric arrays.
type Stats struct {
	NumDNSQueries       int       `json:"num_dns_queries"`
	NumBlockedFiltering int       `json:"num_blocked_filtering"`
	AvgProcessingTime   float64   `json:"avg_processing_time"`
	DNSQueries          []float64 `json:"dns_queries"`
	BlockedFiltering    []float64 `json:"blocked_filtering"`
}

// Filtering mirrors the user_rules section of GET /control/filtering/status.
type Filtering struct {
	UserRules []string `json:"user_rules"`
}

// Client performs AdGuard Home API requests with a bounded timeout.
type Client struct {
	hc *http.Client
}

// New returns a client with an 8-second per-request timeout.
func New() *Client {
	return &Client{hc: &http.Client{Timeout: 8 * time.Second}}
}

func (c *Client) get(srv Server, path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		return err
	}
	if srv.Auth {
		req.SetBasicAuth(srv.User, srv.Pass)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) post(srv Server, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if srv.Auth {
		req.SetBasicAuth(srv.User, srv.Pass)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(snippet))
	}
	return nil
}

// Status fetches the running and protection state of srv.
func (c *Client) Status(srv Server) (*Status, error) {
	var s Status
	if err := c.get(srv, "/control/status", &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Stats fetches the query/block statistics of srv.
func (c *Client) Stats(srv Server) (*Stats, error) {
	var s Stats
	if err := c.get(srv, "/control/stats", &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Filtering fetches the user rules of srv.
func (c *Client) Filtering(srv Server) (*Filtering, error) {
	var f Filtering
	if err := c.get(srv, "/control/filtering/status", &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// SetRules overwrites the entire user-rules list on srv.
func (c *Client) SetRules(srv Server, rules []string) error {
	return c.post(srv, "/control/filtering/set_rules", map[string]any{"rules": rules})
}

// SetProtection enables or disables protection on srv. When disabling, a
// positive durationMs schedules an automatic re-enable (timed pause).
func (c *Client) SetProtection(srv Server, enabled bool, durationMs int) error {
	payload := map[string]any{"enabled": enabled}
	if !enabled && durationMs > 0 {
		payload["duration"] = durationMs
	}
	return c.post(srv, "/control/protection", payload)
}

// RemainingPause returns the time left on a timed pause. It accepts the
// protection_disabled_until value as either a millisecond epoch or an RFC3339
// string, and returns 0 when protection is active or the value is unparseable.
func RemainingPause(disabledUntil any) time.Duration {
	switch v := disabledUntil.(type) {
	case float64:
		if d := time.Until(time.UnixMilli(int64(v))); d > 0 {
			return d
		}
	case string:
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
	}
	return 0
}

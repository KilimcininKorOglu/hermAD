package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sinezty/hermad/internal/adguard"
	"github.com/sinezty/hermad/internal/config"
	"github.com/sinezty/hermad/internal/store"
)

// basePage carries the fields every rendered page needs for the shared layout.
type basePage struct {
	Lang      string
	Langs     []string
	AuthOn    bool
	HasBackup bool
	Active    string
	Version   string
}

// basePage builds the shared layout fields from the current config and request.
func (s *Server) basePage(r *http.Request, active string) basePage {
	cfg := s.cfg.Get()
	return basePage{
		Lang:      s.lang(r),
		Langs:     s.i18n.Languages(),
		AuthOn:    cfg.AuthEnabled,
		HasBackup: cfg.HasBackup(),
		Active:    active,
		Version:   s.version,
	}
}

// bar is one chart column expressed as a CSS height percentage plus a tooltip.
type bar struct {
	H     string
	Title string
}

// serverView is the rendered state of a single AdGuard Home instance.
type serverView struct {
	Key            string
	Name           string
	URL            string
	Up             bool
	Reachable      bool
	ProtectionOn   bool
	PausedRemain   string
	NumQueries     string
	NumBlocked     string
	BlockedPercent string
	AvgLatencyMs   string
	HasChart       bool
	ChartQueries   []bar
	ChartBlocked   []bar
	DomainText     string
	RuleCount      int
}

// uptimeView holds the normalized uptime segments for a server.
type uptimeView struct {
	Name     string
	Segments []bool
	Empty    bool
}

// buildServerViews fetches and renders every active server concurrently.
func (s *Server) buildServerViews(cfg *config.Config) []serverView {
	keys := cfg.ServerKeys()
	out := make([]serverView, len(keys))
	var wg sync.WaitGroup
	for i, k := range keys {
		wg.Go(func() {
			out[i] = s.buildServerView(cfg, k)
		})
	}
	wg.Wait()
	return out
}

func (s *Server) buildServerView(cfg *config.Config, key string) serverView {
	sc := cfg.Servers[key]
	srv := toAG(sc)
	v := serverView{
		Key: key, Name: sc.Name, URL: sc.URL,
		NumQueries: "0", NumBlocked: "0", BlockedPercent: "0.00", AvgLatencyMs: "0.00",
	}

	// The three control-API calls are independent and each writes a disjoint set
	// of fields on v, so they run concurrently to bound a single server view at
	// one request timeout instead of three.
	var wg sync.WaitGroup
	wg.Go(func() {
		if st, err := s.ag.Status(srv); err == nil {
			v.Reachable = true
			v.Up = st.Running
			v.ProtectionOn = st.ProtectionEnabled
			if !st.ProtectionEnabled {
				if d := st.Remaining(); d > 0 {
					v.PausedRemain = fmtDuration(d)
				}
			}
		}
	})
	wg.Go(func() {
		if stats, err := s.ag.Stats(srv); err == nil {
			v.NumQueries = fmtInt(stats.NumDNSQueries)
			v.NumBlocked = fmtInt(stats.NumBlockedFiltering)
			pct := 0.0
			if stats.NumDNSQueries > 0 {
				pct = float64(stats.NumBlockedFiltering) / float64(stats.NumDNSQueries) * 100
			}
			v.BlockedPercent = fmt.Sprintf("%.2f", pct)
			v.AvgLatencyMs = fmt.Sprintf("%.2f", stats.AvgProcessingTime*1000)
			if len(stats.DNSQueries) > 0 {
				v.HasChart = true
				v.ChartQueries, v.ChartBlocked = buildChart(stats.DNSQueries, stats.BlockedFiltering)
			}
		}
	})
	wg.Go(func() {
		if f, err := s.ag.Filtering(srv); err == nil {
			domains := whitelistDomains(f.UserRules)
			v.DomainText = strings.Join(domains, "\n")
			v.RuleCount = len(domains)
		}
	})
	wg.Wait()
	return v
}

// buildUptime renders the uptime bars for every active server, falling back to a
// single live segment when no history has been recorded yet.
func (s *Server) buildUptime(cfg *config.Config, views []serverView) []uptimeView {
	segMax := 96
	if !cfg.HasBackup() {
		segMax = 144
	}
	live := make(map[string]bool, len(views))
	for _, v := range views {
		live[v.Key] = v.Up
	}
	out := make([]uptimeView, 0, len(cfg.ServerKeys()))
	for _, k := range cfg.ServerKeys() {
		segs := normalizeUptime(s.store.History(k, cfg.UptimeRetentionHours), segMax)
		uv := uptimeView{Name: cfg.Servers[k].Name}
		if len(segs) == 0 {
			uv.Empty = true
			uv.Segments = []bool{live[k]}
		} else {
			uv.Segments = segs
		}
		out = append(out, uv)
	}
	return out
}

// normalizeUptime downsamples history to at most maxSegments evenly-spaced
// up/down flags.
func normalizeUptime(history []store.Sample, maxSegments int) []bool {
	n := len(history)
	if n == 0 {
		return nil
	}
	if n <= maxSegments {
		out := make([]bool, n)
		for i, smp := range history {
			out[i] = smp.Up
		}
		return out
	}
	out := make([]bool, maxSegments)
	step := float64(n) / float64(maxSegments)
	for i := range maxSegments {
		idx := int(float64(i) * step)
		if idx >= n {
			idx = n - 1
		}
		out[i] = history[idx].Up
	}
	return out
}

// buildChart normalizes the query and block series against the query maximum so
// the two bar rows are visually comparable.
func buildChart(queries, blocked []float64) ([]bar, []bar) {
	max := 1.0
	for _, q := range queries {
		if q > max {
			max = q
		}
	}
	qb := make([]bar, len(queries))
	for i, q := range queries {
		qb[i] = bar{H: pct(q, max), Title: fmtInt(int(q))}
	}
	bb := make([]bar, len(blocked))
	for i, b := range blocked {
		bb[i] = bar{H: pct(b, max), Title: fmtInt(int(b))}
	}
	return qb, bb
}

func pct(v, max float64) string {
	p := v / max * 100
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	return strconv.FormatFloat(p, 'f', 1, 64)
}

// ---- whitelist rule helpers ----

// whitelistDomains extracts the plain domains from allow rules (@@||domain^).
// Non-allow rules are intentionally excluded; the editor manages only the
// whitelist, while save preserves all other rules untouched.
func whitelistDomains(rules []string) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		if strings.HasPrefix(r, "@@||") {
			if d := cleanRule(r); strings.TrimSpace(d) != "" {
				out = append(out, d)
			}
		}
	}
	return out
}

// mergeWhitelist keeps every non-allow rule and rebuilds the @@||domain^ allow
// rules from the editor's raw text.
func mergeWhitelist(current []string, raw string) []string {
	merged := make([]string, 0, len(current))
	for _, r := range current {
		if !strings.HasPrefix(r, "@@||") {
			merged = append(merged, r)
		}
	}
	for line := range strings.SplitSeq(raw, "\n") {
		d := cleanRule(strings.TrimSpace(line))
		if d == "" {
			continue
		}
		merged = append(merged, "@@||"+d+"^")
	}
	return merged
}

// cleanRule strips the @@|| prefix and everything from the first ^ so an allow
// rule collapses to its bare domain.
func cleanRule(rule string) string {
	rule = strings.TrimPrefix(rule, "@@||")
	if i := strings.Index(rule, "^"); i >= 0 {
		rule = rule[:i]
	}
	return strings.TrimSpace(rule)
}

// ---- formatting helpers ----

func toAG(sc config.ServerConfig) adguard.Server {
	return adguard.Server{URL: sc.URL, Auth: sc.Auth, User: sc.User, Pass: sc.Pass}
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	return fmt.Sprintf("%dm %ds", int(d/time.Minute), int((d%time.Minute)/time.Second))
}

// fmtInt formats an integer with thousands separators.
func fmtInt(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i := range len(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteByte(s[i])
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

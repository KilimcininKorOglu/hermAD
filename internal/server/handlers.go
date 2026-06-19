package server

import (
	"net/http"
	"slices"
	"strconv"

	"github.com/sinezty/hermad/internal/config"
)

// dashboardData is the view model for the dashboard page.
type dashboardData struct {
	basePage
	Servers  []serverView
	Uptime   []uptimeView
	UptimeOn bool
	LastSync string
}

// serversFragment is the view model for the HTMX-refreshed server grid.
type serversFragment struct {
	Lang      string
	HasBackup bool
	Servers   []serverView
}

// alertData is the view model for a toast message.
type alertData struct {
	Kind string // "ok" or "err"
	Msg  string
}

// dashboard renders the full dashboard page.
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	cfg := s.cfg.Get()
	views := s.buildServerViews(cfg)
	data := dashboardData{
		basePage: s.basePage(r, "dashboard"),
		Servers:  views,
		Uptime:   s.buildUptime(cfg, views),
		UptimeOn: cfg.UptimeRetentionHours > 0,
		LastSync: s.store.LastSync(),
	}
	if err := s.tmpl.page(w, "dashboard", data); err != nil {
		s.fail(w, err)
	}
}

// partialServers returns just the server grid for HTMX polling/refresh.
func (s *Server) partialServers(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()
	data := serversFragment{
		Lang:      s.lang(r),
		HasBackup: cfg.HasBackup(),
		Servers:   s.buildServerViews(cfg),
	}
	if err := s.tmpl.partial(w, "servers", data); err != nil {
		s.fail(w, err)
	}
}

// actionProtection enables, disables, or timed-pauses protection on one server.
func (s *Server) actionProtection(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()
	key := r.FormValue("server_key")
	if !isActiveKey(cfg, key) {
		s.toast(w, r, "err", "msg.error")
		return
	}
	srv := toAG(cfg.Servers[key])
	var err error
	switch r.FormValue("protection_action") {
	case "enable":
		err = s.ag.SetProtection(srv, true, 0)
	case "disable":
		err = s.ag.SetProtection(srv, false, 0)
	case "disable_time":
		mins, _ := strconv.Atoi(r.FormValue("duration"))
		err = s.ag.SetProtection(srv, false, mins*60*1000)
	default:
		s.toast(w, r, "err", "msg.error")
		return
	}
	if err != nil {
		s.toast(w, r, "err", "msg.error")
		return
	}
	s.refresh(w)
	s.toast(w, r, "ok", "msg.protection_updated")
}

// actionWhitelist rewrites the allow rules of one server from the editor text.
func (s *Server) actionWhitelist(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()
	key := r.FormValue("server_key")
	if !isActiveKey(cfg, key) {
		s.toast(w, r, "err", "msg.error")
		return
	}
	srv := toAG(cfg.Servers[key])
	current, err := s.ag.Filtering(srv)
	if err != nil {
		s.toast(w, r, "err", "msg.whitelist_failed")
		return
	}
	if err := s.ag.SetRules(srv, mergeWhitelist(current.UserRules, r.FormValue("whitelist_data"))); err != nil {
		s.toast(w, r, "err", "msg.whitelist_failed")
		return
	}
	s.refresh(w)
	s.toast(w, r, "ok", "msg.whitelist_updated")
}

// actionSync runs a manual rule synchronization between master and backup.
func (s *Server) actionSync(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()
	if !cfg.HasBackup() {
		s.toast(w, r, "err", "msg.error")
		return
	}
	if err := s.runSync(cfg, r.FormValue("direction"), false); err != nil {
		s.toast(w, r, "err", "msg.sync_failed")
		return
	}
	s.refresh(w)
	s.toast(w, r, "ok", "msg.sync_done")
}

// export streams the persisted data document as a JSON download.
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.Raw()
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="hermad_data.json"`)
	_, _ = w.Write(b)
}

// toast renders a toast alert fragment for an HTMX swap into #toast.
func (s *Server) toast(w http.ResponseWriter, r *http.Request, kind, msgKey string) {
	data := alertData{Kind: kind, Msg: s.i18n.T(s.lang(r), msgKey)}
	if err := s.tmpl.partial(w, "alert", data); err != nil {
		s.fail(w, err)
	}
}

// refresh asks HTMX clients to reload the server grid via the "refresh" event.
func (s *Server) refresh(w http.ResponseWriter) {
	w.Header().Set("HX-Trigger", "refresh")
}

func isActiveKey(cfg *config.Config, key string) bool {
	return slices.Contains(cfg.ServerKeys(), key)
}

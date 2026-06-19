package server

import (
	"net/http"
	"strconv"
	"strings"
)

// adminData is the view model for the configuration management page.
type adminData struct {
	basePage
	Cfg *adminConfigView
}

// adminConfigView exposes the editable configuration to the template without the
// stored passwords, which are never echoed back into the form.
type adminConfigView struct {
	AuthEnabled          bool
	PanelUser            string
	BackupServer         bool
	UptimeRetentionHours int
	UptimeIntervalMin    int
	Language             string
	AutoSyncEnabled      bool
	AutoSyncDirection    string
	AutoSyncInterval     int
	Master               serverFormView
	Backup               serverFormView
}

type serverFormView struct {
	Key  string
	Name string
	URL  string
	Auth bool
	User string
}

// adminPage renders the configuration form populated with the current values.
func (s *Server) adminPage(w http.ResponseWriter, r *http.Request) {
	if err := s.tmpl.page(w, "admin", adminData{
		basePage: s.basePage(r, "admin"),
		Cfg:      s.adminConfigView(),
	}); err != nil {
		s.fail(w, err)
	}
}

// adminSave applies the submitted configuration and publishes it live. Password
// fields left blank keep their stored values.
func (s *Server) adminSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.toast(w, r, "err", "msg.error")
		return
	}
	cur := s.cfg.Get()
	n := cur.Clone()

	n.AuthEnabled = r.FormValue("auth_enabled") == "on"
	n.PanelUser = strings.TrimSpace(r.FormValue("panel_user"))
	if p := r.FormValue("panel_pass"); p != "" {
		n.PanelPass = p
	}
	n.BackupServer = r.FormValue("backup_server") == "on"
	n.UptimeRetentionHours = atoiDefault(r.FormValue("uptime_retention"), cur.UptimeRetentionHours)
	n.UptimeIntervalMin = atoiDefault(r.FormValue("uptime_interval"), cur.UptimeIntervalMin)
	if lang := r.FormValue("language"); s.i18n.Has(lang) {
		n.Language = lang
	}
	n.AutoSync.Enabled = r.FormValue("autosync_enabled") == "on"
	n.AutoSync.Direction = r.FormValue("autosync_direction")
	n.AutoSync.IntervalMinutes = atoiDefault(r.FormValue("autosync_interval"), cur.AutoSync.IntervalMinutes)

	for _, key := range []string{"master", "backup"} {
		sc := n.Servers[key]
		sc.Name = strings.TrimSpace(r.FormValue(key + "_name"))
		sc.URL = strings.TrimSpace(r.FormValue(key + "_url"))
		sc.Auth = r.FormValue(key+"_auth") == "on"
		sc.User = strings.TrimSpace(r.FormValue(key + "_user"))
		if p := r.FormValue(key + "_pass"); p != "" {
			sc.Pass = p
		}
		n.Servers[key] = sc
	}

	if err := s.cfg.Save(n); err != nil {
		s.toast(w, r, "err", "msg.error")
		return
	}
	s.toast(w, r, "ok", "admin.saved")
}

func (s *Server) adminConfigView() *adminConfigView {
	c := s.cfg.Get()
	master := c.Servers["master"]
	backup := c.Servers["backup"]
	return &adminConfigView{
		AuthEnabled:          c.AuthEnabled,
		PanelUser:            c.PanelUser,
		BackupServer:         c.BackupServer,
		UptimeRetentionHours: c.UptimeRetentionHours,
		UptimeIntervalMin:    c.UptimeIntervalMin,
		Language:             c.Language,
		AutoSyncEnabled:      c.AutoSync.Enabled,
		AutoSyncDirection:    c.AutoSync.Direction,
		AutoSyncInterval:     c.AutoSync.IntervalMinutes,
		Master:               serverFormView{Key: "master", Name: master.Name, URL: master.URL, Auth: master.Auth, User: master.User},
		Backup:               serverFormView{Key: "backup", Name: backup.Name, URL: backup.URL, Auth: backup.Auth, User: backup.User},
	}
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

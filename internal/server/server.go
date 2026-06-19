// Package server wires the HTTP layer: routing, middleware (security headers,
// language resolution, optional authentication), HTML rendering, and the
// background ticker that collects uptime and runs auto-sync.
package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"github.com/sinezty/hermad/internal/adguard"
	"github.com/sinezty/hermad/internal/config"
	"github.com/sinezty/hermad/internal/i18n"
	"github.com/sinezty/hermad/internal/store"
)

// Server holds the dependencies shared by every HTTP handler.
type Server struct {
	cfg     *config.Manager
	store   *store.Store
	ag      *adguard.Client
	i18n    *i18n.Bundle
	tmpl    *renderer
	static  fs.FS
	secret  []byte
	version string
	limiter *loginLimiter
}

// New constructs a Server. tmplFS must contain base/page templates and a
// partials/ subdirectory; staticFS serves /static assets. secret signs session
// cookies; version is the application version shown in the UI.
func New(cfgMgr *config.Manager, st *store.Store, bundle *i18n.Bundle, tmplFS, staticFS fs.FS, secret []byte, version string) (*Server, error) {
	s := &Server{
		cfg:     cfgMgr,
		store:   st,
		ag:      adguard.New(),
		i18n:    bundle,
		static:  staticFS,
		secret:  secret,
		version: version,
		limiter: newLoginLimiter(),
	}
	funcs := template.FuncMap{"t": bundle.T, "dict": dict}
	r, err := newRenderer(tmplFS, funcs)
	if err != nil {
		return nil, err
	}
	s.tmpl = r
	return s, nil
}

// Handler returns the fully wired HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /", s.dashboard)
	mux.HandleFunc("GET /partials/servers", s.partialServers)
	mux.HandleFunc("POST /actions/protection", s.actionProtection)
	mux.HandleFunc("POST /actions/whitelist", s.actionWhitelist)
	mux.HandleFunc("POST /actions/sync", s.actionSync)
	mux.HandleFunc("GET /dns", s.dnsPage)
	mux.HandleFunc("GET /partials/dns", s.partialDNS)
	mux.HandleFunc("POST /actions/dns/save", s.actionDNSSave)
	mux.HandleFunc("POST /actions/dns/delete", s.actionDNSDelete)
	mux.HandleFunc("POST /actions/dns/reconcile", s.actionDNSReconcile)
	mux.HandleFunc("GET /export", s.export)
	mux.HandleFunc("GET /admin", s.adminPage)
	mux.HandleFunc("POST /admin", s.adminSave)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("GET /logout", s.logout)
	mux.HandleFunc("GET /lang/{code}", s.setLang)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(s.static)))
	return securityHeaders(s.withLang(s.withAuth(mux)))
}

// ---- middleware ----

type ctxKey int

const langCtxKey ctxKey = iota

// securityHeaders applies the strict framing and caching headers required for an
// admin panel that exposes credentials.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		if strings.HasPrefix(r.URL.Path, "/static/") {
			// Static assets carry no secrets; allow caching with mandatory
			// revalidation (304) instead of forbidding it outright.
			w.Header().Set("Cache-Control", "no-cache")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// withLang resolves the active language (cookie, then config default) and stores
// it on the request context.
func (s *Server) withLang(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := s.cfg.Get().Language
		if c, err := r.Cookie("lang"); err == nil && s.i18n.Has(c.Value) {
			lang = c.Value
		}
		ctx := context.WithValue(r.Context(), langCtxKey, s.i18n.Resolve(lang))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// withAuth redirects unauthenticated requests to the login page when panel
// authentication is enabled.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Get().AuthEnabled && !isPublicPath(r.URL.Path) && !s.validSession(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isPublicPath(p string) bool {
	return p == "/login" || p == "/healthz" || strings.HasPrefix(p, "/static/") || strings.HasPrefix(p, "/lang/")
}

// health is an unauthenticated liveness probe used by container/orchestrator
// health checks.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// lang returns the resolved language for the request.
func (s *Server) lang(r *http.Request) string {
	if v, ok := r.Context().Value(langCtxKey).(string); ok {
		return v
	}
	return s.i18n.Resolve(s.cfg.Get().Language)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	log.Printf("server: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// ---- rendering ----

type renderer struct {
	pages    map[string]*template.Template
	partials *template.Template
}

func newRenderer(tmplFS fs.FS, funcs template.FuncMap) (*renderer, error) {
	r := &renderer{pages: map[string]*template.Template{}}
	pages := map[string][]string{
		"dashboard": {"base.html", "dashboard.html"},
		"dns":       {"base.html", "dns.html"},
		"admin":     {"base.html", "admin.html"},
		"login":     {"base.html", "login.html"},
	}
	for name, files := range pages {
		t := template.New(name).Funcs(funcs)
		if _, err := t.ParseFS(tmplFS, "partials/*.html"); err != nil {
			return nil, err
		}
		if _, err := t.ParseFS(tmplFS, files...); err != nil {
			return nil, err
		}
		r.pages[name] = t
	}
	pt := template.New("partials").Funcs(funcs)
	if _, err := pt.ParseFS(tmplFS, "partials/*.html"); err != nil {
		return nil, err
	}
	r.partials = pt
	return r, nil
}

// page renders a full page through the base layout, buffering so a template
// error never produces a half-written response.
func (r *renderer) page(w http.ResponseWriter, name string, data any) error {
	t, ok := r.pages[name]
	if !ok {
		return fmt.Errorf("unknown page %q", name)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := buf.WriteTo(w)
	return err
}

// partial renders a named fragment (used for HTMX swaps).
func (r *renderer) partial(w http.ResponseWriter, name string, data any) error {
	var buf bytes.Buffer
	if err := r.partials.ExecuteTemplate(&buf, name, data); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := buf.WriteTo(w)
	return err
}

// dict builds a map from alternating key/value template arguments, enabling
// multi-argument sub-template calls.
func dict(values ...any) (map[string]any, error) {
	if len(values)%2 != 0 {
		return nil, errors.New("dict: odd number of arguments")
	}
	m := make(map[string]any, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, errors.New("dict: keys must be strings")
		}
		m[key] = values[i+1]
	}
	return m, nil
}

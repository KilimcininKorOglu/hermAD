// Command hermad serves the AdGuard Home HA management dashboard. It
// embeds its templates, static assets, and locale bundles, persists runtime
// state under the data directory, and exposes the web UI over HTTP.
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sinezty/hermad/internal/config"
	"github.com/sinezty/hermad/internal/i18n"
	"github.com/sinezty/hermad/internal/server"
	"github.com/sinezty/hermad/internal/store"
)

//go:embed web
var webFS embed.FS

//go:embed locales
var localesFS embed.FS

//go:embed VERSION
var versionRaw string

// version is the application version, embedded from the VERSION file at build time.
var version = strings.TrimSpace(versionRaw)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			fmt.Println("hermad " + version)
			return
		}
	}

	dataDir := env("HERMAD_DATA_DIR", "./docker-data")
	listen := env("HERMAD_LISTEN", ":8080")

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("data dir: %v", err)
	}

	cfgMgr, err := config.NewManager(filepath.Join(dataDir, "config.json"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := ensurePanelPassword(cfgMgr); err != nil {
		log.Fatalf("panel password: %v", err)
	}

	st, err := store.New(filepath.Join(dataDir, "data.json"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	localesSub := mustSub(localesFS, "locales")
	bundle, err := i18n.Load(localesSub, "tr")
	if err != nil {
		log.Fatalf("i18n: %v", err)
	}

	secret, err := loadSecret(filepath.Join(dataDir, "session.key"))
	if err != nil {
		log.Fatalf("secret: %v", err)
	}

	srv, err := server.New(cfgMgr, st, bundle, mustSub(webFS, "web/templates"), mustSub(webFS, "web/static"), secret, version)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv.StartBackground(ctx)

	httpSrv := &http.Server{Addr: listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("hermad %s listening on %s (data: %s)", version, listen, dataDir)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	log.Println("shutdown complete")
}

// env returns the value of key or def when unset/empty.
func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// mustSub returns a sub-filesystem or aborts; the embedded layout is fixed at
// build time, so a failure here is a programming error.
func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		log.Fatalf("embed sub %q: %v", dir, err)
	}
	return sub
}

// ensurePanelPassword generates and persists a random panel password the first
// time authentication is enabled without one, logging it once so the operator
// can sign in. It is a no-op when authentication is disabled or a password is
// already set, so it never overwrites an operator-chosen password.
func ensurePanelPassword(m *config.Manager) error {
	cfg := m.Get()
	if !cfg.AuthEnabled || cfg.PanelPass != "" {
		return nil
	}
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	pw := hex.EncodeToString(buf)
	c := cfg.Clone()
	c.PanelPass = pw
	if err := m.Save(c); err != nil {
		return err
	}
	log.Printf("generated panel password for user %q: %s (change it on the admin page)", c.PanelUser, pw)
	return nil
}

// loadSecret reads the session-signing secret, generating and persisting a new
// 32-byte secret on first run so sessions survive restarts.
func loadSecret(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, err
	}
	return secret, nil
}

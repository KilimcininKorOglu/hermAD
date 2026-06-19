package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/sinezty/hermad/internal/config"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	mgr, err := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("config manager: %v", err)
	}
	return &Server{secret: []byte("test-secret-0123456789abcdef"), cfg: mgr}
}

func issuedCookie(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	s.issueSession(w, httptest.NewRequest(http.MethodPost, "/login", nil))
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie issued")
	return nil
}

func requestWithCookie(c *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func TestValidSessionRoundTrip(t *testing.T) {
	s := testServer(t)
	if !s.validSession(requestWithCookie(issuedCookie(t, s))) {
		t.Fatal("a freshly issued session should be valid")
	}
}

func TestValidSessionRejectsTamper(t *testing.T) {
	s := testServer(t)
	c := issuedCookie(t, s)
	c.Value += "x" // corrupt the signature
	if s.validSession(requestWithCookie(c)) {
		t.Fatal("a tampered session must be rejected")
	}
}

func TestValidSessionInvalidatedByPasswordChange(t *testing.T) {
	s := testServer(t)
	c := issuedCookie(t, s)
	cfg := s.cfg.Get().Clone()
	cfg.PanelPass = "a-new-password"
	if err := s.cfg.Save(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	if s.validSession(requestWithCookie(c)) {
		t.Fatal("changing the panel password must invalidate existing sessions")
	}
}

func TestValidSessionWithoutCookie(t *testing.T) {
	s := testServer(t)
	if s.validSession(requestWithCookie(nil)) {
		t.Fatal("a request without a session cookie must be invalid")
	}
}

func TestIssueSessionSecureFlag(t *testing.T) {
	s := testServer(t)
	// Plain HTTP: cookie must not be Secure (would break login over HTTP).
	w := httptest.NewRecorder()
	s.issueSession(w, httptest.NewRequest(http.MethodPost, "/login", nil))
	if c := w.Result().Cookies()[0]; c.Secure {
		t.Error("cookie should not be Secure over plain HTTP")
	}
	// Behind a TLS-terminating proxy: cookie must be Secure.
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	s.issueSession(w, r)
	if c := w.Result().Cookies()[0]; !c.Secure {
		t.Error("cookie should be Secure when X-Forwarded-Proto is https")
	}
}

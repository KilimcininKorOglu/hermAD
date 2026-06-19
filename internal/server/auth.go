package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie = "hermad_session"
	sessionTTL    = 12 * time.Hour
	maxLoginFails = 5
	loginLockout  = 15 * time.Minute
)

// loginLimiter throttles repeated failed logins per client IP to slow online
// brute force. It keeps a small in-memory map guarded by a mutex; expired
// entries are pruned on each failure so it cannot grow unbounded.
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempts
}

type loginAttempts struct {
	fails int
	until time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: map[string]*loginAttempts{}}
}

// blocked reports whether key is currently locked out.
func (l *loginLimiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[key]
	return a != nil && a.fails >= maxLoginFails && time.Now().Before(a.until)
}

// fail records a failed attempt, locking the key once the threshold is reached.
func (l *loginLimiter) fail(key string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, a := range l.attempts {
		if a.fails >= maxLoginFails && now.After(a.until) {
			delete(l.attempts, k)
		}
	}
	a := l.attempts[key]
	if a == nil {
		a = &loginAttempts{}
		l.attempts[key] = a
	}
	a.fails++
	if a.fails >= maxLoginFails {
		a.until = now.Add(loginLockout)
	}
}

// reset clears a key's failure count after a successful login.
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}

// clientIP returns the request's source IP without the port, used as the
// rate-limit key.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// loginData is the view model for the login page.
type loginData struct {
	basePage
	Error bool
}

// loginPage renders the login form.
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Get().AuthEnabled && s.validSession(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := s.tmpl.page(w, "login", loginData{basePage: s.basePage(r, "")}); err != nil {
		s.fail(w, err)
	}
}

// loginSubmit verifies the panel credentials and issues a session cookie.
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()
	ip := clientIP(r)
	if s.limiter.blocked(ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		if err := s.tmpl.page(w, "login", loginData{basePage: s.basePage(r, ""), Error: true}); err != nil {
			s.fail(w, err)
		}
		return
	}
	user := r.FormValue("login_user")
	pass := r.FormValue("login_pass")
	if constEqual(user, cfg.PanelUser) && constEqual(pass, cfg.PanelPass) {
		s.limiter.reset(ip)
		s.issueSession(w, r)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.limiter.fail(ip)
	w.WriteHeader(http.StatusUnauthorized)
	if err := s.tmpl.page(w, "login", loginData{basePage: s.basePage(r, ""), Error: true}); err != nil {
		s.fail(w, err)
	}
}

// logout clears the session cookie.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// setLang stores the chosen language in a cookie and returns to the referrer.
func (s *Server) setLang(w http.ResponseWriter, r *http.Request) {
	if code := r.PathValue("code"); s.i18n.Has(code) {
		http.SetCookie(w, &http.Cookie{
			Name: "lang", Value: code, Path: "/", MaxAge: 31536000, SameSite: http.SameSiteLaxMode,
		})
	}
	dest := r.Header.Get("Referer")
	if dest == "" {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// issueSession sets a signed session cookie valid for sessionTTL. The Secure
// flag is set when the request arrived over HTTPS (directly or via a
// TLS-terminating proxy) so the cookie is not exposed on a cleartext hop.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request) {
	exp := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	value := exp + "." + s.sign(exp)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: value, Path: "/",
		Expires: time.Now().Add(sessionTTL), HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: isSecureRequest(r),
	})
}

// isSecureRequest reports whether the request reached the server over HTTPS,
// either directly or via a TLS-terminating proxy that set X-Forwarded-Proto.
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// validSession reports whether the request carries a valid, unexpired session.
func (s *Server) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	exp, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	ts, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().Unix() > ts {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(s.sign(exp)))
}

// sign returns the hex HMAC-SHA256 of msg under the server secret, bound to the
// current panel password. Mixing in the password means changing it invalidates
// every previously issued session token.
func (s *Server) sign(msg string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(msg))
	mac.Write([]byte{0})
	mac.Write([]byte(s.cfg.Get().PanelPass))
	return hex.EncodeToString(mac.Sum(nil))
}

// constEqual compares two strings in constant time.
func constEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

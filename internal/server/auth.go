package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookie = "hermad_session"
	sessionTTL    = 12 * time.Hour
)

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
	user := r.FormValue("login_user")
	pass := r.FormValue("login_pass")
	if constEqual(user, cfg.PanelUser) && constEqual(pass, cfg.PanelPass) {
		s.issueSession(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
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

// issueSession sets a signed session cookie valid for sessionTTL.
func (s *Server) issueSession(w http.ResponseWriter) {
	exp := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	value := exp + "." + s.sign(exp)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: value, Path: "/",
		Expires: time.Now().Add(sessionTTL), HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
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

// sign returns the hex HMAC-SHA256 of msg under the server secret.
func (s *Server) sign(msg string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// constEqual compares two strings in constant time.
func constEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

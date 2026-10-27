// Package app implements the HTTP handlers of the cookie-issuing web application.
package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"example.com/cfcookie/internal/config"
)

//go:embed web/index.html web/style.css
var webFS embed.FS

var pageTmpl = template.Must(template.ParseFS(webFS, "web/index.html"))

// ConfigSource yields the current configuration.
type ConfigSource interface {
	Get(ctx context.Context) (*config.Config, error)
}

// Server wires the handlers.
type Server struct {
	Config ConfigSource
	// FailDelay slows down wrong-password responses to blunt online guessing.
	FailDelay time.Duration
	// Sleep is replaceable in tests. It must return early when ctx is done.
	Sleep func(ctx context.Context, d time.Duration)
}

const maxBody = 4 << 10

// Handler returns the routed handler with all middleware applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.page)
	mux.HandleFunc("GET /login", s.page)
	mux.HandleFunc("GET /style.css", s.style)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)

	// Rejects cross-site POSTs using Sec-Fetch-Site / Origin. It compares Origin with
	// the Host header, so CloudFront must forward Host (see docs/cloudfront-s3-setup.md).
	cop := http.NewCrossOriginProtection()
	return accessLog(secureHeaders(cop.Handler(mux)))
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", csp("'self'"))
		next.ServeHTTP(w, r)
	})
}

// csp is the policy for every response. formAction lists where the page's forms may lead.
// Chrome applies form-action to the redirect that answers a form post as well, so pages with a
// form must allow the static site's origin (see render).
func csp(formAction string) string {
	return "default-src 'none'; style-src 'self'; form-action " + formAction + "; base-uri 'none'; frame-ancestors 'none'"
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// accessLog writes one structured line per request. It logs the path only (never the
// query string or form values) and the CloudFront request ID for support cases.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" {
			return
		}
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"ms", time.Since(start).Milliseconds(),
			"cf_id", r.Header.Get("X-Amz-Cf-Id"),
		)
	})
}

type pageData struct {
	Error string
	Next  string
	// StaticURL is the entry point of the static site; empty when the configuration cannot be loaded.
	StaticURL string
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, data pageData) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	if cfg, err := s.Config.Get(r.Context()); err == nil {
		origin := cfg.Signer.Origin()
		h.Set("Content-Security-Policy", csp("'self' "+origin))
		data.StaticURL = origin + cfg.Prefix
	}
	w.WriteHeader(status)
	if err := pageTmpl.Execute(w, data); err != nil {
		slog.Error("render page", "error", err)
	}
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, pageData{Next: r.URL.Query().Get("next")})
}

func (s *Server) style(w http.ResponseWriter, _ *http.Request) {
	b, _ := webFS.ReadFile("web/style.css")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.Config.Get(r.Context())
	if err != nil {
		slog.Error("load config", "error", err)
		http.Error(w, "service misconfigured", http.StatusInternalServerError)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostForm.Get("next"), cfg.Prefix)

	if !passwordMatches(r.PostForm.Get("password"), cfg.Password) {
		slog.Warn("login failed", "cf_id", r.Header.Get("X-Amz-Cf-Id"))
		s.sleep(r.Context(), s.FailDelay)
		s.render(w, r, http.StatusUnauthorized, pageData{Error: "Wrong password.", Next: next})
		return
	}

	// The cookies belong to the static site's host, so they are not set here: the browser is sent
	// to the static site, which stores them and then opens next.
	target, expires, err := cfg.Signer.HandoffURL(next)
	if err != nil {
		slog.Error("issue cookies", "error", err)
		http.Error(w, "could not issue cookies", http.StatusInternalServerError)
		return
	}
	slog.Info("login ok", "expires", expires, "cf_id", r.Header.Get("X-Amz-Cf-Id"))
	// The URL carries the signature. The page that submitted the form sends Referrer-Policy: no-referrer
	// (secureHeaders), so it does not leak through Referer, and the response is never cached.
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.Config.Get(r.Context())
	if err != nil {
		slog.Error("load config", "error", err)
		http.Error(w, "service misconfigured", http.StatusInternalServerError)
		return
	}
	// Only the static host can delete its own cookies.
	http.Redirect(w, r, cfg.Signer.ClearURL(), http.StatusSeeOther)
}

func (s *Server) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	if s.Sleep != nil {
		s.Sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// passwordMatches compares in constant time. Hashing first makes both inputs the
// same length so the comparison time does not leak the secret's length.
func passwordMatches(got string, want []byte) bool {
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256(want)
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// safeNext only allows local paths under the protected prefix, preventing open redirects.
func safeNext(next, prefix string) string {
	def := prefix + "index.html"
	if next == "" || !strings.HasPrefix(next, prefix) || strings.ContainsAny(next, "\\\r\n") {
		return def
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.Contains(u.Path, "//") {
		return def
	}
	return next
}

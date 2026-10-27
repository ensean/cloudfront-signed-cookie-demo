package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.com/cfcookie/internal/config"
	"example.com/cfcookie/internal/signer"
)

const testPassword = "correct-horse-battery"

type fakeSource struct {
	cfg *config.Config
	err error
}

func (f fakeSource) Get(context.Context) (*config.Config, error) { return f.cfg, f.err }

func newServer(t *testing.T) (*Server, *time.Duration) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := signer.New(signer.Options{
		KeyID: "KTEST", Key: key, Domain: "d1.cloudfront.net", PathPrefix: "/", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	var slept time.Duration
	return &Server{
		Config:    fakeSource{cfg: &config.Config{Signer: sg, Password: []byte(testPassword), Prefix: "/"}},
		FailDelay: 250 * time.Millisecond,
		Sleep:     func(_ context.Context, d time.Duration) { slept += d },
	}, &slept
}

// post sends a form POST the way CloudFront would deliver it: Host is the distribution
// domain, a browser adds Origin / Sec-Fetch-Site unless the caller overrides them.
func post(h http.Handler, path string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "https://d1.cloudfront.net"+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// handoff parses the Location of a successful login: it must lead to the static site's cookie endpoint.
func handoff(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "d1.cloudfront.net" || u.Path != "/_auth/set" {
		t.Fatalf("Location = %q, want https://d1.cloudfront.net/_auth/set?...", u)
	}
	return u.Query()
}

func TestLoginSuccessRedirect(t *testing.T) {
	s, slept := newServer(t)
	rec := post(s.Handler(), "/login", url.Values{"password": {testPassword}, "next": {"/docs/a.html"}}, nil)

	q := handoff(t, rec)
	if q.Get("n") != "/docs/a.html" {
		t.Errorf("n = %q", q.Get("n"))
	}
	for _, k := range []string{"p", "s", "k", "e"} {
		if q.Get(k) == "" {
			t.Errorf("handoff lacks %q", k)
		}
	}
	if q.Get("k") != "KTEST" {
		t.Errorf("k = %q", q.Get("k"))
	}
	if *slept != 0 {
		t.Errorf("successful login must not be delayed, slept %s", *slept)
	}
}

func TestLoginDefaultsToIndex(t *testing.T) {
	s, _ := newServer(t)
	q := handoff(t, post(s.Handler(), "/login", url.Values{"password": {testPassword}}, nil))
	if q.Get("n") != "/index.html" {
		t.Errorf("n = %q", q.Get("n"))
	}
}

// The signed cookies belong to the static host; a cookie set here could never be sent there.
func TestLoginSetsNoCookiesOnTheMainHost(t *testing.T) {
	s, _ := newServer(t)
	rec := post(s.Handler(), "/login", url.Values{"password": {testPassword}}, nil)
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("Set-Cookie = %v, want none", got)
	}
}

func TestLoginWrongPasswordRendersFormAgain(t *testing.T) {
	s, slept := newServer(t)
	for _, pw := range []string{"wrong", "", testPassword + "x", strings.ToUpper(testPassword)} {
		*slept = 0
		rec := post(s.Handler(), "/login", url.Values{"password": {pw}, "next": {"/report.txt"}}, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("password %q: status = %d, want 401", pw, rec.Code)
		}
		if n := len(rec.Result().Cookies()); n != 0 {
			t.Errorf("password %q: leaked %d cookies", pw, n)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Wrong password.") || !strings.Contains(body, `value="/report.txt"`) {
			t.Errorf("password %q: form not re-rendered with error and next: %s", pw, body)
		}
		if *slept != 250*time.Millisecond {
			t.Errorf("password %q: delay = %s", pw, *slept)
		}
	}
}

func TestNextIsHTMLEscaped(t *testing.T) {
	s, _ := newServer(t)
	rec := post(s.Handler(), "/login", url.Values{"password": {"bad"}, "next": {`/"><script>alert(1)</script>`}}, nil)
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Errorf("unescaped markup in response: %s", rec.Body.String())
	}
	// And via the query string on the GET page.
	req := httptest.NewRequest(http.MethodGet, `/?next=%22%3E%3Cscript%3Ealert(1)%3C/script%3E`, nil)
	get := httptest.NewRecorder()
	s.Handler().ServeHTTP(get, req)
	if strings.Contains(get.Body.String(), "<script>") {
		t.Errorf("unescaped markup in GET page: %s", get.Body.String())
	}
}

func TestLoginRejectsOversizedBody(t *testing.T) {
	s, _ := newServer(t)
	rec := post(s.Handler(), "/login", url.Values{"password": {strings.Repeat("a", maxBody+1)}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestLoginConfigFailure(t *testing.T) {
	s, _ := newServer(t)
	s.Config = fakeSource{err: errors.New("boom: secret store unavailable")}
	rec := post(s.Handler(), "/login", url.Values{"password": {testPassword}}, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Error("internal error detail leaked to the client")
	}
}

func TestCrossSitePostsAreRejected(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()
	form := url.Values{"password": {testPassword}}

	for name, hdr := range map[string]map[string]string{
		"cross-site fetch metadata": {"Sec-Fetch-Site": "cross-site"},
		"foreign Origin":            {"Origin": "https://evil.example"},
	} {
		rec := post(h, "/login", form, hdr)
		if rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s: status = %d cookies = %d, want 403 and none", name, rec.Code, len(rec.Result().Cookies()))
		}
		if rec := post(h, "/logout", url.Values{}, hdr); rec.Code != http.StatusForbidden {
			t.Errorf("%s: logout status = %d, want 403", name, rec.Code)
		}
	}

	// A browser form post from our own page carries a matching Origin and must work.
	rec := post(h, "/login", form, map[string]string{"Origin": "https://d1.cloudfront.net", "Sec-Fetch-Site": "same-origin"})
	if rec.Code != http.StatusSeeOther {
		t.Errorf("same-origin browser post: status = %d, want 303", rec.Code)
	}
}

func TestSafeNext(t *testing.T) {
	def := "/protected/index.html"
	tests := map[string]string{
		"":                                def,
		"/protected/a.html":               "/protected/a.html",
		"/protected/dir/b.png?x=1":        "/protected/dir/b.png?x=1",
		"/other":                          def,
		"https://evil.example/":           def,
		"//evil.example/protected/":       def,
		"/protected//evil.example":        def,
		"/protected/\\evil":               def,
		"/protected/a\r\nSet-Cookie: x=1": def,
		"protected/a.html":                def,
	}
	for in, want := range tests {
		if got := safeNext(in, "/protected/"); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLogoutSendsBrowserToTheStaticSiteToClearCookies(t *testing.T) {
	s, _ := newServer(t)
	rec := post(s.Handler(), "/logout", url.Values{}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://d1.cloudfront.net/_auth/clear" {
		t.Fatalf("status = %d location = %q, want 303 to the static site's clear endpoint", rec.Code, rec.Header().Get("Location"))
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("Set-Cookie = %v, want none", got)
	}
}

// Chrome applies form-action to the redirect after a form post, so the page that holds the forms
// must allow the static origin. Other responses keep the strict default.
func TestPageAllowsFormsToReachTheStaticSite(t *testing.T) {
	s, _ := newServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://d1.cloudfront.net;") {
		t.Errorf("CSP = %q", csp)
	}
	if !strings.Contains(rec.Body.String(), `href="https://d1.cloudfront.net/"`) {
		t.Errorf("page lacks the link to the static site: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self';") {
		t.Errorf("non-page CSP = %q", csp)
	}
}

func TestPageStillRendersWhenConfigIsUnavailable(t *testing.T) {
	s, _ := newServer(t)
	s.Config = fakeSource{err: errors.New("not configured yet")}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "static site</a>") {
		t.Errorf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self';") {
		t.Errorf("CSP = %q", csp)
	}
}

func TestStaticRoutesAndHeaders(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()
	for _, tc := range []struct{ path, ctype, contains string }{
		{"/", "text/html", "Sign in"},
		{"/login", "text/html", "Sign in"},
		{"/style.css", "text/css", "font-family"},
		{"/healthz", "text/plain", "ok"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", tc.path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, tc.ctype) {
			t.Errorf("%s: content-type %q", tc.path, ct)
		}
		if !strings.Contains(rec.Body.String(), tc.contains) {
			t.Errorf("%s: body lacks %q", tc.path, tc.contains)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing security headers", tc.path)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "script") || strings.Contains(csp, "unsafe") {
			t.Errorf("%s: CSP must not allow scripts or unsafe sources: %q", tc.path, csp)
		}
	}
}

func TestMethodRouting(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/logout", http.StatusMethodNotAllowed},
		{http.MethodGet, "/nope", http.StatusNotFound},
		{http.MethodPut, "/login", http.StatusMethodNotAllowed},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}

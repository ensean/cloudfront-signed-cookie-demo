package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newSigner(t *testing.T, key *rsa.PrivateKey) *Signer {
	t.Helper()
	s, err := New(Options{
		KeyID:      "KTESTKEY123",
		Key:        key,
		Domain:     "d111111abcdef8.cloudfront.net",
		PathPrefix: "/protected/",
		TTL:        time.Hour,
		Now:        func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// cloudFrontDecode reverses CloudFront's URL-safe base64 variant, which writes
// "+" as "-", "=" as "_" and "/" as "~".
func cloudFrontDecode(t *testing.T, s string) []byte {
	t.Helper()
	r := strings.NewReplacer("-", "+", "_", "=", "~", "/")
	b, err := base64.StdEncoding.DecodeString(r.Replace(s))
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func byName(cookies []*http.Cookie) map[string]*http.Cookie {
	m := map[string]*http.Cookie{}
	for _, c := range cookies {
		m[c.Name] = c
	}
	return m
}

func TestIssueProducesVerifiableSHA256Cookies(t *testing.T) {
	key := newKey(t, 2048)
	s := newSigner(t, key)

	cookies, expires, err := s.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if want := fixedNow.Add(time.Hour); !expires.Equal(want) {
		t.Errorf("expires = %s, want %s", expires, want)
	}

	c := byName(cookies)
	for _, name := range []string{"CloudFront-Policy", "CloudFront-Signature", "CloudFront-Key-Pair-Id", "CloudFront-Hash-Algorithm"} {
		if c[name] == nil {
			t.Fatalf("missing cookie %s", name)
		}
	}
	if got := c["CloudFront-Key-Pair-Id"].Value; got != "KTESTKEY123" {
		t.Errorf("key id = %q", got)
	}
	if got := c["CloudFront-Hash-Algorithm"].Value; got != "SHA256" {
		t.Errorf("hash algorithm = %q, want SHA256", got)
	}

	// The signature must verify against the public key over the decoded policy JSON.
	policyJSON := cloudFrontDecode(t, c["CloudFront-Policy"].Value)
	sig := cloudFrontDecode(t, c["CloudFront-Signature"].Value)
	digest := sha256.Sum256(policyJSON)
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	// ... and must NOT verify as SHA-1, otherwise the hash cookie would be a lie.
	sum1 := sha1.Sum(policyJSON)
	if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA1, sum1[:], sig) == nil {
		t.Error("signature unexpectedly verifies as SHA-1")
	}

	var policy struct {
		Statement []struct {
			Resource  string
			Condition struct {
				DateLessThan struct {
					Epoch int64 `json:"AWS:EpochTime"`
				}
			}
		}
	}
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatalf("policy JSON: %v (%s)", err, policyJSON)
	}
	if len(policy.Statement) != 1 {
		t.Fatalf("want 1 statement, got %d", len(policy.Statement))
	}
	st := policy.Statement[0]
	if st.Resource != "https://d111111abcdef8.cloudfront.net/protected/*" {
		t.Errorf("resource = %q", st.Resource)
	}
	if st.Condition.DateLessThan.Epoch != expires.Unix() {
		t.Errorf("epoch = %d, want %d", st.Condition.DateLessThan.Epoch, expires.Unix())
	}
}

func TestIssueCookieAttributes(t *testing.T) {
	cookies, expires, err := newSigner(t, newKey(t, 2048)).Issue()
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 4 {
		t.Fatalf("want 4 cookies, got %d", len(cookies))
	}
	for _, c := range cookies {
		if !c.Secure || !c.HttpOnly {
			t.Errorf("%s: Secure=%v HttpOnly=%v, want both true", c.Name, c.Secure, c.HttpOnly)
		}
		if c.Path != "/protected/" {
			t.Errorf("%s: path = %q", c.Name, c.Path)
		}
		if c.Domain != "" {
			t.Errorf("%s: Domain must be empty (host-only), got %q", c.Name, c.Domain)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("%s: SameSite = %v", c.Name, c.SameSite)
		}
		if !c.Expires.Equal(expires) {
			t.Errorf("%s: Expires = %s, want %s", c.Name, c.Expires, expires)
		}
	}
}

func TestClear(t *testing.T) {
	cleared := newSigner(t, newKey(t, 2048)).Clear()
	if len(cleared) != 4 {
		t.Fatalf("want 4 cookies, got %d", len(cleared))
	}
	for _, c := range cleared {
		if c.MaxAge >= 0 || c.Value != "" || c.Path != "/protected/" {
			t.Errorf("%s: bad clearing cookie %+v", c.Name, c)
		}
		if got := c.String(); !strings.Contains(got, "Max-Age=0") {
			t.Errorf("%s: serialised cookie lacks Max-Age=0: %s", c.Name, got)
		}
	}
}

func TestNewValidation(t *testing.T) {
	k2048 := newKey(t, 2048)
	base := Options{KeyID: "K", Key: k2048, Domain: "d1.cloudfront.net", PathPrefix: "/protected/", TTL: time.Hour}

	tests := []struct {
		name string
		mut  func(*Options)
	}{
		{"no key id", func(o *Options) { o.KeyID = "" }},
		{"1024-bit key", func(o *Options) { o.Key = newKey(t, 1024) }},
		{"domain with scheme", func(o *Options) { o.Domain = "https://d1.cloudfront.net" }},
		{"domain with path", func(o *Options) { o.Domain = "d1.cloudfront.net/x" }},
		{"empty domain", func(o *Options) { o.Domain = "" }},
		{"prefix without trailing slash", func(o *Options) { o.PathPrefix = "/protected" }},
		{"prefix without leading slash", func(o *Options) { o.PathPrefix = "protected/" }},
		{"root prefix", func(o *Options) { o.PathPrefix = "/" }},
		{"zero ttl", func(o *Options) { o.TTL = 0 }},
		{"ttl too long", func(o *Options) { o.TTL = MaxTTL + time.Second }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := base
			tt.mut(&o)
			if _, err := New(o); err == nil {
				t.Error("expected error")
			}
		})
	}
	if _, err := New(base); err != nil {
		t.Errorf("valid options rejected: %v", err)
	}
}

func TestParsePrivateKey(t *testing.T) {
	key := newKey(t, 2048)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"pkcs8": {Type: "PRIVATE KEY", Bytes: pkcs8},
		"pkcs1": {Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParsePrivateKey(pem.EncodeToMemory(block))
			if err != nil {
				t.Fatal(err)
			}
			if !got.(*rsa.PrivateKey).Equal(key) {
				t.Error("parsed key differs")
			}
		})
	}

	if _, err := ParsePrivateKey([]byte("not pem")); err == nil {
		t.Error("expected error for non-PEM input")
	}
	if _, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")})); err == nil {
		t.Error("expected error for garbage key bytes")
	}
}

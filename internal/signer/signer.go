// Package signer issues CloudFront signed cookies (custom policy, SHA-256).
package signer

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign"
)

// MaxTTL bounds how long an issued cookie can be valid.
const MaxTTL = 7 * 24 * time.Hour

// cookieNames lists every cookie that makes up a CloudFront signed-cookie set.
var cookieNames = []string{
	sign.CookiePolicyName,
	sign.CookieSignatureName,
	sign.CookieKeyIDName,
	sign.CookieHashAlgorithmName,
}

// Options configures a Signer.
type Options struct {
	// KeyID is the CloudFront public key ID (the key in the trusted key group).
	KeyID string
	// Key is the RSA-2048 private key matching the CloudFront public key.
	Key crypto.Signer
	// Domain is the CloudFront distribution host name, e.g. d111111abcdef8.cloudfront.net.
	Domain string
	// PathPrefix is the protected path, starting and ending with "/", e.g. "/protected/".
	// The policy grants access to PathPrefix + "*" and the cookies are scoped to PathPrefix.
	PathPrefix string
	// TTL is how long the cookies are valid.
	TTL time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Signer produces signed cookies for one distribution and path prefix.
type Signer struct {
	cs       *sign.CookieSigner
	resource string
	path     string
	ttl      time.Duration
	now      func() time.Time
}

// New validates opts and returns a Signer.
func New(opts Options) (*Signer, error) {
	if opts.KeyID == "" {
		return nil, errors.New("signer: key ID is required")
	}
	rk, ok := opts.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signer: CloudFront requires an RSA key, got %T", opts.Key)
	}
	if rk.N.BitLen() != 2048 {
		return nil, fmt.Errorf("signer: CloudFront requires a 2048-bit RSA key, got %d bits", rk.N.BitLen())
	}
	if opts.Domain == "" || strings.ContainsAny(opts.Domain, "/:?# ") {
		return nil, fmt.Errorf("signer: invalid domain %q (host name only, no scheme or path)", opts.Domain)
	}
	if !strings.HasPrefix(opts.PathPrefix, "/") || !strings.HasSuffix(opts.PathPrefix, "/") || opts.PathPrefix == "/" {
		return nil, fmt.Errorf("signer: path prefix %q must start and end with / and not be the root", opts.PathPrefix)
	}
	if opts.TTL <= 0 || opts.TTL > MaxTTL {
		return nil, fmt.Errorf("signer: TTL %s out of range (0, %s]", opts.TTL, MaxTTL)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	cs := sign.NewCookieSigner(opts.KeyID, opts.Key)
	cs.HashAlg = sign.HashSHA256 // also emits the CloudFront-Hash-Algorithm cookie

	return &Signer{
		cs:       cs,
		resource: "https://" + opts.Domain + opts.PathPrefix + "*",
		path:     opts.PathPrefix,
		ttl:      opts.TTL,
		now:      now,
	}, nil
}

// Resource returns the policy resource pattern the cookies are valid for.
func (s *Signer) Resource() string { return s.resource }

// Issue returns a fresh set of signed cookies and their expiry time.
func (s *Signer) Issue() ([]*http.Cookie, time.Time, error) {
	expires := s.now().Add(s.ttl).UTC().Truncate(time.Second)
	policy := &sign.Policy{
		Statements: []sign.Statement{{
			Resource:  s.resource,
			Condition: sign.Condition{DateLessThan: sign.NewAWSEpochTime(expires)},
		}},
	}
	cookies, err := s.cs.SignWithPolicy(policy, func(o *sign.CookieOptions) {
		o.Path = s.path
		o.Secure = true
		o.SameSite = http.SameSiteLaxMode
		o.Expires = expires
	})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("sign cookies: %w", err)
	}
	return cookies, expires, nil
}

// Clear returns expired cookies that make the browser drop the signed-cookie set.
func (s *Signer) Clear() []*http.Cookie {
	out := make([]*http.Cookie, 0, len(cookieNames))
	for _, name := range cookieNames {
		out = append(out, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     s.path,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0).UTC(),
		})
	}
	return out
}

// ParsePrivateKey parses a PEM encoded RSA private key in PKCS#8 or PKCS#1 form.
func ParsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("signer: no PEM block found in private key")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signer: PKCS#8 key is %T, want RSA", key)
		}
		return rk, nil
	}
	rk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("signer: private key is neither valid PKCS#8 nor PKCS#1 RSA")
	}
	return rk, nil
}

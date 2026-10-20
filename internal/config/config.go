// Package config loads runtime configuration and secrets.
//
// On EC2 the signing key and login password come from AWS Secrets Manager and
// the distribution domain from SSM Parameter Store. For local development they can
// come from environment variables / files instead.
package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"example.com/cfcookie/internal/signer"
)

const (
	defaultTTL    = time.Hour
	defaultPrefix = "/protected/"
	// minPasswordLen guards against an accidentally empty or placeholder secret.
	minPasswordLen = 12
)

// Config is the fully resolved runtime configuration.
type Config struct {
	Signer   *signer.Signer
	Password []byte
	Prefix   string
}

// SecretsAPI is the subset of the Secrets Manager client in use.
type SecretsAPI interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// ParamsAPI is the subset of the SSM client in use.
type ParamsAPI interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, opts ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// Loader resolves a Config.
type Loader struct {
	Getenv   func(string) string
	Secrets  SecretsAPI // may be nil when everything comes from the environment
	Params   ParamsAPI  // may be nil when DOMAIN is set directly
	ReadFile func(string) ([]byte, error)
}

// NewLoader returns a Loader backed by the real process environment.
func NewLoader(secrets SecretsAPI, params ParamsAPI) Loader {
	return Loader{Getenv: os.Getenv, Secrets: secrets, Params: params, ReadFile: os.ReadFile}
}

// Load reads every setting. Environment variables:
//
//	KEY_ID                  CloudFront public key ID (required)
//	SIGNING_KEY_SECRET_ID   Secrets Manager secret holding the PEM private key, or
//	PRIVATE_KEY_FILE        path to a PEM private key (local development)
//	LOGIN_SECRET_ID         Secrets Manager secret holding the login password, or
//	LOGIN_PASSWORD          the password itself (local development)
//	DOMAIN                  CloudFront domain name, or
//	DOMAIN_PARAM            SSM parameter name holding it
//	COOKIE_TTL              cookie lifetime, Go duration (default 1h)
//	PROTECTED_PREFIX        protected path prefix (default /protected/)
func (l Loader) Load(ctx context.Context) (*Config, error) {
	keyID := l.Getenv("KEY_ID")
	if keyID == "" {
		return nil, errors.New("config: KEY_ID is not set")
	}

	ttl := defaultTTL
	if v := l.Getenv("COOKIE_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("config: COOKIE_TTL: %w", err)
		}
		ttl = d
	}
	prefix := defaultPrefix
	if v := l.Getenv("PROTECTED_PREFIX"); v != "" {
		prefix = v
	}

	domain, err := l.domain(ctx)
	if err != nil {
		return nil, err
	}
	keyPEM, err := l.signingKey(ctx)
	if err != nil {
		return nil, err
	}
	key, err := signer.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	pw, err := l.password(ctx)
	if err != nil {
		return nil, err
	}
	if len(pw) < minPasswordLen {
		return nil, fmt.Errorf("config: login password must be at least %d characters", minPasswordLen)
	}

	s, err := signer.New(signer.Options{KeyID: keyID, Key: key, Domain: domain, PathPrefix: prefix, TTL: ttl})
	if err != nil {
		return nil, err
	}
	return &Config{Signer: s, Password: pw, Prefix: prefix}, nil
}

func (l Loader) domain(ctx context.Context) (string, error) {
	if d := l.Getenv("DOMAIN"); d != "" {
		return d, nil
	}
	name := l.Getenv("DOMAIN_PARAM")
	if name == "" || l.Params == nil {
		return "", errors.New("config: set DOMAIN or DOMAIN_PARAM")
	}
	out, err := l.Params.GetParameter(ctx, &ssm.GetParameterInput{Name: &name})
	if err != nil {
		return "", fmt.Errorf("config: read SSM parameter %s: %w", name, err)
	}
	return strings.TrimSpace(*out.Parameter.Value), nil
}

func (l Loader) signingKey(ctx context.Context) ([]byte, error) {
	if id := l.Getenv("SIGNING_KEY_SECRET_ID"); id != "" {
		s, err := l.secret(ctx, id)
		return []byte(s), err
	}
	if path := l.Getenv("PRIVATE_KEY_FILE"); path != "" {
		b, err := l.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: read private key file: %w", err)
		}
		return b, nil
	}
	return nil, errors.New("config: set SIGNING_KEY_SECRET_ID or PRIVATE_KEY_FILE")
}

func (l Loader) password(ctx context.Context) ([]byte, error) {
	if id := l.Getenv("LOGIN_SECRET_ID"); id != "" {
		s, err := l.secret(ctx, id)
		return []byte(strings.TrimSpace(s)), err
	}
	if p := l.Getenv("LOGIN_PASSWORD"); p != "" {
		return []byte(p), nil
	}
	return nil, errors.New("config: set LOGIN_SECRET_ID or LOGIN_PASSWORD")
}

func (l Loader) secret(ctx context.Context, id string) (string, error) {
	if l.Secrets == nil {
		return "", errors.New("config: no Secrets Manager client")
	}
	out, err := l.Secrets.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &id})
	if err != nil {
		// Never include the secret value; the error only names the secret ID.
		return "", fmt.Errorf("config: read secret %s: %w", id, err)
	}
	if out.SecretString == nil {
		return "", fmt.Errorf("config: secret %s has no string value", id)
	}
	return *out.SecretString, nil
}

// Cache wraps a Loader and refreshes its result after ttl, so a rotated secret
// is picked up without a redeploy. A failed refresh keeps serving the last good value.
type Cache struct {
	Loader Loader
	TTL    time.Duration
	Now    func() time.Time

	mu     sync.Mutex
	cfg    *Config
	loaded time.Time
}

// Get returns the current configuration, reloading it if stale.
func (c *Cache) Get(ctx context.Context) (*Config, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	if c.cfg != nil && now().Sub(c.loaded) < c.TTL {
		return c.cfg, nil
	}
	cfg, err := c.Loader.Load(ctx)
	if err != nil {
		if c.cfg != nil {
			slog.Warn("config refresh failed, serving last good config", "error", err)
			return c.cfg, nil
		}
		return nil, err
	}
	c.cfg, c.loaded = cfg, now()
	return cfg, nil
}

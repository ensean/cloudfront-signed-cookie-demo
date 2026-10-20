package config

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func pemKey(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

type fakeSecrets struct {
	values map[string]string
	calls  int
	err    error
}

func (f *fakeSecrets) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.values[*in.SecretId]
	if !ok {
		return nil, errors.New("ResourceNotFoundException")
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(v)}, nil
}

type fakeParams map[string]string

func (f fakeParams) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	v, ok := f[*in.Name]
	if !ok {
		return nil, errors.New("ParameterNotFound")
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(v)}}, nil
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadFromAWS(t *testing.T) {
	sec := &fakeSecrets{values: map[string]string{"key-secret": pemKey(t), "pw-secret": "  a-long-password-123\n"}}
	l := Loader{
		Getenv: env(map[string]string{
			"KEY_ID": "KABC", "SIGNING_KEY_SECRET_ID": "key-secret", "LOGIN_SECRET_ID": "pw-secret",
			"DOMAIN_PARAM": "/cfcookie/domain", "COOKIE_TTL": "30m",
		}),
		Secrets: sec,
		Params:  fakeParams{"/cfcookie/domain": "d1.cloudfront.net\n"},
	}
	cfg, err := l.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg.Password) != "a-long-password-123" {
		t.Errorf("password not trimmed: %q", cfg.Password)
	}
	if cfg.Prefix != "/protected/" {
		t.Errorf("prefix = %q", cfg.Prefix)
	}
	if got := cfg.Signer.Resource(); got != "https://d1.cloudfront.net/protected/*" {
		t.Errorf("resource = %q", got)
	}
}

func TestLoadFromEnvAndFile(t *testing.T) {
	l := Loader{
		Getenv: env(map[string]string{
			"KEY_ID": "K", "PRIVATE_KEY_FILE": "/k.pem", "LOGIN_PASSWORD": "local-dev-password", "DOMAIN": "d2.cloudfront.net",
			"PROTECTED_PREFIX": "/private/",
		}),
		ReadFile: func(string) ([]byte, error) { return []byte(pemKey(t)), nil },
	}
	cfg, err := l.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Signer.Resource(); got != "https://d2.cloudfront.net/private/*" {
		t.Errorf("resource = %q", got)
	}
}

func TestLoadErrors(t *testing.T) {
	good := map[string]string{
		"KEY_ID": "K", "SIGNING_KEY_SECRET_ID": "key", "LOGIN_SECRET_ID": "pw", "DOMAIN": "d.cloudfront.net",
	}
	with := func(over map[string]string) func(string) string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		for k, v := range over {
			if v == "" {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return env(m)
	}
	okSecrets := func() *fakeSecrets {
		return &fakeSecrets{values: map[string]string{"key": pemKey(t), "pw": "long-enough-password"}}
	}

	tests := []struct {
		name    string
		loader  Loader
		wantErr string
	}{
		{"missing key id", Loader{Getenv: with(map[string]string{"KEY_ID": ""}), Secrets: okSecrets()}, "KEY_ID"},
		{"bad ttl", Loader{Getenv: with(map[string]string{"COOKIE_TTL": "soon"}), Secrets: okSecrets()}, "COOKIE_TTL"},
		{"no domain", Loader{Getenv: with(map[string]string{"DOMAIN": ""}), Secrets: okSecrets()}, "DOMAIN"},
		{"missing ssm param", Loader{Getenv: with(map[string]string{"DOMAIN": "", "DOMAIN_PARAM": "/x"}), Secrets: okSecrets(), Params: fakeParams{}}, "SSM"},
		{"secret fetch fails", Loader{Getenv: with(nil), Secrets: &fakeSecrets{err: errors.New("AccessDenied")}}, "read secret key"},
		{"placeholder key", Loader{Getenv: with(nil), Secrets: &fakeSecrets{values: map[string]string{"key": "PLACEHOLDER", "pw": "long-enough-password"}}}, "PEM"},
		{"short password", Loader{Getenv: with(nil), Secrets: &fakeSecrets{values: map[string]string{"key": pemKey(t), "pw": "short"}}}, "at least"},
		{"no secrets client", Loader{Getenv: with(nil)}, "Secrets Manager client"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.loader.Load(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestErrorsNeverContainSecretValues(t *testing.T) {
	const pw = "super-secret-but-too-short-for-nothing"
	l := Loader{
		Getenv:  env(map[string]string{"KEY_ID": "K", "SIGNING_KEY_SECRET_ID": "key", "LOGIN_SECRET_ID": "pw", "DOMAIN": "d.cloudfront.net"}),
		Secrets: &fakeSecrets{values: map[string]string{"key": "-----BEGIN PRIVATE KEY-----\nTOPSECRETBYTES\n-----END PRIVATE KEY-----", "pw": pw}},
	}
	_, err := l.Load(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "TOPSECRETBYTES") || strings.Contains(err.Error(), pw) {
		t.Errorf("error leaks secret material: %v", err)
	}
}

func TestCacheRefreshesAndKeepsLastGood(t *testing.T) {
	sec := &fakeSecrets{values: map[string]string{"key": pemKey(t), "pw": "long-enough-password"}}
	l := Loader{
		Getenv:  env(map[string]string{"KEY_ID": "K", "SIGNING_KEY_SECRET_ID": "key", "LOGIN_SECRET_ID": "pw", "DOMAIN": "d.cloudfront.net"}),
		Secrets: sec,
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &Cache{Loader: l, TTL: 5 * time.Minute, Now: func() time.Time { return now }}
	ctx := context.Background()

	first, err := c.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	callsAfterFirst := sec.calls

	now = now.Add(4 * time.Minute)
	if again, _ := c.Get(ctx); again != first || sec.calls != callsAfterFirst {
		t.Error("within TTL the cached config must be reused without calling AWS")
	}

	// After the TTL a rotated password is picked up.
	sec.values["pw"] = "rotated-password-456"
	now = now.Add(2 * time.Minute)
	second, err := c.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(second.Password) != "rotated-password-456" {
		t.Errorf("rotated password not picked up: %q", second.Password)
	}

	// If a later refresh fails, the last good config keeps serving.
	sec.err = errors.New("throttled")
	now = now.Add(10 * time.Minute)
	stale, err := c.Get(ctx)
	if err != nil || stale != second {
		t.Errorf("want last good config on refresh failure, got %v / %v", stale, err)
	}
}

func TestCacheFirstLoadFailureIsReported(t *testing.T) {
	c := &Cache{Loader: Loader{Getenv: env(nil)}, TTL: time.Minute}
	if _, err := c.Get(context.Background()); err == nil {
		t.Error("expected error when nothing has loaded yet")
	}
}

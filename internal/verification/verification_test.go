package verification

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/gi8lino/hookglass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHeader verifies exact-match checks and rejection of duplicate headers.
func TestHeader(t *testing.T) {
	t.Setenv("TEST_HEADER_KEY", "top-secret")
	verifier, err := newHeader(config.Header{Name: "x-api-key", ValueEnv: "TEST_HEADER_KEY"})
	require.NoError(t, err)

	tests := []struct {
		name   string
		values []string
		valid  bool
	}{
		{"valid", []string{"top-secret"}, true},
		{"wrong", []string{"wrong"}, false},
		{"empty", []string{""}, false},
		{"duplicate", []string{"top-secret", "top-secret"}, false},
		{"absent", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			for _, value := range tt.values {
				header.Add("X-API-Key", value)
			}
			assert.Equal(t, tt.valid, verifier.Valid(header, nil, time.Now()))
		})
	}
}

// TestBearer verifies case-insensitive schemes and strict credential handling.
func TestBearer(t *testing.T) {
	t.Setenv("TEST_BEARER_TOKEN", "my-token")
	verifier, err := newBearer(config.Bearer{TokenEnv: "TEST_BEARER_TOKEN"})
	require.NoError(t, err)

	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{"valid", "Bearer my-token", true},
		{"lowercase", "bearer my-token", true},
		{"wrong scheme", "Basic my-token", false},
		{"wrong token", "Bearer wrong", false},
		{"empty token", "Bearer ", false},
		{"extra token", "Bearer my-token extra", false},
		{"double space", "Bearer  my-token", false},
		{"no scheme", "my-token", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			header.Set("Authorization", tt.value)
			assert.Equal(t, tt.valid, verifier.Valid(header, nil, time.Now()))
		})
	}

	header := http.Header{}
	header.Add("Authorization", "Bearer my-token")
	header.Add("Authorization", "Bearer my-token")
	assert.False(t, verifier.Valid(header, nil, time.Now()), "duplicate Authorization headers accepted")
}

// TestBuild verifies enabled routes and fail-fast configuration errors.
func TestBuild(t *testing.T) {
	t.Setenv("TEST_HMAC_SECRET", "hmac-secret")
	t.Setenv("TEST_HEADER_KEY", "key-secret")
	t.Setenv("TEST_BEARER_TOKEN", "token-secret")

	settings := config.Default()
	settings.HMAC = config.HMAC{
		Enabled: true, SecretEnv: "TEST_HMAC_SECRET", Algorithm: "sha256",
		SignatureHeader: "X-Signature", SignaturePrefix: "sha256=", SignatureEncoding: "hex", MessageFormat: "{body}",
	}
	settings.Header = config.Header{Enabled: true, Name: "X-API-Key", ValueEnv: "TEST_HEADER_KEY"}
	settings.Bearer = config.Bearer{Enabled: true, TokenEnv: "TEST_BEARER_TOKEN"}

	routes, err := Build(settings)
	require.NoError(t, err)
	require.NotNil(t, routes.HMAC)
	require.NotNil(t, routes.Header)
	require.NotNil(t, routes.Bearer)

	body := []byte("hello")
	mac := hmac.New(sha256.New, []byte("hmac-secret"))
	_, err = mac.Write(body)
	require.NoError(t, err)
	header := http.Header{}
	header.Set("X-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	assert.True(t, routes.HMAC.Valid(header, body, time.Now()))

	settings.Bearer.TokenEnv = "MISSING_HOOKGLASS_TEST_SECRET"
	_, err = Build(settings)
	require.Error(t, err)
	assert.ErrorContains(t, err, "bearer:")

	settings.Bearer.Enabled = false
	routes, err = Build(settings)
	require.NoError(t, err)
	assert.Nil(t, routes.Bearer)
}

// TestInvalidConfigurations ensures insecure or malformed verification is rejected.
func TestInvalidConfigurations(t *testing.T) {
	t.Setenv("TEST_HEADER_KEY", "secret")
	t.Setenv("TEST_BEARER_TOKEN", "secret")

	for _, name := range []string{"", "Bad Header", "Bad:Header", "Bad\nHeader"} {
		t.Run("header name "+name, func(t *testing.T) {
			_, err := newHeader(config.Header{Name: name, ValueEnv: "TEST_HEADER_KEY"})
			require.Error(t, err)
		})
	}

	_, err := newHeader(config.Header{Name: "X-Key"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "value-env")

	_, err = newBearer(config.Bearer{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "token-env")

	t.Setenv("TEST_BEARER_TOKEN", "contains whitespace")
	_, err = newBearer(config.Bearer{TokenEnv: "TEST_BEARER_TOKEN"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "whitespace")

	_, err = newHMAC(config.HMAC{SecretEnv: "TEST_MISSING_KEY"})
	require.Error(t, err)
}

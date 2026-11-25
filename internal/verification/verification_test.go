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

// TestBuild verifies enabled routes and fail-fast configuration errors.
func TestBuild(t *testing.T) {
	t.Parallel()

	lookup := lookupValues(map[string]string{
		"TEST_HMAC_SECRET":  "hmac-secret",
		"TEST_HEADER_KEY":   "key-secret",
		"TEST_BEARER_TOKEN": "token-secret",
	})

	settings := config.Default()
	settings.HMAC = config.HMAC{
		Enabled:           true,
		SecretEnv:         "TEST_HMAC_SECRET",
		Algorithm:         "sha256",
		SignatureHeader:   "X-Signature",
		SignaturePrefix:   "sha256=",
		SignatureEncoding: "hex",
		MessageFormat:     "{body}",
	}
	settings.Header = config.Header{
		Enabled:  true,
		Name:     "X-API-Key",
		ValueEnv: "TEST_HEADER_KEY",
	}
	settings.Bearer = config.Bearer{
		Enabled:  true,
		TokenEnv: "TEST_BEARER_TOKEN",
	}

	t.Run("enabled", func(t *testing.T) {
		t.Parallel()

		routes, err := build(settings, lookup)
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
	})

	t.Run("missing_secret", func(t *testing.T) {
		t.Parallel()

		settings := settings
		settings.Bearer.TokenEnv = "MISSING_HOOKGLASS_TEST_SECRET"
		routes, err := build(settings, lookup)
		require.Error(t, err)
		assert.ErrorContains(t, err, "bearer:")
		assert.Equal(t, Routes{}, routes)
	})

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()

		settings := settings
		settings.Bearer.Enabled = false
		routes, err := build(settings, lookup)
		require.NoError(t, err)
		assert.Nil(t, routes.Bearer)
	})

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()

		routes, err := build(config.Default(), lookupValues(nil))
		require.NoError(t, err)
		assert.Equal(t, Routes{}, routes)
	})
}

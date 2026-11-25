package verification

import (
	"net/http"
	"testing"
	"time"

	"github.com/gi8lino/hookglass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHeader verifies exact header credentials.
func TestHeader(t *testing.T) {
	t.Parallel()

	verifier, err := newHeader(config.Header{
		Name:     "x-api-key",
		ValueEnv: "KEY",
	}, lookupValues(map[string]string{"KEY": "top-secret"}))
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"X-Api-Key": {"top-secret"}}
		assert.True(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("wrong", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"X-Api-Key": {"wrong"}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"X-Api-Key": {""}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("duplicate", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"X-Api-Key": {"top-secret", "top-secret"}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("absent", func(t *testing.T) {
		t.Parallel()

		header := http.Header{}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})
}

// TestNewHeader rejects invalid configuration.
func TestNewHeader(t *testing.T) {
	t.Parallel()

	t.Run("empty_name", func(t *testing.T) {
		t.Parallel()

		_, err := newHeader(config.Header{
			Name:     "",
			ValueEnv: "KEY",
		}, lookupValues(map[string]string{"KEY": "secret"}))
		require.ErrorContains(t, err, "name")
	})

	t.Run("space", func(t *testing.T) {
		t.Parallel()

		_, err := newHeader(config.Header{
			Name:     "Bad Header",
			ValueEnv: "KEY",
		}, lookupValues(map[string]string{"KEY": "secret"}))
		require.ErrorContains(t, err, "name")
	})

	t.Run("colon", func(t *testing.T) {
		t.Parallel()

		_, err := newHeader(config.Header{
			Name:     "Bad:Header",
			ValueEnv: "KEY",
		}, lookupValues(map[string]string{"KEY": "secret"}))
		require.ErrorContains(t, err, "name")
	})

	t.Run("newline", func(t *testing.T) {
		t.Parallel()

		_, err := newHeader(config.Header{
			Name:     "Bad\nHeader",
			ValueEnv: "KEY",
		}, lookupValues(map[string]string{"KEY": "secret"}))
		require.ErrorContains(t, err, "name")
	})

	t.Run("missing_env", func(t *testing.T) {
		t.Parallel()

		_, err := newHeader(config.Header{
			Name:     "X-Key",
			ValueEnv: "",
		}, lookupValues(map[string]string{"KEY": "secret"}))
		require.ErrorContains(t, err, "value-env")
	})

	t.Run("invalid_value", func(t *testing.T) {
		t.Parallel()

		_, err := newHeader(config.Header{
			Name:     "X-Key",
			ValueEnv: "KEY",
		}, lookupValues(map[string]string{"KEY": "bad\r\nvalue"}))
		require.ErrorContains(t, err, "header value")
	})

	t.Run("leading_space", func(t *testing.T) {
		t.Parallel()

		_, err := newHeader(config.Header{
			Name:     "X-Key",
			ValueEnv: "KEY",
		}, lookupValues(map[string]string{"KEY": " secret"}))
		require.ErrorContains(t, err, "whitespace")
	})

	t.Run("trailing_tab", func(t *testing.T) {
		t.Parallel()

		_, err := newHeader(config.Header{
			Name:     "X-Key",
			ValueEnv: "KEY",
		}, lookupValues(map[string]string{"KEY": "secret\t"}))
		require.ErrorContains(t, err, "whitespace")
	})
}

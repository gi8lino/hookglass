package verification

import (
	"net/http"
	"testing"
	"time"

	"github.com/gi8lino/hookglass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBearer checks bearer credentials.
func TestBearer(t *testing.T) {
	t.Parallel()

	verifier, err := newBearer(config.Bearer{TokenEnv: "TOKEN"}, lookupValues(map[string]string{"TOKEN": "my-token"}))
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"Authorization": {"Bearer my-token"}}
		assert.True(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("lowercase", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"Authorization": {"bearer my-token"}}
		assert.True(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("wrong_scheme", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"Authorization": {"Basic my-token"}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("wrong_token", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"Authorization": {"Bearer wrong"}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("empty_token", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"Authorization": {"Bearer "}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("extra_token", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"Authorization": {"Bearer my-token extra"}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("double_space", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"Authorization": {"Bearer  my-token"}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("no_scheme", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"Authorization": {"my-token"}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("unicode_whitespace", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"Authorization": {"Bearer my-token "}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("control", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"Authorization": {"Bearer my-token"}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("duplicate", func(t *testing.T) {
		t.Parallel()

		header := http.Header{"Authorization": {"Bearer my-token", "Bearer my-token"}}
		assert.False(t, verifier.Valid(header, nil, time.Time{}))
	})

	t.Run("absent", func(t *testing.T) {
		t.Parallel()

		assert.False(t, verifier.Valid(http.Header{}, nil, time.Time{}))
	})
}

// TestNewBearer rejects unusable tokens.
func TestNewBearer(t *testing.T) {
	t.Parallel()

	t.Run("missing_env", func(t *testing.T) {
		t.Parallel()

		_, err := newBearer(config.Bearer{}, lookupValues(nil))
		require.ErrorContains(t, err, "token-env")
	})

	t.Run("space", func(t *testing.T) {
		t.Parallel()

		_, err := newBearer(config.Bearer{TokenEnv: "TOKEN"}, lookupValues(map[string]string{"TOKEN": "contains whitespace"}))
		require.ErrorContains(t, err, "bearer token")
	})

	t.Run("unicode_whitespace", func(t *testing.T) {
		t.Parallel()

		_, err := newBearer(config.Bearer{TokenEnv: "TOKEN"}, lookupValues(map[string]string{"TOKEN": "a b"}))
		require.ErrorContains(t, err, "bearer token")
	})

	t.Run("control", func(t *testing.T) {
		t.Parallel()

		_, err := newBearer(config.Bearer{TokenEnv: "TOKEN"}, lookupValues(map[string]string{"TOKEN": "ab"}))
		require.ErrorContains(t, err, "bearer token")
	})
}

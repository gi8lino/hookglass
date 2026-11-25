package verification

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lookupValues returns a read-only test environment lookup.
func lookupValues(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

// TestRequiredEnv distinguishes missing and empty variables without changing credentials.
func TestRequiredEnv(t *testing.T) {
	t.Parallel()

	t.Run("missing_name", func(t *testing.T) {
		t.Parallel()

		value, err := requiredEnv("", "secret-env", lookupValues(nil))
		require.ErrorContains(t, err, "secret-env is required")
		assert.Empty(t, value)
	})

	t.Run("blank_name", func(t *testing.T) {
		t.Parallel()

		value, err := requiredEnv("  ", "secret-env", lookupValues(nil))
		require.ErrorContains(t, err, "secret-env is required")
		assert.Empty(t, value)
	})

	t.Run("unset", func(t *testing.T) {
		t.Parallel()

		value, err := requiredEnv("KEY", "secret-env", lookupValues(nil))
		require.ErrorContains(t, err, "is not set")
		assert.Empty(t, value)
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		value, err := requiredEnv("KEY", "secret-env", lookupValues(map[string]string{"KEY": ""}))
		require.ErrorContains(t, err, "is empty")
		assert.Empty(t, value)
	})

	t.Run("exact", func(t *testing.T) {
		t.Parallel()

		value, err := requiredEnv("KEY", "secret-env", lookupValues(map[string]string{"KEY": " secret "}))
		require.NoError(t, err)
		assert.Equal(t, " secret ", value)
	})
}

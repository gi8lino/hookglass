package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParse verifies CLI overrides, defaults, and positional argument rejection.
func TestParse(t *testing.T) {
	t.Parallel()

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()

		options, err := Parse(nil, "test")
		require.NoError(t, err)
		assert.Empty(t, options.ConfigFile)
		assert.Equal(t, "127.0.0.1:8080", options.ListenAddress)
	})

	t.Run("overrides", func(t *testing.T) {
		t.Parallel()

		options, err := Parse([]string{"--config=examples/snitch.yaml", "--listen-address=:9999"}, "test")
		require.NoError(t, err)
		assert.Equal(t, "examples/snitch.yaml", options.ConfigFile)
		assert.Equal(t, ":9999", options.ListenAddress)
	})

	t.Run("rejects positional args", func(t *testing.T) {
		t.Parallel()

		_, err := Parse([]string{"unexpected"}, "test")
		require.Error(t, err)
	})
}

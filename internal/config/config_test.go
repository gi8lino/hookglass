package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadDefaults checks that an empty path enables only the echo endpoint.
func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	settings, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, Default(), settings)
	assert.EqualValues(t, 64<<10, settings.MaxBodyBytes)
	assert.False(t, settings.HMAC.Enabled)
	assert.False(t, settings.Header.Enabled)
	assert.False(t, settings.Bearer.Enabled)
}

// TestLoadStrict validates the YAML configuration and disallows ambiguous documents.
func TestLoadStrict(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "hookglass.yaml")
		require.NoError(t, os.WriteFile(path, []byte("max-body-bytes: 128\nhmac:\n  enabled: true\nheader:\n"+
			"  enabled: true\n  name: X-Key\n  value-env: HEADER_SECRET\n"+
			"bearer:\n  enabled: true\n  token-env: BEARER_TOKEN\n"), 0o600))

		settings, err := Load(path)
		require.NoError(t, err)
		assert.EqualValues(t, 128, settings.MaxBodyBytes)
		assert.True(t, settings.HMAC.Enabled)
		assert.True(t, settings.Header.Enabled)
		assert.True(t, settings.Bearer.Enabled)
	})

	t.Run("unknown", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "hookglass.yaml")
		require.NoError(t, os.WriteFile(path, []byte("bad-field: yes\n"), 0o600))

		_, err := Load(path)
		require.Error(t, err)
	})

	t.Run("removed listen address", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "hookglass.yaml")
		require.NoError(t, os.WriteFile(path, []byte("listen-address: ':8080'\n"), 0o600))

		_, err := Load(path)
		require.Error(t, err)
	})

	t.Run("duplicate", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "hookglass.yaml")
		require.NoError(t, os.WriteFile(path, []byte("max-body-bytes: 64\nmax-body-bytes: 128\n"), 0o600))

		_, err := Load(path)
		require.Error(t, err)
	})

	t.Run("two documents", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "hookglass.yaml")
		require.NoError(t, os.WriteFile(path, []byte("max-body-bytes: 128\n---\nmax-body-bytes: 256\n"), 0o600))

		_, err := Load(path)
		require.Error(t, err)
	})

	t.Run("invalid body limit", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "hookglass.yaml")
		require.NoError(t, os.WriteFile(path, []byte("max-body-bytes: 0\n"), 0o600))

		_, err := Load(path)
		require.Error(t, err)
	})

	t.Run("negative body limit", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "hookglass.yaml")
		require.NoError(t, os.WriteFile(path, []byte("max-body-bytes: -1\n"), 0o600))

		_, err := Load(path)
		require.Error(t, err)
	})

	t.Run("malformed", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "hookglass.yaml")
		require.NoError(t, os.WriteFile(path, []byte("max-body-bytes: [\n"), 0o600))

		_, err := Load(path)
		require.Error(t, err)
	})
}

// TestLoadMissingFile reports a descriptive error when a config file cannot be opened.
func TestLoadMissingFile(t *testing.T) {
	t.Parallel()

	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "open configuration")
}

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

	tests := []struct {
		name    string
		content string
		valid   bool
	}{
		{
			name: "valid",
			content: "max-body-bytes: 128\nhmac:\n  enabled: true\nheader:\n" +
				"  enabled: true\n  name: X-Key\n  value-env: HEADER_SECRET\n" +
				"bearer:\n  enabled: true\n  token-env: BEARER_TOKEN\n",
			valid: true,
		},
		{name: "unknown", content: "bad-field: yes\n"},
		{name: "removed listen address", content: "listen-address: ':8080'\n"},
		{name: "duplicate", content: "max-body-bytes: 64\nmax-body-bytes: 128\n"},
		{name: "two documents", content: "max-body-bytes: 128\n---\nmax-body-bytes: 256\n"},
		{name: "invalid body limit", content: "max-body-bytes: 0\n"},
		{name: "negative body limit", content: "max-body-bytes: -1\n"},
		{name: "malformed", content: "max-body-bytes: [\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "hookglass.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))

			settings, err := Load(path)
			if !tt.valid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.EqualValues(t, 128, settings.MaxBodyBytes)
			assert.True(t, settings.HMAC.Enabled)
			assert.True(t, settings.Header.Enabled)
			assert.True(t, settings.Bearer.Enabled)
		})
	}
}

// TestLoadMissingFile reports a descriptive error when a config file cannot be opened.
func TestLoadMissingFile(t *testing.T) {
	t.Parallel()

	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "open configuration")
}

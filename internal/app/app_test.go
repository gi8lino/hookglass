package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRun checks startup failure diagnostics and command-line error reporting.
func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("configuration_failure", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "missing.yaml")
		var logs bytes.Buffer

		err := Run(context.Background(), "test", []string{"--config=" + path}, io.Discard, io.Discard)
		require.ErrorContains(t, err, "load configuration:")
		assert.ErrorIs(t, err, os.ErrNotExist)

		var entry map[string]any
		require.NoError(t, json.Unmarshal(logs.Bytes(), &entry))
		assert.Equal(t, "ERROR", entry["level"])
		assert.Equal(t, "failed to load configuration", entry["msg"])
		assert.Equal(t, "config_failed", entry["event"])
		assert.Equal(t, path, entry["config_file"])
		assert.Contains(t, entry["error"], "open configuration")
	})

	t.Run("verification_failure", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "hookglass.yaml")
		require.NoError(t, os.WriteFile(path, []byte("bearer:\n  enabled: true\n"), 0o600))

		var stdout, stderr bytes.Buffer
		err := Run(context.Background(), "test", []string{"--config=" + path}, &stdout, &stderr)
		require.ErrorContains(t, err, "initialize webhook verification: bearer: token-env is required")

		var entry map[string]any
		require.NoError(t, json.Unmarshal(stderr.Bytes(), &entry))
		assert.Equal(t, "ERROR", entry["level"])
		assert.Equal(t, "failed to initialize webhook verification", entry["msg"])
		assert.Equal(t, "verifiers_failed", entry["event"])
		assert.Equal(t, path, entry["config_file"])
		assert.Equal(t, "bearer: token-env is required", entry["error"])
	})

	t.Run("flag_failure", func(t *testing.T) {
		t.Parallel()

		var stdout, stderr bytes.Buffer

		err := Run(context.Background(), "test", []string{"unexpected"}, &stdout, &stderr)
		require.ErrorContains(t, err, "parse flags:")
		assert.Empty(t, stdout.String())
		assert.NotEmpty(t, stderr.String())
	})
}

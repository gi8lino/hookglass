package app

import (
	"bytes"
	"context"
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
		var stdout, stderr bytes.Buffer

		err := Run(context.Background(), "test", []string{"--config=" + path}, &stdout, &stderr)
		require.ErrorContains(t, err, "load configuration:")
		assert.ErrorIs(t, err, os.ErrNotExist)

		logs := stdout.String()
		assert.Contains(t, logs, "failed to load configuration")
		assert.Contains(t, logs, "event")
		assert.Contains(t, logs, "config_failed")
		assert.Contains(t, logs, "config_file")
		assert.Contains(t, logs, path)
		assert.Contains(t, logs, "error")
		assert.Contains(t, logs, "open configuration")
		assert.Empty(t, stderr.String())
	})

	t.Run("verification_failure", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "hookglass.yaml")
		require.NoError(t, os.WriteFile(path, []byte("bearer:\n  enabled: true\n"), 0o600))

		var stdout, stderr bytes.Buffer
		err := Run(context.Background(), "test", []string{"--config=" + path}, &stdout, &stderr)
		require.ErrorContains(t, err, "initialize webhook verification: bearer: token-env is required")

		logs := stdout.String()
		assert.Contains(t, logs, "failed to initialize webhook verification")
		assert.Contains(t, logs, "event")
		assert.Contains(t, logs, "verifiers_failed")
		assert.Contains(t, logs, "config_file")
		assert.Contains(t, logs, path)
		assert.Contains(t, logs, "error")
		assert.Contains(t, logs, "bearer: token-env is required")
		assert.Empty(t, stderr.String())
	})

	t.Run("flag_failure", func(t *testing.T) {
		t.Parallel()

		var stdout, stderr bytes.Buffer

		err := Run(context.Background(), "test", []string{"unexpected"}, &stdout, &stderr)
		require.ErrorContains(t, err, "expected at most 0 positional arguments, got 1")
		assert.Empty(t, stdout.String())
		assert.Equal(t, err.Error()+"\n", stderr.String())
	})
}

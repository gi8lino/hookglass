package verification

import (
	"testing"

	"github.com/gi8lino/hookglass/internal/config"
	"github.com/stretchr/testify/require"
)

// TestNewHMAC rejects missing secrets and invalid options.
func TestNewHMAC(t *testing.T) {
	t.Parallel()

	t.Run("missing_secret", func(t *testing.T) {
		t.Parallel()

		_, err := newHMAC(config.HMAC{SecretEnv: "KEY"}, lookupValues(nil))
		require.ErrorContains(t, err, "is not set")
	})

	t.Run("invalid_age", func(t *testing.T) {
		t.Parallel()

		_, err := newHMAC(config.HMAC{
			SecretEnv: "KEY",
			MaxAge:    "bad",
		}, lookupValues(map[string]string{"KEY": "secret"}))
		require.ErrorContains(t, err, "invalid max-age")
	})

	t.Run("invalid_header", func(t *testing.T) {
		t.Parallel()

		_, err := newHMAC(config.HMAC{
			SecretEnv:       "KEY",
			SignatureHeader: "Bad Header",
		}, lookupValues(map[string]string{"KEY": "secret"}))
		require.ErrorContains(t, err, "signature-header")
	})
}

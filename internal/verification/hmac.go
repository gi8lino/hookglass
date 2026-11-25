package verification

import (
	"fmt"
	"time"

	"github.com/gi8lino/hookglass/internal/config"
	"github.com/gi8lino/hookglass/internal/hmacverify"
)

// newHMAC compiles the HMAC scheme using a secret from the environment.
func newHMAC(settings config.HMAC, lookup func(string) (string, bool)) (Verifier, error) {
	secret, err := requiredEnv(settings.SecretEnv, "secret-env", lookup)
	if err != nil {
		return nil, err
	}

	var maxAge time.Duration
	if settings.MaxAge != "" {
		maxAge, err = time.ParseDuration(settings.MaxAge)
		if err != nil {
			return nil, fmt.Errorf("invalid max-age: %w", err)
		}
	}

	return hmacverify.New([]byte(secret), hmacverify.Options{
		Algorithm:         settings.Algorithm,
		SignatureHeader:   settings.SignatureHeader,
		SignaturePrefix:   settings.SignaturePrefix,
		SignatureEncoding: settings.SignatureEncoding,
		MessageFormat:     settings.MessageFormat,
		TimestampHeader:   settings.TimestampHeader,
		TimestampFormat:   settings.TimestampFormat,
		MaxAge:            maxAge,
	})
}

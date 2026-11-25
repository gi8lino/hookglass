package verification

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gi8lino/hookglass/internal/config"
	"golang.org/x/net/http/httpguts"
)

// headerVerifier matches one exact header value against a configured secret.
type headerVerifier struct {
	// name is the canonical HTTP field name.
	name string
	// expected is the SHA-256 digest of the configured credential.
	expected [sha256.Size]byte
}

// Valid checks that exactly one header has the configured value.
func (v headerVerifier) Valid(headers http.Header, _ []byte, _ time.Time) bool {
	values := headers.Values(v.name)
	if len(values) != 1 {
		return false
	}

	return matchesDigest(values[0], v.expected)
}

// newHeader validates a header name and loads its required value from the environment.
func newHeader(settings config.Header, lookup func(string) (string, bool)) (Verifier, error) {
	if !httpguts.ValidHeaderFieldName(settings.Name) {
		return nil, errors.New("name must be a valid HTTP header name")
	}

	value, err := requiredEnv(settings.ValueEnv, "value-env", lookup)
	if err != nil {
		return nil, err
	}

	if !httpguts.ValidHeaderFieldValue(value) {
		return nil, errors.New("header value must be a valid HTTP header value")
	}
	if strings.Trim(value, " \t") != value {
		return nil, errors.New("header value must not have leading or trailing HTTP whitespace")
	}

	return headerVerifier{
		name:     http.CanonicalHeaderKey(settings.Name),
		expected: sha256.Sum256([]byte(value)),
	}, nil
}

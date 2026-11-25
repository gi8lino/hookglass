package verification

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/gi8lino/hookglass/internal/config"
	"golang.org/x/net/http/httpguts"
)

// bearerVerifier verifies an Authorization header with the Bearer scheme.
type bearerVerifier struct {
	// expected is the SHA-256 digest of the configured token.
	expected [sha256.Size]byte
}

// Valid checks one bearer credential without exposing the token.
func (v bearerVerifier) Valid(headers http.Header, _ []byte, _ time.Time) bool {
	values := headers.Values("Authorization")
	if len(values) != 1 {
		return false
	}

	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || !validBearerToken(token) {
		return false
	}

	return matchesDigest(token, v.expected)
}

// newBearer loads the expected bearer token from the environment.
func newBearer(settings config.Bearer, lookup func(string) (string, bool)) (Verifier, error) {
	token, err := requiredEnv(settings.TokenEnv, "token-env", lookup)
	if err != nil {
		return nil, err
	}

	if !validBearerToken(token) {
		return nil, errors.New("bearer token must not contain whitespace or invalid HTTP header characters")
	}

	return bearerVerifier{
		expected: sha256.Sum256([]byte(token)),
	}, nil
}

// validBearerToken reports whether token is nonempty and safe in an HTTP header without whitespace.
func validBearerToken(token string) bool {
	return token != "" && httpguts.ValidHeaderFieldValue(token) && strings.IndexFunc(token, unicode.IsSpace) == -1
}

// Package verification builds configurable webhook authentication checks.
package verification

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gi8lino/hookglass/internal/config"
	"github.com/gi8lino/hookglass/internal/hmacverify"
)

// Verifier authenticates request headers and the original body bytes.
type Verifier interface {
	// Valid reports whether a request satisfies the configured verification scheme.
	Valid(http.Header, []byte, time.Time) bool
}

// Routes contains optional verification for each protected endpoint.
type Routes struct {
	// HMAC authenticates requests to POST /hmac.
	HMAC Verifier
	// Header authenticates requests to POST /header.
	Header Verifier
	// Bearer authenticates requests to POST /bearer.
	Bearer Verifier
}

// Build prepares all enabled verification schemes before starting the server.
func Build(settings config.Config) (routes Routes, err error) {
	if settings.HMAC.Enabled {
		routes.HMAC, err = newHMAC(settings.HMAC)
		if err != nil {
			return Routes{}, fmt.Errorf("hmac: %w", err)
		}
	}
	if settings.Header.Enabled {
		routes.Header, err = newHeader(settings.Header)
		if err != nil {
			return Routes{}, fmt.Errorf("header: %w", err)
		}
	}
	if settings.Bearer.Enabled {
		routes.Bearer, err = newBearer(settings.Bearer)
		if err != nil {
			return Routes{}, fmt.Errorf("bearer: %w", err)
		}
	}
	return routes, nil
}

// newHMAC compiles the HMAC scheme using a secret from the environment.
func newHMAC(settings config.HMAC) (Verifier, error) {
	if !validHeaderName(settings.SignatureHeader) || settings.TimestampHeader != "" && !validHeaderName(settings.TimestampHeader) {
		return nil, errors.New("signature-header and timestamp-header must be valid HTTP header names")
	}
	secret, err := secretFromEnv(settings.SecretEnv, "secret-env")
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

// headerVerifier matches one exact header value against a configured secret.
type headerVerifier struct {
	name     string
	expected [sha256.Size]byte
}

// Valid checks that exactly one header has the configured value.
func (v headerVerifier) Valid(headers http.Header, _ []byte, _ time.Time) bool {
	values := headers.Values(v.name)
	if len(values) != 1 {
		return false
	}
	provided := sha256.Sum256([]byte(values[0]))
	return subtle.ConstantTimeCompare(provided[:], v.expected[:]) == 1
}

// newHeader validates a header name and loads its required value from the environment.
func newHeader(settings config.Header) (Verifier, error) {
	if !validHeaderName(settings.Name) {
		return nil, errors.New("name must be a valid HTTP header name")
	}
	value, err := secretFromEnv(settings.ValueEnv, "value-env")
	if err != nil {
		return nil, err
	}
	return headerVerifier{name: http.CanonicalHeaderKey(settings.Name), expected: sha256.Sum256([]byte(value))}, nil
}

// bearerVerifier verifies an Authorization header with the Bearer scheme.
type bearerVerifier struct {
	expected [sha256.Size]byte
}

// Valid checks one bearer credential without exposing the token.
func (v bearerVerifier) Valid(headers http.Header, _ []byte, _ time.Time) bool {
	values := headers.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, " \t\r\n") {
		return false
	}
	provided := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(provided[:], v.expected[:]) == 1
}

// newBearer loads the expected bearer token from the environment.
func newBearer(settings config.Bearer) (Verifier, error) {
	token, err := secretFromEnv(settings.TokenEnv, "token-env")
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("bearer token must not contain whitespace")
	}
	return bearerVerifier{expected: sha256.Sum256([]byte(token))}, nil
}

// secretFromEnv reads a required, nonempty secret without logging its value.
func secretFromEnv(name, field string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("environment variable %q is empty or unset", name)
	}
	return value, nil
}

// validHeaderName accepts HTTP field-name tokens without whitespace or separators.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	return true
}

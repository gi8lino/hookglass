package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gi8lino/hookglass/internal/hmacverify"
	"github.com/gi8lino/hookglass/internal/verification"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEcho verifies that requests are logged and acknowledged without authentication.
func TestEcho(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	server := New("127.0.0.1:8080", 100, verification.Routes{}, logger)
	request := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(`{"ip":"203.0.113.10"}`))
	request.Header.Set("Authorization", "Bearer secret-token")
	request.Header.Set("X-Warden-Signature", "sensitive-signature")
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusNoContent, response.Code)
	for _, want := range []string{"webhook received", "path=/echo", "203.0.113.10", "verified=false"} {
		assert.Contains(t, output.String(), want)
	}
	for _, secret := range []string{"Bearer secret-token", "sensitive-signature"} {
		assert.NotContains(t, output.String(), secret)
	}
}

// TestHMAC verifies that only authenticated webhook bodies are logged.
func TestHMAC(t *testing.T) {
	t.Parallel()

	verifier, err := hmacverify.New([]byte("secret"), hmacverify.Options{
		Algorithm: "sha256", SignatureHeader: "X-Signature", SignaturePrefix: "sha256=", SignatureEncoding: "hex", MessageFormat: "{body}",
	})
	require.NoError(t, err)

	var output bytes.Buffer
	server := New("127.0.0.1:8080", 100, verification.Routes{HMAC: verifier}, slog.New(slog.NewTextHandler(&output, nil)))
	body := "hello"

	unsigned := httptest.NewRequest(http.MethodPost, "/hmac", strings.NewReader(body))
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, unsigned)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	assert.Empty(t, output.String())

	mac := hmac.New(sha256.New, []byte("secret"))
	_, err = mac.Write([]byte(body))
	require.NoError(t, err)

	signed := httptest.NewRequest(http.MethodPost, "/hmac", strings.NewReader(body))
	signed.Header.Set("X-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response = httptest.NewRecorder()
	server.Handler.ServeHTTP(response, signed)
	require.Equal(t, http.StatusNoContent, response.Code)
	assert.Contains(t, output.String(), "verified=true")
	assert.Contains(t, output.String(), "hello")
}

// TestDisabledHMAC verifies that the protected route is unavailable by default.
func TestDisabledHMAC(t *testing.T) {
	t.Parallel()

	server := New("127.0.0.1:8080", 64, verification.Routes{}, slog.Default())
	request := httptest.NewRequest(http.MethodPost, "/hmac", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusNotFound, response.Code)
}

// TestBodyLimit rejects oversized requests without emitting their contents.
func TestBodyLimit(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	server := New("127.0.0.1:8080", 4, verification.Routes{}, slog.New(slog.NewTextHandler(&output, nil)))
	request := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader("12345"))
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusRequestEntityTooLarge, response.Code)
	assert.Empty(t, output.String())
}

// TestHealth verifies that probes remain silent.
func TestHealth(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	server := New("127.0.0.1:8080", 100, verification.Routes{}, slog.New(slog.NewTextHandler(&output, nil)))
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusNoContent, response.Code)
	assert.Empty(t, output.String())
}

// TestOptionalRoutes verifies protected routes are registered only when enabled.
func TestOptionalRoutes(t *testing.T) {
	t.Parallel()

	server := New("127.0.0.1:8080", 100, verification.Routes{}, slog.Default())
	for _, route := range []string{"/hmac", "/header", "/bearer"} {
		t.Run(route, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodPost, route, nil)
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)
			assert.Equal(t, http.StatusNotFound, response.Code)
		})
	}
}

// TestHeaderAndBearer verifies invalid credentials are rejected without logging.
func TestHeaderAndBearer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		path       string
		verifiers  verification.Routes
		validName  string
		validValue string
	}{
		{name: "header", path: "/header", verifiers: verification.Routes{Header: testHeaderVerifier{name: "X-API-Key", value: "test-key"}}, validName: "X-API-Key", validValue: "test-key"},
		{name: "bearer", path: "/bearer", verifiers: verification.Routes{Bearer: testHeaderVerifier{name: "Authorization", value: "Bearer test-token"}}, validName: "Authorization", validValue: "Bearer test-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			server := New("127.0.0.1:8080", 100, tt.verifiers, slog.New(slog.NewTextHandler(&output, nil)))
			for _, attempt := range []struct {
				name  string
				value string
				want  int
			}{
				{"missing", "", http.StatusUnauthorized},
				{"wrong", "incorrect", http.StatusUnauthorized},
				{"correct", tt.validValue, http.StatusNoContent},
			} {
				t.Run(attempt.name, func(t *testing.T) {
					request := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader("hello"))
					if attempt.value != "" {
						request.Header.Set(tt.validName, attempt.value)
					}
					response := httptest.NewRecorder()
					server.Handler.ServeHTTP(response, request)
					assert.Equal(t, attempt.want, response.Code)
				})
			}
			assert.Equal(t, 1, strings.Count(output.String(), "webhook received"))
			assert.NotContains(t, output.String(), tt.validValue)
			assert.NotContains(t, output.String(), "incorrect")
		})
	}
}

// testHeaderVerifier tests route wiring independently of authentication implementations.
type testHeaderVerifier struct{ name, value string }

// Valid checks the expected test header.
func (v testHeaderVerifier) Valid(headers http.Header, _ []byte, _ time.Time) bool {
	return headers.Get(v.name) == v.value
}

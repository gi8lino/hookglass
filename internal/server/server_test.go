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
	assert.Contains(t, output.String(), "webhook received")
	assert.Contains(t, output.String(), "path=/echo")
	assert.Contains(t, output.String(), "203.0.113.10")
	assert.Contains(t, output.String(), "verified=false")
	assert.NotContains(t, output.String(), "Bearer secret-token")
	assert.NotContains(t, output.String(), "sensitive-signature")
}

// TestHMAC verifies that only authenticated webhook bodies are logged.
func TestHMAC(t *testing.T) {
	t.Parallel()

	verifier, err := hmacverify.New([]byte("secret"), hmacverify.Options{
		Algorithm:         "sha256",
		SignatureHeader:   "X-Signature",
		SignaturePrefix:   "sha256=",
		SignatureEncoding: "hex",
		MessageFormat:     "{body}",
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

	t.Run("/hmac", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/hmac", nil)
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, request)

		assert.Equal(t, http.StatusNotFound, response.Code)
	})

	t.Run("/header", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/header", nil)
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, request)

		assert.Equal(t, http.StatusNotFound, response.Code)
	})

	t.Run("/bearer", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/bearer", nil)
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, request)

		assert.Equal(t, http.StatusNotFound, response.Code)
	})
}

// TestHeaderAndBearer verifies invalid credentials are rejected without logging.
func TestHeaderAndBearer(t *testing.T) {
	t.Parallel()

	t.Run("header", func(t *testing.T) {
		t.Parallel()

		verifiers := verification.Routes{Header: testHeaderVerifier{
			name:  "X-API-Key",
			value: "test-key",
		}}

		t.Run("missing", func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			server := New("127.0.0.1:8080", 100, verifiers, slog.New(slog.NewTextHandler(&output, nil)))
			request := httptest.NewRequest(http.MethodPost, "/header", strings.NewReader("hello"))
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)

			assert.Equal(t, http.StatusUnauthorized, response.Code)
			assert.Empty(t, output.String())
		})

		t.Run("wrong", func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			server := New("127.0.0.1:8080", 100, verifiers, slog.New(slog.NewTextHandler(&output, nil)))
			request := httptest.NewRequest(http.MethodPost, "/header", strings.NewReader("hello"))
			request.Header.Set("X-API-Key", "incorrect")
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)

			assert.Equal(t, http.StatusUnauthorized, response.Code)
			assert.Empty(t, output.String())
		})

		t.Run("correct", func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			server := New("127.0.0.1:8080", 100, verifiers, slog.New(slog.NewTextHandler(&output, nil)))
			request := httptest.NewRequest(http.MethodPost, "/header", strings.NewReader("hello"))
			request.Header.Set("X-API-Key", "test-key")
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)

			assert.Equal(t, http.StatusNoContent, response.Code)
			assert.Equal(t, 1, strings.Count(output.String(), "webhook received"))
			assert.NotContains(t, output.String(), "test-key")
		})
	})

	t.Run("bearer", func(t *testing.T) {
		t.Parallel()

		verifiers := verification.Routes{Bearer: testHeaderVerifier{
			name:  "Authorization",
			value: "Bearer test-token",
		}}

		t.Run("missing", func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			server := New("127.0.0.1:8080", 100, verifiers, slog.New(slog.NewTextHandler(&output, nil)))
			request := httptest.NewRequest(http.MethodPost, "/bearer", strings.NewReader("hello"))
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)

			assert.Equal(t, http.StatusUnauthorized, response.Code)
			assert.Empty(t, output.String())
		})

		t.Run("wrong", func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			server := New("127.0.0.1:8080", 100, verifiers, slog.New(slog.NewTextHandler(&output, nil)))
			request := httptest.NewRequest(http.MethodPost, "/bearer", strings.NewReader("hello"))
			request.Header.Set("Authorization", "incorrect")
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)

			assert.Equal(t, http.StatusUnauthorized, response.Code)
			assert.Empty(t, output.String())
		})

		t.Run("correct", func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			server := New("127.0.0.1:8080", 100, verifiers, slog.New(slog.NewTextHandler(&output, nil)))
			request := httptest.NewRequest(http.MethodPost, "/bearer", strings.NewReader("hello"))
			request.Header.Set("Authorization", "Bearer test-token")
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)

			assert.Equal(t, http.StatusNoContent, response.Code)
			assert.Equal(t, 1, strings.Count(output.String(), "webhook received"))
			assert.NotContains(t, output.String(), "Bearer test-token")
		})
	})
}

// testHeaderVerifier tests route wiring independently of authentication implementations.
type testHeaderVerifier struct {
	// name is the expected request header.
	name string
	// value is the expected header value.
	value string
}

// Valid checks the expected test header.
func (v testHeaderVerifier) Valid(headers http.Header, _ []byte, _ time.Time) bool {
	return headers.Get(v.name) == v.value
}

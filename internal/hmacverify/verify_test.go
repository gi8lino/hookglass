package hmacverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValid verifies webhook signing conventions and raw-body integrity.
func TestValid(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	body := []byte(`{"text":"{timestamp}","data":"{body}"}`)

	t.Run("Snitch and Warden", func(t *testing.T) {
		t.Parallel()

		options := Options{
			Algorithm:         "sha256",
			SignatureHeader:   "X-Snitch-Signature",
			SignaturePrefix:   "v1=",
			SignatureEncoding: "hex",
			MessageFormat:     "{timestamp}.{body}",
			TimestampHeader:   "X-Snitch-Timestamp",
			TimestampFormat:   "unix",
			MaxAge:            5 * time.Minute,
		}
		assertValidSignature(t, options, append([]byte(timestamp+"."), body...), body, timestamp, now, sha256.New)
	})

	t.Run("GitHub", func(t *testing.T) {
		t.Parallel()

		options := Options{
			Algorithm:         "sha256",
			SignatureHeader:   "X-Hub-Signature-256",
			SignaturePrefix:   "sha256=",
			SignatureEncoding: "hex",
			MessageFormat:     "{body}",
		}
		assertValidSignature(t, options, body, body, "", now, sha256.New)
	})

	t.Run("Slack", func(t *testing.T) {
		t.Parallel()

		options := Options{
			Algorithm:         "sha256",
			SignatureHeader:   "X-Slack-Signature",
			SignaturePrefix:   "v0=",
			SignatureEncoding: "hex",
			MessageFormat:     "v0:{timestamp}:{body}",
			TimestampHeader:   "X-Slack-Request-Timestamp",
			TimestampFormat:   "unix",
			MaxAge:            5 * time.Minute,
		}
		assertValidSignature(t, options, append([]byte("v0:"+timestamp+":"), body...), body, timestamp, now, sha256.New)
	})

	t.Run("sha512 base64", func(t *testing.T) {
		t.Parallel()

		options := Options{
			Algorithm:         "sha512",
			SignatureHeader:   "X-Signature",
			SignaturePrefix:   "",
			SignatureEncoding: "base64",
			MessageFormat:     "{body}",
		}
		assertValidSignature(t, options, body, body, "", now, sha512.New)
	})
}

// assertValidSignature checks valid, modified and invalid signatures for one scheme.
func assertValidSignature(t *testing.T, options Options, message, body []byte, timestamp string, now time.Time, newHash func() hash.Hash) {
	t.Helper()

	verifier, err := New([]byte("secret"), options)
	require.NoError(t, err)

	mac := hmac.New(newHash, []byte("secret"))
	_, err = mac.Write(message)
	require.NoError(t, err)
	digest := hex.EncodeToString(mac.Sum(nil))
	if options.SignatureEncoding == "base64" {
		digest = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}

	headers := make(http.Header)
	headers.Set(options.SignatureHeader, options.SignaturePrefix+digest)
	if options.TimestampHeader != "" {
		headers.Set(options.TimestampHeader, timestamp)
	}
	assert.True(t, verifier.Valid(headers, body, now), "valid signature rejected")
	assert.False(t, verifier.Valid(headers, append(append([]byte(nil), body...), '!'), now), "modified body accepted")

	headers.Set(options.SignatureHeader, options.SignaturePrefix+"00")
	assert.False(t, verifier.Valid(headers, body, now), "invalid signature accepted")
}

// TestFreshTimestamp verifies timestamp encodings and replay boundaries.
func TestFreshTimestamp(t *testing.T) {
	t.Parallel()

	now := time.Unix(1700000000, 0).UTC()
	age := 5 * time.Minute

	t.Run("current unix", func(t *testing.T) {
		t.Parallel()

		assert.True(t, freshTimestamp(strconv.FormatInt(now.Unix(), 10), "unix", age, now))
	})

	t.Run("old boundary", func(t *testing.T) {
		t.Parallel()

		assert.True(t, freshTimestamp(strconv.FormatInt(now.Add(-age).Unix(), 10), "unix", age, now))
	})

	t.Run("future boundary", func(t *testing.T) {
		t.Parallel()

		assert.True(t, freshTimestamp(strconv.FormatInt(now.Add(age).Unix(), 10), "unix", age, now))
	})

	t.Run("expired", func(t *testing.T) {
		t.Parallel()

		assert.False(t, freshTimestamp(strconv.FormatInt(now.Add(-age-time.Second).Unix(), 10), "unix", age, now))
	})

	t.Run("too far in future", func(t *testing.T) {
		t.Parallel()

		assert.False(t, freshTimestamp(strconv.FormatInt(now.Add(age+time.Second).Unix(), 10), "unix", age, now))
	})

	t.Run("plus prefix", func(t *testing.T) {
		t.Parallel()

		assert.False(t, freshTimestamp("+1700000000", "unix", age, now))
	})

	t.Run("leading zero", func(t *testing.T) {
		t.Parallel()

		assert.False(t, freshTimestamp("01700000000", "unix", age, now))
	})

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()

		assert.False(t, freshTimestamp("not-a-time", "unix", age, now))
	})

	t.Run("unix milliseconds", func(t *testing.T) {
		t.Parallel()

		assert.True(t, freshTimestamp(strconv.FormatInt(now.UnixMilli(), 10), "unix-ms", age, now))
	})

	t.Run("rfc3339", func(t *testing.T) {
		t.Parallel()

		assert.True(t, freshTimestamp(now.Format(time.RFC3339Nano), "rfc3339", age, now))
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		assert.False(t, freshTimestamp("", "unix", age, now))
	})
}

// TestNewRejectsBadOptions ensures invalid schemes cannot be enabled silently.
func TestNewRejectsBadOptions(t *testing.T) {
	t.Parallel()

	valid := Options{
		Algorithm:         "sha256",
		SignatureHeader:   "X-Signature",
		SignatureEncoding: "hex",
		MessageFormat:     "{body}",
	}

	t.Run("unsupported algorithm", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.Algorithm = "sha1"

		_, err := New([]byte("secret"), settings)
		require.Error(t, err)
	})

	t.Run("unsupported encoding", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.SignatureEncoding = "raw"

		_, err := New([]byte("secret"), settings)
		require.Error(t, err)
	})

	t.Run("missing signature header", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.SignatureHeader = ""

		_, err := New([]byte("secret"), settings)
		require.Error(t, err)
	})

	t.Run("missing body", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.MessageFormat = "timestamp"

		_, err := New([]byte("secret"), settings)
		require.Error(t, err)
	})

	t.Run("repeated body", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.MessageFormat = "{body}{body}"

		_, err := New([]byte("secret"), settings)
		require.Error(t, err)
	})

	t.Run("unknown token", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.MessageFormat = "{unknown}{body}"

		_, err := New([]byte("secret"), settings)
		require.Error(t, err)
	})

	t.Run("open placeholder", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.MessageFormat = "{body}{"

		_, err := New([]byte("secret"), settings)
		require.Error(t, err)
	})

	t.Run("closing brace", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.MessageFormat = "{body}}"

		_, err := New([]byte("secret"), settings)
		require.Error(t, err)
	})

	t.Run("missing timestamp settings", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.MessageFormat = "{timestamp}.{body}"

		_, err := New([]byte("secret"), settings)
		require.Error(t, err)
	})

	t.Run("unexpected timestamp settings", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.MaxAge = time.Minute

		_, err := New([]byte("secret"), settings)
		require.Error(t, err)
	})

	t.Run("missing timestamp format", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.MessageFormat = "{timestamp}.{body}"
		settings.TimestampHeader = "X-Date"
		settings.MaxAge = time.Minute

		_, err := New([]byte("secret"), settings)
		require.Error(t, err)
	})

	t.Run("invalid_signature_header", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.SignatureHeader = "Bad Header"

		_, err := New([]byte("secret"), settings)
		require.ErrorContains(t, err, "signature-header")
	})

	t.Run("invalid_timestamp_header", func(t *testing.T) {
		t.Parallel()

		settings := valid
		settings.MessageFormat = "{timestamp}.{body}"
		settings.TimestampHeader = "Bad:Header"
		settings.TimestampFormat = "unix"
		settings.MaxAge = time.Minute

		_, err := New([]byte("secret"), settings)
		require.ErrorContains(t, err, "timestamp-header")
	})

	t.Run("missing_secret", func(t *testing.T) {
		t.Parallel()

		_, err := New(nil, valid)
		require.ErrorContains(t, err, "secret")
	})
}

// TestTimestampTampering ensures signatures cannot be replayed outside their window.
func TestTimestampTampering(t *testing.T) {
	t.Parallel()

	options := Options{
		Algorithm:         "sha256",
		SignatureHeader:   "X-Signature",
		SignatureEncoding: "hex",
		MessageFormat:     "{timestamp}.{body}",
		TimestampHeader:   "X-Timestamp",
		TimestampFormat:   "unix",
		MaxAge:            time.Minute,
	}
	verifier, err := New([]byte("secret"), options)
	require.NoError(t, err)

	now := time.Unix(1700000000, 0)
	body := []byte("test")
	mac := hmac.New(sha256.New, []byte("secret"))
	_, err = mac.Write(append([]byte(strconv.FormatInt(now.Unix(), 10)+"."), body...))
	require.NoError(t, err)

	headers := http.Header{}
	headers.Set("X-Signature", hex.EncodeToString(mac.Sum(nil)))
	headers.Set("X-Timestamp", strconv.FormatInt(now.Unix(), 10))
	assert.True(t, verifier.Valid(headers, body, now))

	headers.Set("X-Timestamp", strconv.FormatInt(now.Add(-2*time.Minute).Unix(), 10))
	assert.False(t, verifier.Valid(headers, body, now))
}

// TestDuplicateHeaders rejects ambiguous HMAC signature and timestamp headers.
func TestDuplicateHeaders(t *testing.T) {
	t.Parallel()

	verifier, err := New([]byte("secret"), Options{
		Algorithm:         "sha256",
		SignatureHeader:   "X-Signature",
		SignatureEncoding: "hex",
		MessageFormat:     "{timestamp}.{body}",
		TimestampHeader:   "X-Timestamp",
		TimestampFormat:   "unix", MaxAge: time.Minute,
	})
	require.NoError(t, err)

	now := time.Unix(1700000000, 0)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte("secret"))
	_, err = mac.Write([]byte(timestamp + ".hello"))
	require.NoError(t, err)
	signature := hex.EncodeToString(mac.Sum(nil))
	headers := http.Header{}
	headers.Set("X-Signature", signature)
	headers.Set("X-Timestamp", timestamp)
	assert.True(t, verifier.Valid(headers, []byte("hello"), now))

	headers.Add("X-Signature", signature)
	assert.False(t, verifier.Valid(headers, []byte("hello"), now), "duplicate signatures accepted")

	headers.Del("X-Signature")
	headers.Set("X-Signature", signature)
	headers.Add("X-Timestamp", timestamp)
	assert.False(t, verifier.Valid(headers, []byte("hello"), now), "duplicate timestamps accepted")
}

// TestNewCopiesSecret ensures the verifier owns its signing key.
func TestNewCopiesSecret(t *testing.T) {
	t.Parallel()

	secret := []byte("secret")
	verifier, err := New(secret, Options{
		Algorithm:         "sha256",
		SignatureHeader:   "X-Signature",
		SignatureEncoding: "hex",
		MessageFormat:     "{body}",
	})
	require.NoError(t, err)

	secret[0] = 'X'
	assert.Equal(t, []byte("secret"), verifier.secret)
}

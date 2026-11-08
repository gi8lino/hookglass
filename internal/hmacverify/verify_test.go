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

	tests := []struct {
		name          string
		options       Options
		message       []byte
		timestamp     string
		signatureName string
		newHash       func() hash.Hash
	}{
		{
			name: "Snitch and Warden",
			options: Options{
				Algorithm: "sha256", SignatureHeader: "X-Snitch-Signature", SignaturePrefix: "v1=",
				SignatureEncoding: "hex", MessageFormat: "{timestamp}.{body}",
				TimestampHeader: "X-Snitch-Timestamp", TimestampFormat: "unix", MaxAge: 5 * time.Minute,
			},
			message: append(append([]byte(timestamp), '.'), body...), timestamp: timestamp,
			signatureName: "X-Snitch-Signature", newHash: sha256.New,
		},
		{
			name: "GitHub",
			options: Options{
				Algorithm: "sha256", SignatureHeader: "X-Hub-Signature-256", SignaturePrefix: "sha256=",
				SignatureEncoding: "hex", MessageFormat: "{body}",
			},
			message: body, signatureName: "X-Hub-Signature-256", newHash: sha256.New,
		},
		{
			name: "Slack",
			options: Options{
				Algorithm: "sha256", SignatureHeader: "X-Slack-Signature", SignaturePrefix: "v0=",
				SignatureEncoding: "hex", MessageFormat: "v0:{timestamp}:{body}",
				TimestampHeader: "X-Slack-Request-Timestamp", TimestampFormat: "unix", MaxAge: 5 * time.Minute,
			},
			message: append(append([]byte("v0:"+timestamp), ':'), body...), timestamp: timestamp,
			signatureName: "X-Slack-Signature", newHash: sha256.New,
		},
		{
			name: "sha512 base64",
			options: Options{
				Algorithm: "sha512", SignatureHeader: "X-Signature", SignatureEncoding: "base64",
				MessageFormat: "{body}",
			},
			message: body, signatureName: "X-Signature", newHash: sha512.New,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			verifier, err := New([]byte("secret"), tt.options)
			require.NoError(t, err)
			mac := hmac.New(tt.newHash, []byte("secret"))
			_, err = mac.Write(tt.message)
			require.NoError(t, err)
			digest := hex.EncodeToString(mac.Sum(nil))
			if tt.options.SignatureEncoding == "base64" {
				digest = base64.StdEncoding.EncodeToString(mac.Sum(nil))
			}

			headers := make(http.Header)
			headers.Set(tt.signatureName, tt.options.SignaturePrefix+digest)
			if tt.options.TimestampHeader != "" {
				headers.Set(tt.options.TimestampHeader, tt.timestamp)
			}
			assert.True(t, verifier.Valid(headers, body, now), "valid signature rejected")
			assert.False(t, verifier.Valid(headers, append(append([]byte(nil), body...), '!'), now), "modified body accepted")

			headers.Set(tt.signatureName, tt.options.SignaturePrefix+"00")
			assert.False(t, verifier.Valid(headers, body, now), "invalid signature accepted")
		})
	}
}

// TestFreshTimestamp verifies timestamp encodings and replay boundaries.
func TestFreshTimestamp(t *testing.T) {
	t.Parallel()

	now := time.Unix(1700000000, 0).UTC()
	age := 5 * time.Minute
	tests := []struct {
		name   string
		value  string
		format string
		valid  bool
	}{
		{"current unix", strconv.FormatInt(now.Unix(), 10), "unix", true},
		{"old boundary", strconv.FormatInt(now.Add(-age).Unix(), 10), "unix", true},
		{"future boundary", strconv.FormatInt(now.Add(age).Unix(), 10), "unix", true},
		{"expired", strconv.FormatInt(now.Add(-age-time.Second).Unix(), 10), "unix", false},
		{"too far in future", strconv.FormatInt(now.Add(age+time.Second).Unix(), 10), "unix", false},
		{"plus prefix", "+1700000000", "unix", false},
		{"leading zero", "01700000000", "unix", false},
		{"invalid", "not-a-time", "unix", false},
		{"unix milliseconds", strconv.FormatInt(now.UnixMilli(), 10), "unix-ms", true},
		{"rfc3339", now.Format(time.RFC3339Nano), "rfc3339", true},
		{"empty", "", "unix", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.valid, freshTimestamp(tt.value, tt.format, age, now))
		})
	}
}

// TestNewRejectsBadOptions ensures invalid schemes cannot be enabled silently.
func TestNewRejectsBadOptions(t *testing.T) {
	t.Parallel()

	valid := Options{Algorithm: "sha256", SignatureHeader: "X-Signature", SignatureEncoding: "hex", MessageFormat: "{body}"}
	tests := []struct {
		name   string
		change func(*Options)
	}{
		{"unsupported algorithm", func(o *Options) { o.Algorithm = "sha1" }},
		{"unsupported encoding", func(o *Options) { o.SignatureEncoding = "raw" }},
		{"missing signature header", func(o *Options) { o.SignatureHeader = "" }},
		{"missing body", func(o *Options) { o.MessageFormat = "timestamp" }},
		{"repeated body", func(o *Options) { o.MessageFormat = "{body}{body}" }},
		{"unknown token", func(o *Options) { o.MessageFormat = "{unknown}{body}" }},
		{"open placeholder", func(o *Options) { o.MessageFormat = "{body}{" }},
		{"closing brace", func(o *Options) { o.MessageFormat = "{body}}" }},
		{"missing timestamp settings", func(o *Options) { o.MessageFormat = "{timestamp}.{body}" }},
		{"unexpected timestamp settings", func(o *Options) { o.MaxAge = time.Minute }},
		{"missing timestamp format", func(o *Options) {
			o.MessageFormat = "{timestamp}.{body}"
			o.TimestampHeader = "X-Date"
			o.MaxAge = time.Minute
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			settings := valid
			tt.change(&settings)
			_, err := New([]byte("secret"), settings)
			require.Error(t, err)
		})
	}

	_, err := New(nil, valid)
	require.Error(t, err)
	assert.ErrorContains(t, err, "secret")
}

// TestTimestampTampering ensures signatures cannot be replayed outside their window.
func TestTimestampTampering(t *testing.T) {
	t.Parallel()

	options := Options{Algorithm: "sha256", SignatureHeader: "X-Signature", SignatureEncoding: "hex", MessageFormat: "{timestamp}.{body}", TimestampHeader: "X-Timestamp", TimestampFormat: "unix", MaxAge: time.Minute}
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
		Algorithm: "sha256", SignatureHeader: "X-Signature", SignatureEncoding: "hex",
		MessageFormat: "{timestamp}.{body}", TimestampHeader: "X-Timestamp",
		TimestampFormat: "unix", MaxAge: time.Minute,
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

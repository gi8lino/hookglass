// Package hmacverify verifies configurable webhook HMAC signatures over raw bytes.
package hmacverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Options defines the signature scheme expected at the HMAC endpoint.
type Options struct {
	Algorithm         string
	SignatureHeader   string
	SignaturePrefix   string
	SignatureEncoding string
	MessageFormat     string
	TimestampHeader   string
	TimestampFormat   string
	MaxAge            time.Duration
}

type pieceKind uint8

const (
	literalPiece pieceKind = iota
	bodyPiece
	timestampPiece
)

type piece struct {
	kind  pieceKind
	value string
}

// Verifier holds a validated signature scheme and its secret.
type Verifier struct {
	secret            []byte
	newHash           func() hash.Hash
	signatureHeader   string
	signaturePrefix   string
	signatureEncoding string
	message           []piece
	timestampHeader   string
	timestampFormat   string
	maxAge            time.Duration
}

// New compiles a webhook signature scheme and rejects unsafe or ambiguous settings.
func New(secret []byte, options Options) (verifier *Verifier, err error) {
	if len(secret) == 0 {
		return nil, errors.New("HMAC secret must not be empty")
	}
	if options.SignatureHeader == "" {
		return nil, errors.New("signature-header is required")
	}

	var newHash func() hash.Hash
	switch options.Algorithm {
	case "sha256":
		newHash = sha256.New
	case "sha512":
		newHash = sha512.New
	default:
		return nil, fmt.Errorf("unsupported HMAC algorithm %q", options.Algorithm)
	}

	switch options.SignatureEncoding {
	case "hex", "base64":
	default:
		return nil, fmt.Errorf("unsupported signature encoding %q", options.SignatureEncoding)
	}

	parts, usesTimestamp, err := compileMessage(options.MessageFormat)
	if err != nil {
		return nil, err
	}
	if usesTimestamp {
		if options.TimestampHeader == "" || options.MaxAge <= 0 {
			return nil, errors.New("signed timestamp requires timestamp-header and positive max-age")
		}
		switch options.TimestampFormat {
		case "unix", "unix-ms", "rfc3339":
		default:
			return nil, fmt.Errorf("unsupported timestamp format %q", options.TimestampFormat)
		}
	} else if options.TimestampHeader != "" || options.TimestampFormat != "" || options.MaxAge != 0 {
		return nil, errors.New("timestamp settings require {timestamp} in message-format")
	}

	return &Verifier{
		secret:            append([]byte(nil), secret...),
		newHash:           newHash,
		signatureHeader:   options.SignatureHeader,
		signaturePrefix:   options.SignaturePrefix,
		signatureEncoding: options.SignatureEncoding,
		message:           parts,
		timestampHeader:   options.TimestampHeader,
		timestampFormat:   options.TimestampFormat,
		maxAge:            options.MaxAge,
	}, nil
}

// compileMessage parses literal segments and body/timestamp placeholders once at startup.
func compileMessage(format string) (parts []piece, usesTimestamp bool, err error) {
	bodyCount := 0
	for format != "" {
		start := strings.IndexByte(format, '{')
		if start == -1 {
			if strings.ContainsRune(format, '}') {
				return nil, false, errors.New("unmatched closing brace in message-format")
			}
			parts = append(parts, piece{kind: literalPiece, value: format})
			break
		}
		if strings.ContainsRune(format[:start], '}') {
			return nil, false, errors.New("unmatched closing brace in message-format")
		}
		if start > 0 {
			parts = append(parts, piece{kind: literalPiece, value: format[:start]})
		}
		end := strings.IndexByte(format[start:], '}')
		if end == -1 {
			return nil, false, errors.New("unclosed placeholder in message-format")
		}
		name := format[start+1 : start+end]
		switch name {
		case "body":
			bodyCount++
			parts = append(parts, piece{kind: bodyPiece})
		case "timestamp":
			usesTimestamp = true
			parts = append(parts, piece{kind: timestampPiece})
		default:
			return nil, false, fmt.Errorf("unsupported message placeholder %q", name)
		}
		format = format[start+end+1:]
	}
	if bodyCount != 1 {
		return nil, false, errors.New("message-format must contain {body} exactly once")
	}
	return parts, usesTimestamp, nil
}

// Valid checks timestamp freshness and authenticates the original request bytes.
func (v *Verifier) Valid(headers http.Header, body []byte, now time.Time) bool {
	signatures := headers.Values(v.signatureHeader)
	if len(signatures) != 1 {
		return false
	}
	signature := signatures[0]
	if !strings.HasPrefix(signature, v.signaturePrefix) {
		return false
	}
	signature = strings.TrimPrefix(signature, v.signaturePrefix)

	var provided []byte
	var err error
	switch v.signatureEncoding {
	case "hex":
		provided, err = hex.DecodeString(signature)
	case "base64":
		provided, err = base64.StdEncoding.DecodeString(signature)
	}
	if err != nil {
		return false
	}

	var timestamp string
	if v.timestampHeader != "" {
		timestamps := headers.Values(v.timestampHeader)
		if len(timestamps) != 1 {
			return false
		}
		timestamp = timestamps[0]
		if !freshTimestamp(timestamp, v.timestampFormat, v.maxAge, now) {
			return false
		}
	}

	mac := hmac.New(v.newHash, v.secret)
	for _, part := range v.message {
		switch part.kind {
		case literalPiece:
			_, _ = mac.Write([]byte(part.value))
		case bodyPiece:
			_, _ = mac.Write(body)
		case timestampPiece:
			_, _ = mac.Write([]byte(timestamp))
		}
	}
	return hmac.Equal(provided, mac.Sum(nil))
}

// freshTimestamp accepts a canonical timestamp within the permitted replay window.
func freshTimestamp(value, format string, maxAge time.Duration, now time.Time) bool {
	var timestamp time.Time
	switch format {
	case "unix", "unix-ms":
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil || strconv.FormatInt(seconds, 10) != value {
			return false
		}
		if format == "unix" {
			timestamp = time.Unix(seconds, 0)
		} else {
			timestamp = time.UnixMilli(seconds)
		}
	case "rfc3339":
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return false
		}
		timestamp = parsed
	default:
		return false
	}
	return !timestamp.Before(now.Add(-maxAge)) && !timestamp.After(now.Add(maxAge))
}

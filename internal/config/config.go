// Package config loads Hookglass server and verification settings from YAML.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v4"
)

const defaultMaxBodyBytes = 64 << 10

// Config configures the HTTP listener and optional verification endpoints.
type Config struct {
	// MaxBodyBytes limits requests accepted by webhook routes.
	MaxBodyBytes int64 `yaml:"max-body-bytes"`
	// HMAC controls the optional signed webhook endpoint.
	HMAC HMAC `yaml:"hmac"`
	// Header controls the optional static-header verification endpoint.
	Header Header `yaml:"header"`
	// Bearer controls the optional bearer-token verification endpoint.
	Bearer Bearer `yaml:"bearer"`
}

// HMAC describes a provider's signature headers and signed-message construction.
type HMAC struct {
	// Enabled registers POST /hmac when true.
	Enabled bool `yaml:"enabled"`
	// SecretEnv names the environment variable holding the signing secret.
	SecretEnv string `yaml:"secret-env"`
	// Algorithm selects the HMAC digest implementation.
	Algorithm string `yaml:"algorithm"`
	// SignatureHeader carries the remote signature.
	SignatureHeader string `yaml:"signature-header"`
	// SignaturePrefix is stripped before decoding the signature.
	SignaturePrefix string `yaml:"signature-prefix"`
	// SignatureEncoding determines how the digest is represented.
	SignatureEncoding string `yaml:"signature-encoding"`
	// MessageFormat combines literal text with raw body and timestamp placeholders.
	MessageFormat string `yaml:"message-format"`
	// TimestampHeader carries the signed timestamp, when configured.
	TimestampHeader string `yaml:"timestamp-header"`
	// TimestampFormat identifies the timestamp's wire representation.
	TimestampFormat string `yaml:"timestamp-format"`
	// MaxAge limits the accepted timestamp deviation.
	MaxAge string `yaml:"max-age"`
}

// Header configures an exact-value HTTP header check.
type Header struct {
	// Enabled registers POST /header when true.
	Enabled bool `yaml:"enabled"`
	// Name identifies the header to verify.
	Name string `yaml:"name"`
	// ValueEnv names the environment variable containing the expected value.
	ValueEnv string `yaml:"value-env"`
}

// Bearer configures Authorization: Bearer token verification.
type Bearer struct {
	// Enabled registers POST /bearer when true.
	Enabled bool `yaml:"enabled"`
	// TokenEnv names the environment variable containing the expected token.
	TokenEnv string `yaml:"token-env"`
}

// Default returns settings that expose only a loopback echo endpoint.
func Default() Config {
	return Config{
		MaxBodyBytes: defaultMaxBodyBytes,
	}
}

// Load reads a single strict YAML document or returns defaults when no path is given.
func Load(path string) (settings Config, err error) {
	settings = Default()
	if path == "" {
		return settings, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return settings, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close() //nolint:errcheck

	loader, err := yaml.NewLoader(file, yaml.WithKnownFields(), yaml.WithUniqueKeys())
	if err != nil {
		return settings, fmt.Errorf("initialize YAML loader: %w", err)
	}
	if err := loader.Load(&settings); err != nil {
		return settings, fmt.Errorf("parse configuration: %w", err)
	}

	var extra any
	if err := loader.Load(&extra); err != io.EOF {
		if err == nil {
			return settings, errors.New("configuration must contain one YAML document")
		}
		return settings, fmt.Errorf("parse configuration: %w", err)
	}

	if settings.MaxBodyBytes <= 0 {
		return settings, errors.New("max-body-bytes must be positive")
	}
	return settings, nil
}

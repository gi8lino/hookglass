// Package verification builds configurable webhook authentication checks.
package verification

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gi8lino/hookglass/internal/config"
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
func Build(settings config.Config) (Routes, error) {
	return build(settings, os.LookupEnv)
}

// build prepares enabled verifiers using the supplied environment lookup.
func build(settings config.Config, lookup func(string) (string, bool)) (routes Routes, err error) {
	if settings.HMAC.Enabled {
		routes.HMAC, err = newHMAC(settings.HMAC, lookup)
		if err != nil {
			return Routes{}, fmt.Errorf("hmac: %w", err)
		}
	}

	if settings.Header.Enabled {
		routes.Header, err = newHeader(settings.Header, lookup)
		if err != nil {
			return Routes{}, fmt.Errorf("header: %w", err)
		}
	}

	if settings.Bearer.Enabled {
		routes.Bearer, err = newBearer(settings.Bearer, lookup)
		if err != nil {
			return Routes{}, fmt.Errorf("bearer: %w", err)
		}
	}

	return routes, nil
}

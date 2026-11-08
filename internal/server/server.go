// Package server serves webhook echo and optional authenticated endpoints.
package server

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gi8lino/hookglass/internal/verification"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 30 * time.Second
)

// New creates an HTTP server with echo, health and enabled verification routes.
func New(address string, maxBodyBytes int64, verifiers verification.Routes, logger *slog.Logger) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /echo", receive(maxBodyBytes, nil, logger))
	if verifiers.HMAC != nil {
		mux.HandleFunc("POST /hmac", receive(maxBodyBytes, verifiers.HMAC, logger))
	}
	if verifiers.Header != nil {
		mux.HandleFunc("POST /header", receive(maxBodyBytes, verifiers.Header, logger))
	}
	if verifiers.Bearer != nil {
		mux.HandleFunc("POST /bearer", receive(maxBodyBytes, verifiers.Bearer, logger))
	}

	return &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

// receive logs accepted requests without exposing authentication headers.
func receive(maxBodyBytes int64, verifier verification.Verifier, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "invalid request body", http.StatusBadRequest)
			}
			return
		}

		if verifier != nil && !verifier.Valid(r.Header, body, time.Now()) {
			http.Error(w, "verification failed", http.StatusUnauthorized)
			return
		}

		logger.InfoContext(
			r.Context(),
			"webhook received",
			"event", "webhook_received",
			"method", r.Method,
			"path", r.URL.Path,
			"content_type", r.Header.Get("Content-Type"),
			"verified", verifier != nil,
			"body", string(body),
		)

		w.WriteHeader(http.StatusNoContent)
	}
}

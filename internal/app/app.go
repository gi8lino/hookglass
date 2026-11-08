// Package app configures and runs the Hookglass webhook receiver.
package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/containeroo/httpkit/grace"
	"github.com/containeroo/tinyflags"
	"github.com/gi8lino/hookglass/internal/config"
	"github.com/gi8lino/hookglass/internal/flags"
	"github.com/gi8lino/hookglass/internal/server"
	"github.com/gi8lino/hookglass/internal/verification"
)

// Run starts Hookglass and handles command-line errors and operating-system signals.
func Run(ctx context.Context, version string, args []string, stdout, stderr io.Writer) error {
	flags, err := flags.Parse(args, version)
	if err != nil {
		if tinyflags.IsHelpRequested(err) || tinyflags.IsVersionRequested(err) {
			fmt.Fprint(stdout, err.Error()) // nolint:errcheck
			return nil
		}
		fmt.Fprintln(stderr, err) // nolint:errcheck

		return err
	}

	ctx, stop := grace.SignalContext(ctx)
	defer stop()

	cfg, err := config.Load(flags.ConfigFile)
	if err != nil {
		return err
	}

	verifiers, err := verification.Build(cfg)
	if err != nil {
		return err
	}

	logger := slog.Default()
	logger.Info("starting webhook receiver",
		"address", flags.ListenAddress,
		"hmac_enabled", verifiers.HMAC != nil,
		"header_enabled", verifiers.Header != nil,
		"bearer_enabled", verifiers.Bearer != nil,
		"version", version,
	)

	handler := server.New(flags.ListenAddress, cfg.MaxBodyBytes, verifiers, logger)
	if err := grace.RunServer(ctx, handler, logger); err != nil {
		logger.Error("application failed",
			"event", "app_failed",
			"error", err,
		)
		return fmt.Errorf("run server: %w", err)
	}

	return nil
}

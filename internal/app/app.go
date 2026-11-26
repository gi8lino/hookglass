// Package app configures and runs the Hookglass webhook receiver.
package app

import (
	"context"
	"fmt"
	"io"

	appkitlogging "github.com/containeroo/appkit/logging"

	"github.com/containeroo/httpkit/grace"
	"github.com/containeroo/tinyflags"
	"github.com/gi8lino/hookglass/internal/cli"
	"github.com/gi8lino/hookglass/internal/config"
	"github.com/gi8lino/hookglass/internal/server"
	"github.com/gi8lino/hookglass/internal/verification"
)

// Run starts Hookglass and handles command-line errors and operating-system signals.
func Run(ctx context.Context, version string, args []string, stdout, stderr io.Writer) error {
	flags, err := cli.Parse(args, version)
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

	// Configure process logging and record the effective application identity.
	logger := appkitlogging.Setup(flags.Logging.Format, flags.Logging.Debug, stdout)

	cfg, err := config.Load(flags.ConfigFile)
	if err != nil {
		logger.ErrorContext(ctx, "failed to load configuration",
			"event", "config_failed",
			"config_file", flags.ConfigFile,
			"error", err,
		)

		return fmt.Errorf("load configuration: %w", err)
	}

	verifiers, err := verification.Build(cfg)
	if err != nil {
		logger.ErrorContext(ctx, "failed to initialize webhook verification",
			"event", "verifiers_failed",
			"config_file", flags.ConfigFile,
			"error", err,
		)

		return fmt.Errorf("initialize webhook verification: %w", err)
	}

	logger.Info("starting webhook receiver",
		"address", flags.ListenAddress,
		"hmac_enabled", verifiers.HMAC != nil,
		"header_enabled", verifiers.Header != nil,
		"bearer_enabled", verifiers.Bearer != nil,
		"version", version,
	)
	handler := server.New(flags.ListenAddress, cfg.MaxBodyBytes, verifiers, logger)
	if err := grace.RunServer(ctx, handler, logger); err != nil {
		logger.ErrorContext(ctx, "HTTP server failed",
			"event", "app_failed",
			"address", flags.ListenAddress,
			"error", err,
		)
		return fmt.Errorf("run server: %w", err)
	}

	return nil
}

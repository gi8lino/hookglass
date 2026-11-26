// Package flags parses Hookglass command-line and environment overrides.
package flags

import (
	appkitconfig "github.com/containeroo/appkit/config"
	"github.com/containeroo/tinyflags"
)

// Options holds command-line overrides for the application configuration.
type Options struct {
	// ConfigFile identifies the optional YAML configuration file.
	ConfigFile string
	// ListenAddress specifies the application HTTP listen address.
	ListenAddress string
	// Logging contains diagnostic and access logging settings.
	Logging appkitconfig.Logging
}

// Parse reads Hookglass flags and returns the selected configuration overrides.
func Parse(args []string, version string) (options Options, err error) {
	tf := tinyflags.NewFlagSet("hookglass", tinyflags.ContinueOnError)
	tf.Version(version)
	tf.EnvPrefix("HOOKGLASS_")
	tf.MaxPositional(0)

	configFile := tf.String("config", "", "YAML configuration file").
		Value()
	listenAddress := tf.String("listen-address", "127.0.0.1:8080", "Application listen address").
		Value()

	finalizeLogging := appkitconfig.RegisterLogging(tf, &options.Logging)

	if err := tf.Parse(args); err != nil {
		return options, err
	}

	options.ConfigFile = *configFile
	options.ListenAddress = *listenAddress

	finalizeLogging()

	return options, nil
}

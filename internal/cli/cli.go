// Package flags parses Hookglass command-line and environment overrides.
package cli

import (
	appkitconfig "github.com/containeroo/appkit/config"
	"github.com/containeroo/tinyflags"
)

// Flags holds command-line overrides for the application configuration.
type Flags struct {
	// ConfigFile identifies the optional YAML configuration file.
	ConfigFile string
	// ListenAddress specifies the application HTTP listen address.
	ListenAddress string
	// Logging contains diagnostic and access logging settings.
	Logging appkitconfig.Logging
}

// Parse reads Hookglass flags and returns the selected configuration overrides.
func Parse(argv []string, version string) (flags Flags, err error) {
	tf := tinyflags.NewFlagSet("hookglass", tinyflags.ContinueOnError)
	tf.Version(version)
	tf.EnvPrefix("HOOKGLASS_")
	tf.MaxPositional(0)

	configFile := tf.String("config", "", "YAML configuration file").
		Value()
	listenAddress := tf.String("listen-address", "127.0.0.1:8080", "Application listen address").
		Value()

	finalizeLogging := appkitconfig.RegisterLogging(tf, &flags.Logging)

	if err := tf.Parse(argv); err != nil {
		return flags, err
	}

	flags.ConfigFile = *configFile
	flags.ListenAddress = *listenAddress

	finalizeLogging()

	return flags, nil
}

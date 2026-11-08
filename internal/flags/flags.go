// Package flags parses Hookglass command-line and environment overrides.
package flags

import (
	"github.com/containeroo/tinyflags"
)

// Options holds command-line overrides for the application configuration.
type Options struct {
	// ConfigFile identifies the optional YAML configuration file.
	ConfigFile string
	// ListenAddress overrides the YAML listener address when set.
	ListenAddress string
}

// Parse reads Hookglass flags and returns the selected configuration overrides.
func Parse(args []string, version string) (options Options, err error) {
	fs := tinyflags.NewFlagSet("hookglass", tinyflags.ContinueOnError)
	fs.Version(version)
	fs.EnvPrefix("HOOKGLASS_")
	fs.MaxPositional(0)

	configFile := fs.String("config", "", "YAML configuration file").
		Value()
	listenAddress := fs.String("listen-address", "127.0.0.1:8080", "Application listen address").
		Value()

	if err := fs.Parse(args); err != nil {
		return options, err
	}

	return Options{ConfigFile: *configFile, ListenAddress: *listenAddress}, nil
}

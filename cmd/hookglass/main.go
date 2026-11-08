// Command hookglass receives and verifies webhooks for development and testing.
package main

import (
	"context"
	"os"

	"github.com/gi8lino/hookglass/internal/app"
)

// Version is set by the release build.
var Version = "dev"

// main starts the Hookglass application.
func main() {
	ctx := context.Background()
	if err := app.Run(ctx, Version, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		os.Exit(1)
	}
}

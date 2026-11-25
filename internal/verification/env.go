package verification

import (
	"fmt"
	"strings"
)

// requiredEnv returns the nonempty value of a required environment variable without exposing it.
func requiredEnv(name, field string, lookup func(string) (string, bool)) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%s is required", field)
	}

	value, ok := lookup(name)
	if !ok {
		return "", fmt.Errorf("environment variable %q is not set", name)
	}
	if value == "" {
		return "", fmt.Errorf("environment variable %q is empty", name)
	}

	return value, nil
}

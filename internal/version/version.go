// Package version holds build information set at link time:
//
//	go build -ldflags "-X nodetrust/internal/version.Version=v0.1.0 -X nodetrust/internal/version.Commit=abc123"
package version

import "fmt"

var (
	// Version is the release version, or "dev" for local builds.
	Version = "dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
)

// String returns a one-line description such as "nodetrust-agent dev (unknown)".
func String(component string) string {
	return fmt.Sprintf("nodetrust-%s %s (%s)", component, Version, Commit)
}

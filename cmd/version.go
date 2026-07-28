package cmd

// Build metadata injected at release time via -ldflags (see .goreleaser.yaml).
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// versionString renders the build metadata for the root command's --version flag.
func versionString() string {
	return Version + " (commit " + Commit + ", built " + Date + ")"
}

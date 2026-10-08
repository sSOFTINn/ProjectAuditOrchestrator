// Package buildinfo holds identity injected by the release builder.
package buildinfo

// Development builds must never impersonate a versioned release.
var (
	Version       = "dev"
	Revision      = "unknown"
	SourceState   = "unknown"
	SandboxSHA256 = ""
)

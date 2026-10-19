// Package buildinfo holds the build's version, commit and date, set at build
// time by the Makefile's -ldflags. `raven version`, the daemon's startup log
// and the API's reported version (raven status) all read it, so they agree.
package buildinfo

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

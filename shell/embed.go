//go:build shell

// Package shell embeds the built Module Federation host (npm run build) when
// compiled with -tags shell; without the tag the gateway serves no shell.
package shell

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist is the built shell rooted at dist/.
func Dist() (fs.FS, bool) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return sub, true
}

//go:build ui

package main

import (
	"embed"
	"io/fs"
)

//go:embed all:ui/dist
var uiDist embed.FS

// remoteDist is the built remote (cd ui && npm run build), compiled in with -tags ui.
func remoteDist() (fs.FS, bool) {
	sub, err := fs.Sub(uiDist, "ui/dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "mf-manifest.json"); err != nil {
		return nil, false
	}
	return sub, true
}

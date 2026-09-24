//go:build !ui

package main

import "io/fs"

// remoteDist reports no remote when built without -tags ui.
func remoteDist() (fs.FS, bool) { return nil, false }

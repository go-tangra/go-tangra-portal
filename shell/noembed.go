//go:build !shell

package shell

import "io/fs"

// Dist reports no shell when the binary was built without -tags shell.
func Dist() (fs.FS, bool) { return nil, false }

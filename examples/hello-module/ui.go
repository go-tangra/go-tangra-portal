package main

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// remoteHandler serves the federated remote (ui/dist) under /ui/ for the
// gateway's /m/hello/ relay: manifest never cached, hashed assets immutable.
func remoteHandler(dist fs.FS) http.Handler {
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		st, err := fs.Stat(dist, p)
		if p == "" || err != nil || st.IsDir() || p == "index.html" {
			http.NotFound(w, r)
			return
		}
		switch {
		case strings.HasSuffix(p, "mf-manifest.json"):
			w.Header().Set("Cache-Control", "no-store")
		case strings.HasPrefix(p, "assets/"):
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		default:
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

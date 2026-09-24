package httpapi

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

// noncePlaceholder in index.html is replaced with the per-request CSP nonce.
const noncePlaceholder = "__CSP_NONCE__"

// ServeShell serves the built shell: hashed assets immutable, index.html
// no-store with the CSP nonce injected and a CSRF cookie for fresh browsers;
// unknown paths fall back to index.html (client-side routing).
func (s *Server) ServeShell(w http.ResponseWriter, r *http.Request) {
	if s.shell == nil {
		WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	clean := path.Clean("/" + r.URL.Path)
	if strings.HasPrefix(clean, "//") || strings.Contains(clean, "\\") {
		WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
		return
	}
	if clean != r.URL.Path && clean+"/" != r.URL.Path {
		// Same-origin, path-only target (cleaned above; never a scheme or host).
		http.Redirect(w, r, clean, http.StatusTemporaryRedirect) // #nosec G710 -- path.Clean output, no host component
		return
	}
	p := strings.TrimPrefix(clean, "/")
	if p != "" && p != "index.html" {
		if st, err := fs.Stat(s.shell, p); err == nil && !st.IsDir() {
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			http.FileServer(http.FS(s.shell)).ServeHTTP(w, r)
			return
		}
	}
	index, err := fs.ReadFile(s.shell, "index.html")
	if err != nil {
		WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
		return
	}
	if _, err := r.Cookie(edge.CSRFCookie); err != nil {
		edge.IssueCSRFCookie(w)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(bytes.ReplaceAll(index, []byte(noncePlaceholder), []byte(edge.Nonce(r.Context()))))
}

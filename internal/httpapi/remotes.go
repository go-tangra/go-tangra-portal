package httpapi

import (
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/route"
	fidentity "github.com/go-tangra/go-tangra/v4/identity"
)

// RemoteUIPath is where modules serve their federated remote on their Freya HTTP server.
const RemoteUIPath = "/ui"

// hashedAsset matches Vite's content-hashed file names (immutable caching).
var hashedAsset = regexp.MustCompile(`[-.][A-Za-z0-9_-]{8,}\.(js|mjs|css|woff2?|ttf|png|svg|webp|map)$`)

var remoteMu sync.Mutex
var remoteCache = map[string]Backend{}

// remoteAsset relays GET /m/<module>/<asset> to the module's /ui/<asset>
// over the pinned channel. Only current registrations are reachable; the
// path is normalised so nothing outside /ui is ever requested.
func (s *Server) remoteAsset(d ShellDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		module, asset := r.PathValue("module"), r.PathValue("asset")
		clean, ok := route.Normalize("/" + asset)
		if !ok || clean == "/" || strings.Contains(clean, "/../") {
			WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
			return
		}
		reg, found := d.Reg.Get(module)
		if !found || d.Reg.State(module) == registry.StateRevoked {
			WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
			return
		}
		id, instances := d.Reg.Backends(module)
		if len(instances) == 0 || instances[0].Backend.HTTPURL == "" {
			WriteError(w, ErrUnavailable.Status, ErrUnavailable.Reason)
			return
		}
		spiffe, err := fidentity.ParseSPIFFEID(id)
		if err != nil {
			WriteError(w, ErrUnavailable.Status, ErrUnavailable.Reason)
			return
		}
		target := instances[0].Backend.HTTPURL
		key := module + "|" + target
		remoteMu.Lock()
		be := remoteCache[key]
		if be == nil {
			if be, err = d.Proxies(module, spiffe, target); err != nil {
				remoteMu.Unlock()
				WriteError(w, ErrUnavailable.Status, ErrUnavailable.Reason)
				return
			}
			remoteCache[key] = be
		}
		remoteMu.Unlock()
		out := r.Clone(r.Context())
		out.URL.Path = path.Join(RemoteUIPath, clean)
		out.URL.RawPath = ""
		out.RequestURI = ""
		out.Header.Del("Cookie")
		out.Header.Del("Authorization")
		rec := &cacheWriter{ResponseWriter: w, immutable: hashedAsset.MatchString(clean), manifest: strings.HasSuffix(clean, "/mf-manifest.json")}
		be.ServeHTTP(rec, out)
		_ = reg
	}
}

// cacheWriter sets caching headers according to the asset kind.
type cacheWriter struct {
	http.ResponseWriter
	immutable, manifest bool
	done                bool
}

func (c *cacheWriter) WriteHeader(code int) {
	if !c.done {
		c.done = true
		h := c.Header()
		switch {
		case code >= 300:
			h.Set("Cache-Control", "no-store")
		case c.manifest:
			h.Set("Cache-Control", "no-store")
		case c.immutable:
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		default:
			h.Set("Cache-Control", "no-cache")
		}
		h.Del("Set-Cookie")
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *cacheWriter) Write(b []byte) (int, error) {
	if !c.done {
		c.WriteHeader(http.StatusOK)
	}
	return c.ResponseWriter.Write(b)
}

// Flush supports streaming.
func (c *cacheWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

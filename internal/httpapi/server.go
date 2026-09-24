// Package httpapi is the public HTTP surface of the gateway: the shell and
// operations API under /gateway/v1 (OpenAPI-validated), the shell assets, the
// federated remote relay under /m/<module>/ and the fallback that hands every
// other path to the module forwarder.
package httpapi

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/go-tangra/go-tangra-portal/v4/api/openapi"
	"github.com/go-tangra/go-tangra/v4/transport"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

// APIPrefix is the gateway's own API; RemotePrefix relays federated remotes.
const (
	APIPrefix    = "/gateway/v1/"
	RemotePrefix = "/m/"
)

// Route is a declared method/path pair.
type Route struct{ Method, Path string }

func (r Route) String() string { return r.Method + " " + r.Path }

// Option configures the handler.
type Option func(*Server)

// WithShell serves the built shell from dist for paths no module owns.
func WithShell(dist fs.FS) Option { return func(s *Server) { s.shell = dist } }

// Middleware wraps the whole chain (identity resolution is installed this way).
type Middleware func(http.Handler) http.Handler

// WithMiddleware prepends middleware (outermost first).
func WithMiddleware(m ...Middleware) Option { return func(s *Server) { s.mws = append(s.mws, m...) } }

// Server mounts every declared OpenAPI route (501 until a story implements
// it), validates requests against the document and serves the shell.
type Server struct {
	rt        transport.Runtime
	edge      *edge.Server
	doc       *openapi3.T
	router    routers.Router
	mux       *http.ServeMux
	mu        sync.RWMutex
	handlers  map[Route]http.Handler
	declared  []Route
	shell     fs.FS
	mws       []Middleware
	forwarder http.Handler
	handler   http.Handler
}

// LoadDocument parses and validates the embedded OpenAPI document.
func LoadDocument() (*openapi3.T, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(openapi.Gateway)
	if err != nil {
		return nil, fmt.Errorf("httpapi: openapi: %w", err)
	}
	if err := doc.Validate(loader.Context, openapi3.DisableExamplesValidation()); err != nil {
		return nil, fmt.Errorf("httpapi: openapi: %w", err)
	}
	return doc, nil
}

// DeclaredRoutes lists every operation in the document, sorted.
func DeclaredRoutes(doc *openapi3.T) []Route {
	var out []Route
	for p, item := range doc.Paths.Map() {
		for m := range item.Operations() {
			out = append(out, Route{Method: strings.ToUpper(m), Path: p})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// muxPattern turns an OpenAPI path into a Go 1.22 mux pattern; a trailing
// {asset} parameter under /m/ matches the rest of the path.
func muxPattern(rt Route) string {
	p := rt.Path
	if strings.HasPrefix(p, RemotePrefix) && strings.HasSuffix(p, "/{asset}") {
		p = strings.TrimSuffix(p, "{asset}") + "{asset...}"
	}
	return rt.Method + " " + p
}

// NewHandler builds the API without binding a listener (tests, embedding).
func NewHandler(rt transport.Runtime, opts ...Option) (*Server, error) {
	doc, err := LoadDocument()
	if err != nil {
		return nil, err
	}
	servers := doc.Servers
	doc.Servers = nil
	router, err := gorillamux.NewRouter(doc)
	doc.Servers = servers
	if err != nil {
		return nil, fmt.Errorf("httpapi: router: %w", err)
	}
	s := &Server{rt: rt, doc: doc, router: router, mux: http.NewServeMux(), handlers: map[Route]http.Handler{}}
	for _, o := range opts {
		o(s)
	}
	s.declared = DeclaredRoutes(doc)
	for _, rt := range s.declared {
		rt := rt
		s.mux.Handle(muxPattern(rt), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.mu.RLock()
			h := s.handlers[rt]
			s.mu.RUnlock()
			if h == nil {
				WriteError(w, ErrNotImplemented.Status, ErrNotImplemented.Reason)
				return
			}
			h.ServeHTTP(w, r)
		}))
	}
	// Anything else under the gateway's own prefixes is unknown.
	s.mux.Handle(APIPrefix, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
	}))
	s.mux.Handle("/", http.HandlerFunc(s.fallback))
	var h http.Handler = s.validate(s.mux)
	for i := len(s.mws) - 1; i >= 0; i-- {
		h = s.mws[i](h)
	}
	s.handler = h
	return s, nil
}

// New builds the API and binds it to an edge listener. State-changing
// requests that carry no cookie at all are exempt from CSRF (machine clients
// with bearer tokens, external gRPC clients): CSRF only matters for ambient
// cookie credentials.
func New(rt transport.Runtime, cfg edge.Config, opts ...Option) (*Server, error) {
	s, err := NewHandler(rt, opts...)
	if err != nil {
		return nil, err
	}
	if cfg.CSRFExempt == nil {
		cfg.CSRFExempt = WithoutCookies
	}
	e, err := edge.NewServer(rt, cfg)
	if err != nil {
		return nil, err
	}
	e.HandlePrefix("/", s.handler)
	s.edge = e
	return s, nil
}

// WithoutCookies reports whether a request carries no cookie at all (CSRF is
// irrelevant without ambient credentials; such requests are anonymous or
// bearer-authenticated).
func WithoutCookies(r *http.Request) bool {
	_, ok := r.Header["Cookie"]
	return !ok
}

// SetForwarder installs the module dispatcher for paths the gateway does not
// own. It must call ServeShell or NotFound itself when no module matches.
func (s *Server) SetForwarder(h http.Handler) {
	s.mu.Lock()
	s.forwarder = h
	s.mu.Unlock()
}

func (s *Server) fallback(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	f := s.forwarder
	s.mu.RUnlock()
	if f != nil {
		f.ServeHTTP(w, r)
		return
	}
	s.NotOwned(w, r)
}

// NotOwned answers a path no module owns: the shell for navigations, else 404.
func (s *Server) NotOwned(w http.ResponseWriter, r *http.Request) {
	if s.shell != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) && !strings.HasPrefix(r.URL.Path, "/api/") {
		s.ServeShell(w, r)
		return
	}
	WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
}

// Handle installs h for a declared route; undeclared routes are refused so
// the contract and the implementation cannot drift.
func (s *Server) Handle(method, path string, h http.Handler) error {
	rt := Route{Method: strings.ToUpper(method), Path: path}
	if !s.isDeclared(rt) {
		return fmt.Errorf("httpapi: route %s is not declared in the OpenAPI document", rt)
	}
	s.mu.Lock()
	s.handlers[rt] = h
	s.mu.Unlock()
	return nil
}

// HandleFunc is Handle for a function.
func (s *Server) HandleFunc(method, path string, h func(http.ResponseWriter, *http.Request)) error {
	return s.Handle(method, path, http.HandlerFunc(h))
}

// MustHandle panics on an undeclared route (wiring errors are programming errors).
func (s *Server) MustHandle(method, path string, h func(http.ResponseWriter, *http.Request)) {
	if err := s.HandleFunc(method, path, h); err != nil {
		panic(err)
	}
}

func (s *Server) isDeclared(rt Route) bool {
	for _, d := range s.declared {
		if d == rt {
			return true
		}
	}
	return false
}

// Declared lists routes from the document; Implemented lists those with a handler.
func (s *Server) Declared() []Route { return append([]Route(nil), s.declared...) }

// Implemented lists the declared routes that have a handler.
func (s *Server) Implemented() []Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Route
	for rt := range s.handlers {
		out = append(out, rt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// Document returns the parsed OpenAPI document.
func (s *Server) Document() *openapi3.T { return s.doc }

// Handler returns the full chain.
func (s *Server) Handler() http.Handler { return s.handler }

// Edge returns the bound listener (nil for NewHandler).
func (s *Server) Edge() *edge.Server { return s.edge }

// Start/Stop delegate to the edge listener.
func (s *Server) Start(ctx context.Context) error { return s.edge.Start(ctx) }
func (s *Server) Stop(ctx context.Context) error  { return s.edge.Stop(ctx) }

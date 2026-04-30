package server

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/service"
)

// ModuleAssetProxy is a reverse proxy that routes /modules/{module_id}/*
// requests to the corresponding module's HTTP server for frontend assets.
// It replaces per-module nginx location blocks with a single dynamic proxy.
type ModuleAssetProxy struct {
	log      *log.Helper
	registry *service.ModuleRegistry

	// Cached reverse proxies keyed by module_id
	proxies sync.Map // module_id -> *httputil.ReverseProxy
}

// NewModuleAssetProxy creates a new ModuleAssetProxy.
func NewModuleAssetProxy(ctx *bootstrap.Context, registry *service.ModuleRegistry) *ModuleAssetProxy {
	p := &ModuleAssetProxy{
		log:      ctx.NewLoggerHelper("module-asset-proxy/admin-service"),
		registry: registry,
	}

	// Subscribe to module events to invalidate proxy cache on unregister/update
	registry.OnEvent(p.handleModuleEvent)

	return p
}

// handleModuleEvent handles module lifecycle events.
func (p *ModuleAssetProxy) handleModuleEvent(event service.ModuleRegistryEvent) {
	switch event.Type {
	case service.ModuleEventUnregistered:
		p.proxies.Delete(event.Module.ModuleID)
		p.log.Infof("Removed cached proxy for unregistered module: %s", event.Module.ModuleID)
	case service.ModuleEventRegistered, service.ModuleEventUpdated:
		// Invalidate cached proxy so it picks up the new endpoint
		p.proxies.Delete(event.Module.ModuleID)
	}
}

// ServeHTTP implements http.Handler.
// Route format: /modules/{module_id}/{rest_of_path}
func (p *ModuleAssetProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	moduleID, assetPath := p.extractModuleFromPath(r.URL.Path)
	if moduleID == "" {
		p.writeError(w, http.StatusBadRequest, "missing module ID in path")
		return
	}

	// Look up module in registry
	mod, exists := p.registry.Get(moduleID)
	if !exists {
		p.writeError(w, http.StatusNotFound, "module not found: %s", moduleID)
		return
	}

	if mod.HttpEndpoint == "" {
		p.writeError(w, http.StatusBadGateway, "module %s has no HTTP endpoint configured", moduleID)
		return
	}

	// Get or create reverse proxy for this module
	proxy, err := p.getOrCreateProxy(moduleID, mod.HttpEndpoint)
	if err != nil {
		p.writeError(w, http.StatusBadGateway, "failed to create proxy for module %s: %v", moduleID, err)
		return
	}

	// Cache-Control: only override for recognised static-asset paths
	// (federated remote chunks). Anything else — SSE streams, audio
	// recordings, JSON APIs served by a module's HTTP server — gets
	// whatever Cache-Control the upstream sets, or none at all.
	//
	// The previous blanket-immutable policy broke SSE: browsers and
	// some proxies treat `immutable` as "this body never changes" and
	// terminate / cache the long-lived stream after the first chunk.
	switch {
	case strings.HasSuffix(assetPath, "remoteEntry.js"):
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	case isCacheableAsset(assetPath):
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}

	// Rewrite the request path: strip /modules/{module_id} prefix
	r.URL.Path = assetPath
	r.URL.RawPath = ""

	proxy.ServeHTTP(w, r)
}

// isCacheableAsset returns true for paths that look like Vite-style
// fingerprinted bundles (assets/*.js, *.css, *.woff2, etc.) — those are
// safe to mark immutable. Anything else (SSE, recordings, API calls)
// must not get long-cache headers.
func isCacheableAsset(p string) bool {
	if !strings.HasPrefix(p, "/assets/") {
		return false
	}
	switch {
	case strings.HasSuffix(p, ".js"),
		strings.HasSuffix(p, ".css"),
		strings.HasSuffix(p, ".woff"),
		strings.HasSuffix(p, ".woff2"),
		strings.HasSuffix(p, ".ttf"),
		strings.HasSuffix(p, ".otf"),
		strings.HasSuffix(p, ".png"),
		strings.HasSuffix(p, ".jpg"),
		strings.HasSuffix(p, ".jpeg"),
		strings.HasSuffix(p, ".webp"),
		strings.HasSuffix(p, ".svg"),
		strings.HasSuffix(p, ".gif"),
		strings.HasSuffix(p, ".ico"):
		return true
	}
	return false
}

// getOrCreateProxy returns a cached proxy or creates a new one.
func (p *ModuleAssetProxy) getOrCreateProxy(moduleID, httpEndpoint string) (*httputil.ReverseProxy, error) {
	if val, ok := p.proxies.Load(moduleID); ok {
		return val.(*httputil.ReverseProxy), nil
	}

	target, err := url.Parse("http://" + httpEndpoint)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Custom Transport with no per-request deadlines so long-lived
	// upstream connections (SSE streams, large file downloads via the
	// recordings endpoint) aren't killed by Go's stdlib defaults
	// (IdleConnTimeout=90s, etc). DialContext keeps a reasonable
	// connect timeout so a wedged upstream still fails fast.
	proxy.Transport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false, // module HTTP servers are HTTP/1.1
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       0, // never close idle conns from the pool
		ResponseHeaderTimeout: 0, // never time out waiting for response headers
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Force immediate flush after each upstream write. Go 1.19+
	// auto-detects text/event-stream and sets this internally, but
	// being explicit hardens against future stdlib changes and covers
	// other streaming content-types (audio recordings) too.
	proxy.FlushInterval = -1

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		p.log.Warnf("Proxy error for module %s: %v", moduleID, err)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"code":502,"message":"upstream error for module %s"}`, moduleID)))
	}

	actual, _ := p.proxies.LoadOrStore(moduleID, proxy)
	return actual.(*httputil.ReverseProxy), nil
}

// extractModuleFromPath extracts the module ID and remaining asset path.
// Input:  /modules/sharing/assets/main.js
// Output: "sharing", "/assets/main.js"
func (p *ModuleAssetProxy) extractModuleFromPath(path string) (moduleID, assetPath string) {
	const prefix = "/modules/"
	if !strings.HasPrefix(path, prefix) {
		return "", ""
	}

	remaining := strings.TrimPrefix(path, prefix)
	if remaining == "" {
		return "", ""
	}

	slashIdx := strings.Index(remaining, "/")
	if slashIdx == -1 {
		return remaining, "/"
	}

	return remaining[:slashIdx], remaining[slashIdx:]
}

// writeError writes a JSON error response.
func (p *ModuleAssetProxy) writeError(w http.ResponseWriter, code int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"code":%d,"message":"%s"}`, code, msg)))
}

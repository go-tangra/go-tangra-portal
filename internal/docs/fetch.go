package docs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/go-tangra/go-tangra/v4/helpdocs"
	fidentity "github.com/go-tangra/go-tangra/v4/identity"
)

// ClientFactory returns an HTTP client that only completes connections to
// the peer with the given SPIFFE ID (transport/http.NewClient: the gateway's
// SVID, mTLS, peer identity verified).
type ClientFactory func(id fidentity.SPIFFEID) (*http.Client, error)

// HTTPFetcher fetches bundles over the mesh, one client per module identity.
type HTTPFetcher struct {
	Clients ClientFactory

	mu      sync.Mutex
	clients map[string]*http.Client
}

// Fetch implements Fetcher.
func (f *HTTPFetcher) Fetch(ctx context.Context, t Target, etag string) ([]byte, error) {
	c, err := f.client(t.Identity)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(t.Backend, "/")+helpdocs.BundlePath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if etag != "" {
		req.Header.Set("If-None-Match", `"`+etag+`"`)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, ErrNotModified
	case resp.StatusCode != http.StatusOK:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("GET %s: status %d", helpdocs.BundlePath, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBundleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBundleBytes {
		return nil, fmt.Errorf("bundle exceeds %d bytes", MaxBundleBytes)
	}
	return body, nil
}

func (f *HTTPFetcher) client(identity string) (*http.Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.clients[identity]; c != nil {
		return c, nil
	}
	id, err := fidentity.ParseSPIFFEID(identity)
	if err != nil {
		return nil, fmt.Errorf("module identity: %w", err)
	}
	c, err := f.Clients(id)
	if err != nil {
		return nil, err
	}
	if f.clients == nil {
		f.clients = map[string]*http.Client{}
	}
	f.clients[identity] = c
	return c, nil
}

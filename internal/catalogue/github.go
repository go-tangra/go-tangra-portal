package catalogue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultAPI is GitHub's REST API.
const DefaultAPI = "https://api.github.com"

// Release asset names published by the catalogue-entry action.
const (
	AssetEntry       = "catalogue-entry.json"
	AssetBundle      = "bundle.zip"
	AssetAttestation = "catalogue.sigstore.json"
	maxAttestation   = 64 << 10
	maxReleaseJSON   = 1 << 20
)

// ErrUnavailable: GitHub could not be reached or answered with an error.
var ErrUnavailable = errors.New("catalogue: GitHub unavailable")

// GitHub reads releases. Only the API host, github.com and
// *.githubusercontent.com are ever contacted (SR-002).
type GitHub struct {
	API    string // default DefaultAPI
	Token  string // optional; raises rate limits
	Client *http.Client
	// allowTestHost lets tests serve downloads from the API host.
	allowTestHost bool
}

// Asset is one release asset.
type Asset struct {
	URL  string
	Size int64
}

// Release is a repository's latest release.
type Release struct {
	Tag    string
	Assets map[string]Asset
}

func (g *GitHub) api() string {
	if g.API == "" {
		return DefaultAPI
	}
	return strings.TrimSuffix(g.API, "/")
}

func (g *GitHub) client() *http.Client {
	base := g.Client
	if base == nil {
		base = &http.Client{Timeout: 30 * time.Second}
	}
	c := *base
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || !g.allowed(req.URL) {
			return fmt.Errorf("redirect to %s refused", req.URL.Host)
		}
		return nil
	}
	return &c
}

func (g *GitHub) allowed(u *url.URL) bool {
	api, _ := url.Parse(g.api())
	host := u.Hostname()
	switch {
	case api != nil && u.Host == api.Host && (u.Scheme == "https" || g.allowTestHost):
		return true
	case u.Scheme != "https":
		return false
	case host == "github.com", strings.HasSuffix(host, ".githubusercontent.com"):
		return true
	}
	return false
}

// Latest returns repo's latest release (owner/repo).
func (g *GitHub) Latest(ctx context.Context, repo string) (Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.api()+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	resp, err := g.client().Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("%w: %v", ErrUnavailable, redact(err))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return Release{}, fmt.Errorf("no release published (or repository not found)")
	case resp.StatusCode != http.StatusOK:
		return Release{}, fmt.Errorf("%w: HTTP %d", ErrUnavailable, resp.StatusCode)
	}
	var body struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReleaseJSON)).Decode(&body); err != nil {
		return Release{}, fmt.Errorf("%w: unreadable release", ErrUnavailable)
	}
	rel := Release{Tag: body.TagName, Assets: map[string]Asset{}}
	for _, a := range body.Assets {
		rel.Assets[a.Name] = Asset{URL: a.URL, Size: a.Size}
	}
	return rel, nil
}

// Download fetches an asset of at most limit bytes.
func (g *GitHub) Download(ctx context.Context, a Asset, limit int64) ([]byte, error) {
	if a.Size > limit {
		return nil, fmt.Errorf("asset too large (%d bytes, limit %d)", a.Size, limit)
	}
	u, err := url.Parse(a.URL)
	if err != nil || !g.allowed(u) {
		return nil, fmt.Errorf("asset URL host not allowed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, redact(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: asset HTTP %d", ErrUnavailable, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, redact(err))
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("asset too large (limit %d)", limit)
	}
	return b, nil
}

// redact keeps URL errors free of query strings (signed download URLs).
func redact(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		if u, perr := url.Parse(ue.URL); perr == nil {
			u.RawQuery = ""
			return ue.Op + " " + u.String() + ": " + ue.Err.Error()
		}
	}
	return err.Error()
}

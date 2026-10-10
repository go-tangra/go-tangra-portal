package catalogue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	fwcat "github.com/go-tangra/go-tangra/v4/catalogue"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// DefaultInterval is how often every source is read.
const DefaultInterval = 6 * time.Hour

// Outcomes of reading a release.
const (
	OutcomeStored      = "stored"      // a newer verified entry was stored
	OutcomeCurrent     = "current"     // the release is the stored entry
	OutcomeRefused     = "refused"     // the release was refused (Error says why)
	OutcomeUnavailable = "unavailable" // GitHub could not be read
)

// Store is the catalogue's storage.
type Store interface {
	ListAllowedOwners(ctx context.Context) ([]string, error)
	ListSources(ctx context.Context) ([]store.CatalogueSource, error)
	SourceChecked(ctx context.Context, repo, module, errText string) error
	LatestEntries(ctx context.Context) ([]store.CatalogueEntry, error)
	InsertEntry(ctx context.Context, e store.CatalogueEntry) error
}

// VerifyFunc checks an attestation over artifacts for repo at tag and
// returns the signing identity (Verifier.VerifyBundle).
type VerifyFunc func(attestation []byte, repo, tag string, artifacts ...[]byte) (string, error)

// Result is the outcome of reading one release.
type Result struct {
	Repo    string `json:"repo"`
	Module  string `json:"module,omitempty"`
	Version string `json:"version,omitempty"`
	Outcome string `json:"outcome"`
	Error   string `json:"error,omitempty"`
}

// Service reads sources, verifies their releases and stores entries. It
// runs beside the request path (Run) and on administrator demand.
type Service struct {
	Store    Store
	GitHub   *GitHub
	Verify   VerifyFunc
	Audit    *audit.Writer
	Logger   *slog.Logger
	Interval time.Duration
	Now      func() time.Time
}

// refusal carries an audit reason with the message shown to administrators.
type refusal struct{ reason, msg string }

func (r refusal) Error() string { return r.msg }

func refuse(reason, format string, a ...any) error {
	return refusal{reason, fmt.Sprintf(format, a...)}
}

// Run reads every source now and then every Interval until ctx ends.
func (s *Service) Run(ctx context.Context) {
	interval := s.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	s.RefreshAll(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.RefreshAll(ctx)
		}
	}
}

// RefreshAll reads every source once.
func (s *Service) RefreshAll(ctx context.Context) []Result {
	sources, err := s.Store.ListSources(ctx)
	if err != nil {
		s.logger().Warn("catalogue: sources unavailable")
		return nil
	}
	out := make([]Result, 0, len(sources))
	for _, src := range sources {
		out = append(out, s.Refresh(ctx, src.Repo))
	}
	return out
}

// Refresh reads repo's latest release and stores its entry when it verifies.
func (s *Service) Refresh(ctx context.Context, repo string) Result {
	res := Result{Repo: repo}
	rel, err := s.GitHub.Latest(ctx, repo)
	if err != nil {
		return s.finish(ctx, res, err)
	}
	entry, okE := rel.Assets[AssetEntry]
	bundle, okB := rel.Assets[AssetBundle]
	att, okA := rel.Assets[AssetAttestation]
	if !okE || !okB || !okA {
		return s.finish(ctx, res, refuse("no_entry", "no catalogue entry in release %s", rel.Tag))
	}
	var data [3][]byte
	for i, a := range []struct {
		asset Asset
		limit int64
	}{{entry, fwcat.MaxEntryBytes}, {bundle, fwcat.MaxBundleBytes}, {att, maxAttestation}} {
		b, err := s.GitHub.Download(ctx, a.asset, a.limit)
		if err != nil {
			if !errors.Is(err, ErrUnavailable) {
				err = refuse("too_large", "%v", err)
			}
			return s.finish(ctx, res, err)
		}
		data[i] = b
	}
	return s.ingest(ctx, res, repo, rel.Tag, data[0], data[1], data[2])
}

// Upload verifies release assets supplied by an administrator (cores without
// GitHub access) exactly as Refresh does. The entry's repository must be a
// catalogue source.
func (s *Service) Upload(ctx context.Context, entry, bundle, attestation []byte) Result {
	claimed, err := fwcat.ParseEntry(entry)
	if err != nil {
		return Result{Outcome: OutcomeRefused, Error: err.Error()}
	}
	sources, err := s.Store.ListSources(ctx)
	if err != nil {
		return Result{Outcome: OutcomeUnavailable, Error: "catalogue store unavailable"}
	}
	for _, src := range sources {
		if strings.EqualFold(src.Repo, claimed.Repository) {
			return s.ingest(ctx, Result{Repo: src.Repo}, src.Repo, "v"+claimed.Version, entry, bundle, attestation)
		}
	}
	return Result{Repo: claimed.Repository, Outcome: OutcomeRefused, Error: claimed.Repository + " is not a catalogue source"}
}

func (s *Service) ingest(ctx context.Context, res Result, repo, tag string, entryRaw, bundle, attestation []byte) Result {
	owner, _, _ := strings.Cut(repo, "/")
	owners, err := s.Store.ListAllowedOwners(ctx)
	if err != nil {
		return s.finish(ctx, res, fmt.Errorf("%w: store", ErrUnavailable))
	}
	if !containsFold(owners, owner) {
		return s.finish(ctx, res, refuse("owner_not_allowed", "%s is not an allowed owner", owner))
	}
	if len(attestation) > maxAttestation {
		return s.finish(ctx, res, refuse("too_large", "attestation too large"))
	}
	// Nothing is parsed or trusted before the attestation verifies.
	who, err := s.Verify(attestation, repo, tag, entryRaw, bundle)
	if errors.Is(err, ErrUnavailable) {
		return s.finish(ctx, res, err)
	}
	if err != nil {
		return s.finish(ctx, res, refuse("attestation", "attestation refused: %v", err))
	}
	e, err := fwcat.ParseEntry(entryRaw)
	if err != nil {
		return s.finish(ctx, res, refuse("invalid", "%v", err))
	}
	res.Module, res.Version = e.Module, e.Version
	switch {
	case !strings.EqualFold(e.Repository, repo):
		return s.finish(ctx, res, refuse("repository_mismatch", "entry names repository %s, not %s", e.Repository, repo))
	case tag != "v"+e.Version:
		return s.finish(ctx, res, refuse("tag_mismatch", "release tag %s does not match entry version %s", tag, e.Version))
	}
	if err := e.CheckBundle(bundle); err != nil {
		return s.finish(ctx, res, refuse("invalid", "%v", err))
	}
	if err := s.bound(ctx, repo, e.Module); err != nil {
		return s.finish(ctx, res, err)
	}
	if cur, ok, err := s.latest(ctx, e.Module); err != nil {
		return s.finish(ctx, res, fmt.Errorf("%w: store", ErrUnavailable))
	} else if ok {
		cmp, _ := fwcat.CompareVersions(e.Version, cur.Version)
		if cmp == 0 {
			res.Outcome = OutcomeCurrent
			_ = s.Store.SourceChecked(ctx, repo, e.Module, "")
			return res
		}
		if cmp < 0 {
			return s.finish(ctx, res, refuse("downgrade", "release %s is older than the stored %s", e.Version, cur.Version))
		}
	}
	esum, bsum := sha256.Sum256(entryRaw), sha256.Sum256(bundle)
	row := store.CatalogueEntry{Module: e.Module, Version: e.Version, Repo: repo, VersionKey: versionKey(e.Version), Entry: entryRaw,
		EntrySHA256: hex.EncodeToString(esum[:]), Bundle: bundle, BundleSHA256: hex.EncodeToString(bsum[:]), AttestedBy: who, VerifiedAt: s.now()}
	if err := s.Store.SourceChecked(ctx, repo, e.Module, ""); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return s.finish(ctx, res, refuse("module_taken", "module %s is already published by another source", e.Module))
		}
		return s.finish(ctx, res, fmt.Errorf("%w: store", ErrUnavailable))
	}
	if err := s.Store.InsertEntry(ctx, row); err != nil && !errors.Is(err, store.ErrConflict) {
		return s.finish(ctx, res, fmt.Errorf("%w: store", ErrUnavailable))
	}
	res.Outcome = OutcomeStored
	s.emit(audit.Event{Type: audit.CatalogueEntryVerified, Module: e.Module, ActorKind: "system", SubjectKind: "repository", SubjectID: repo,
		Outcome: "ok", Details: map[string]any{"version": e.Version, "attested_by": who}})
	return res
}

// bound refuses a repository switching modules and a module already
// published by another source.
func (s *Service) bound(ctx context.Context, repo, module string) error {
	sources, err := s.Store.ListSources(ctx)
	if err != nil {
		return fmt.Errorf("%w: store", ErrUnavailable)
	}
	for _, src := range sources {
		switch {
		case strings.EqualFold(src.Repo, repo) && src.Module != "" && src.Module != module:
			return refuse("module_changed", "%s publishes %s, not %s", repo, src.Module, module)
		case !strings.EqualFold(src.Repo, repo) && src.Module == module:
			return refuse("module_taken", "module %s is already published by %s", module, src.Repo)
		}
	}
	return nil
}

func (s *Service) latest(ctx context.Context, module string) (store.CatalogueEntry, bool, error) {
	all, err := s.Store.LatestEntries(ctx)
	if err != nil {
		return store.CatalogueEntry{}, false, err
	}
	for _, e := range all {
		if e.Module == module {
			return e, true, nil
		}
	}
	return store.CatalogueEntry{}, false, nil
}

// finish records a failed read on the source and audits refusals.
func (s *Service) finish(ctx context.Context, res Result, err error) Result {
	res.Error = err.Error()
	var r refusal
	switch {
	case errors.As(err, &r):
		res.Outcome = OutcomeRefused
		s.emit(audit.Event{Type: audit.CatalogueEntryRefused, Module: res.Module, ActorKind: "system", SubjectKind: "repository", SubjectID: res.Repo,
			Outcome: "refused", Reason: r.reason, Details: map[string]any{"version": res.Version, "error": r.msg}})
	default:
		res.Outcome = OutcomeUnavailable
	}
	if res.Repo != "" {
		_ = s.Store.SourceChecked(ctx, res.Repo, "", res.Error)
	}
	return res
}

func (s *Service) emit(e audit.Event) {
	if s.Audit != nil {
		_ = s.Audit.Emit(e)
	}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// versionKey orders X.Y.Z versions in SQL.
func versionKey(v string) int64 {
	var a, b, c int64
	_, _ = fmt.Sscanf(v, "%d.%d.%d", &a, &b, &c)
	return a*1_000_000_000_000 + b*1_000_000 + c
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

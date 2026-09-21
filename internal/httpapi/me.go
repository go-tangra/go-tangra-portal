package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-freya/freya/services/gateway/internal/identity"
	"github.com/go-freya/freya/transport/edge"
)

// IdentitySource resolves the caller of a request (identity.Resolver).
type IdentitySource interface {
	Resolve(ctx context.Context, r *http.Request) (identity.Identity, error)
}

// Me is the GET /gateway/v1/me body.
type Me struct {
	UserID    string   `json:"user_id"`
	TenantID  string   `json:"tenant_id"`
	SessionID string   `json:"session_id,omitempty"`
	Roles     []string `json:"roles"`
	AMR       []string `json:"amr,omitempty"`
	Operator  bool     `json:"operator"`
	Source    string   `json:"source"`
	ExpiresAt string   `json:"expires_at"`
	// Feature 004: shown by the shell header and modules; empty for bearer callers.
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
}

// RegisterMe mounts GET /gateway/v1/me. A fresh browser also receives the
// CSRF cookie here so the shell can make its first state-changing call.
func (s *Server) RegisterMe(src IdentitySource) {
	s.MustHandle("GET", "/gateway/v1/me", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(edge.CSRFCookie); err != nil {
			edge.IssueCSRFCookie(w)
		}
		id, err := src.Resolve(r.Context(), r)
		if err != nil {
			Fail(w, r, s.rt.Logger(), mapIdentityErr(err))
			return
		}
		WriteJSON(w, http.StatusOK, Me{UserID: id.UserID, TenantID: id.TenantID, SessionID: id.SessionID, Roles: id.Roles, AMR: id.AMR, Operator: id.Operator, Source: id.Source,
			ExpiresAt: id.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"), DisplayName: id.DisplayName, AvatarURL: id.AvatarURL})
	})
}

// mapIdentityErr converts identity errors to the closed refusal vocabulary.
func mapIdentityErr(err error) error {
	switch {
	case errors.Is(err, identity.ErrAnonymous), errors.Is(err, identity.ErrUnauthenticated):
		return ErrUnauthenticated
	case errors.Is(err, identity.ErrUnavailable):
		return ErrUnavailable
	}
	return err
}

// RequireIdentity resolves the caller or writes the refusal; ok=false means written.
func RequireIdentity(w http.ResponseWriter, r *http.Request, src IdentitySource) (identity.Identity, bool) {
	return requireIdentity(w, r, src, nil)
}

func requireIdentity(w http.ResponseWriter, r *http.Request, src IdentitySource, log *slog.Logger) (identity.Identity, bool) {
	id, err := src.Resolve(r.Context(), r)
	if err != nil {
		if log != nil && !errors.Is(err, identity.ErrAnonymous) && !errors.Is(err, identity.ErrUnauthenticated) {
			log.WarnContext(r.Context(), "identity resolution failed", "path", r.URL.Path, "err", err)
		}
		Fail(w, r, nil, mapIdentityErr(err))
		return identity.Identity{}, false
	}
	return id, true
}

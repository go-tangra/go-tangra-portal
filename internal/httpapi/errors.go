package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
)

// Error is a refusal with a stable reason from the closed vocabulary
// (contracts/gateway-api.openapi.yaml, contracts/forwarding.md).
type Error struct {
	Status int
	Reason string
}

func (e *Error) Error() string { return e.Reason }

// Refusals.
var (
	ErrUnauthenticated = &Error{http.StatusUnauthorized, "unauthenticated"}
	ErrForbidden       = &Error{http.StatusForbidden, "forbidden"}
	ErrNotFound        = &Error{http.StatusNotFound, "not_found"}
	ErrValidation      = &Error{http.StatusBadRequest, "validation_failed"}
	ErrUnavailable     = &Error{http.StatusServiceUnavailable, "temporarily_unavailable"}
	ErrRateLimited     = &Error{http.StatusTooManyRequests, "rate_limited"}
	ErrTooLarge        = &Error{http.StatusRequestEntityTooLarge, "payload_too_large"}
	ErrCSRF            = &Error{http.StatusForbidden, "csrf"}
	ErrNotImplemented  = &Error{http.StatusNotImplemented, "not_implemented"}
)

// MaxBodyBytes bounds JSON bodies of the gateway's own API.
const MaxBodyBytes = 64 << 10

// WriteJSON encodes v with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError emits {"reason": ...} and nothing else.
func WriteError(w http.ResponseWriter, status int, reason string) {
	WriteJSON(w, status, map[string]string{"reason": reason})
}

// Fail maps err to a response: *Error verbatim; anything else is an internal
// or upstream failure reported as 503 temporarily_unavailable (details go to
// the log only, never to the client).
func Fail(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	var e *Error
	if errors.As(err, &e) {
		WriteError(w, e.Status, e.Reason)
		return
	}
	if log != nil {
		log.ErrorContext(r.Context(), "request failed", "path", r.URL.Path, "err", err)
	}
	WriteError(w, ErrUnavailable.Status, ErrUnavailable.Reason)
}

// DecodeJSON reads a bounded JSON body into v, refusing unknown fields and
// trailing data.
func DecodeJSON(r *http.Request, v any) error {
	body := http.MaxBytesReader(nil, r.Body, MaxBodyBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrValidation
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrValidation
	}
	return nil
}

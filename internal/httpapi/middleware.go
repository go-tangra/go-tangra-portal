package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
)

// validate checks requests to the gateway's own API against the OpenAPI
// document; forwarded module traffic is never validated here.
func (s *Server) validate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, APIPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		route, params, err := s.router.FindRoute(r)
		if err != nil {
			if errors.Is(err, routers.ErrPathNotFound) {
				next.ServeHTTP(w, r)
				return
			}
			WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		}
		in := &openapi3filter.RequestValidationInput{Request: r, PathParams: params, Route: route,
			Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc, MultiError: false}}
		if err := openapi3filter.ValidateRequest(r.Context(), in); err != nil {
			WriteError(w, ErrValidation.Status, ErrValidation.Reason)
			return
		}
		next.ServeHTTP(w, r)
	})
}

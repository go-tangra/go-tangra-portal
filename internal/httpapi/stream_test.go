package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// streamRecorder is a ResponseRecorder safe for concurrent reads while a
// handler is still streaming.
type streamRecorder struct {
	mu  sync.Mutex
	rec *httptest.ResponseRecorder
	buf strings.Builder
}

func newStreamRecorder() *streamRecorder { return &streamRecorder{rec: httptest.NewRecorder()} }

func (s *streamRecorder) Header() http.Header { return s.rec.Header() }
func (s *streamRecorder) WriteHeader(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rec.WriteHeader(code)
}
func (s *streamRecorder) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Write(b)
	return s.rec.Write(b)
}
func (s *streamRecorder) Flush() {}
func (s *streamRecorder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

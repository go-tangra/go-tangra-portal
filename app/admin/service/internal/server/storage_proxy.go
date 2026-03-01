package server

import (
	"io"
	"net/http"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/minio/minio-go/v7"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/pkg/oss"
)

// StorageProxy serves objects from S3-compatible storage (RustFS/MinIO)
// using authenticated access, so buckets don't need public-read policies.
type StorageProxy struct {
	log *log.Helper
	mc  *oss.MinIOClient
}

// NewStorageProxy creates a new StorageProxy handler.
func NewStorageProxy(ctx *bootstrap.Context, mc *oss.MinIOClient) *StorageProxy {
	return &StorageProxy{
		log: ctx.NewLoggerHelper("storage-proxy/admin-service"),
		mc:  mc,
	}
}

// ServeHTTP implements http.Handler.
// Route format: /{bucket}/{object_key...}
// Example: /images/avatars/abc123.jpg → bucket="images", key="avatars/abc123.jpg"
func (p *StorageProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	slashIdx := strings.Index(path, "/")
	if slashIdx < 0 || slashIdx == len(path)-1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	bucket := path[:slashIdx]
	objectKey := path[slashIdx+1:]

	obj, err := p.mc.GetClient().GetObject(r.Context(), bucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		p.log.Warnf("GetObject error: bucket=%s key=%s err=%v", bucket, objectKey, err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer obj.Close()

	info, err := obj.Stat()
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "NoSuchKey") || strings.Contains(errStr, "not found") {
			w.WriteHeader(http.StatusNotFound)
		} else {
			p.log.Warnf("Stat error: bucket=%s key=%s err=%v", bucket, objectKey, err)
			w.WriteHeader(http.StatusBadGateway)
		}
		return
	}

	w.Header().Set("Content-Type", info.ContentType)
	w.Header().Set("Cache-Control", "public, max-age=604800") // 7 days
	if info.ETag != "" {
		w.Header().Set("ETag", info.ETag)
	}

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	io.Copy(w, obj)
}

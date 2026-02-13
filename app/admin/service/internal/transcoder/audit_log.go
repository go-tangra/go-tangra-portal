package transcoder

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/mileusna/useragent"
	"github.com/tx7do/go-utils/geoip/geolite"
	"github.com/tx7do/go-utils/jwtutil"
	"github.com/tx7do/go-utils/trans"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	auditV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/audit/service/v1"
	authenticationV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/authentication/service/v1"

	appViewer "github.com/go-tangra/go-tangra-portal/pkg/entgo/viewer"
	appJwt "github.com/go-tangra/go-tangra-portal/pkg/jwt"
)

// WriteApiLogFunc is the function type for writing API audit logs.
type WriteApiLogFunc func(ctx context.Context, data *auditV1.ApiAuditLog) error

// maxAuditBodySize limits the request body captured for audit logging.
const maxAuditBodySize = 4096

var auditGeoIPClient *geolite.Client

func init() {
	var err error
	auditGeoIPClient, err = geolite.NewClient()
	if err != nil {
		log.Warnf("Failed to initialize audit GeoIP client: %v", err)
	}
}

// SetWriteApiLogFunc configures the audit log writer function.
func (t *Transcoder) SetWriteApiLogFunc(fn WriteApiLogFunc) {
	t.writeApiLogFunc = fn
}

// bufferRequestBody reads and buffers the request body, restoring it for subsequent reads.
func bufferRequestBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Warnf("Failed to read request body for audit: %v", err)
		return nil
	}
	if err := r.Body.Close(); err != nil {
		log.Warnf("Failed to close request body: %v", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	if len(bodyBytes) > maxAuditBodySize {
		return bodyBytes[:maxAuditBodySize]
	}
	return bodyBytes
}

// writeAuditLog builds and writes an API audit log entry for a transcoded request.
func (t *Transcoder) writeAuditLog(
	ctx context.Context,
	r *http.Request,
	moduleID string,
	method *MethodInfo,
	modulePath string,
	statusCode int,
	reason string,
	latencyMs int64,
	bodyBytes []byte,
) {
	if t.writeApiLogFunc == nil {
		return
	}

	apiLog := &auditV1.ApiAuditLog{}

	clientIP := auditGetClientIP(r)
	referer, _ := url.QueryUnescape(r.Header.Get("Referer"))
	requestURI, _ := url.QueryUnescape(r.RequestURI)

	apiLog.HttpMethod = trans.Ptr(r.Method)
	if method != nil {
		apiLog.ApiOperation = trans.Ptr(fmt.Sprintf("module:%s/%s", moduleID, method.FullName))
	} else {
		apiLog.ApiOperation = trans.Ptr(fmt.Sprintf("module:%s%s", moduleID, modulePath))
	}
	apiLog.Path = trans.Ptr(fmt.Sprintf("/admin/v1/modules/%s%s", moduleID, modulePath))
	apiLog.Referer = trans.Ptr(referer)
	apiLog.IpAddress = trans.Ptr(clientIP)
	apiLog.RequestId = trans.Ptr(auditGetRequestID(r))
	apiLog.RequestUri = trans.Ptr(requestURI)
	apiLog.RequestBody = trans.Ptr(string(bodyBytes))

	ut := auditExtractAuthToken(r)
	if ut != nil {
		apiLog.UserId = trans.Ptr(ut.UserId)
		apiLog.TenantId = ut.TenantId
		apiLog.Username = ut.Username
	}

	apiLog.GeoLocation = auditFillGeoLocation(clientIP)
	apiLog.DeviceInfo = auditFillDeviceInfo(r, ut)

	apiLog.LatencyMs = trans.Ptr(uint32(latencyMs))
	apiLog.StatusCode = trans.Ptr(uint32(statusCode))
	apiLog.Reason = trans.Ptr(reason)
	apiLog.Success = trans.Ptr(statusCode < 400)

	apiLog.LogHash = trans.Ptr(auditHashLog(apiLog))
	apiLog.Signature = auditSignLog(apiLog, t.ecPrivateKey)

	logCtx := appViewer.NewSystemViewerContext(ctx)
	if err := t.writeApiLogFunc(logCtx, apiLog); err != nil {
		t.log.Warnf("Failed to write API audit log for module %s: %v", moduleID, err)
	}
}

// grpcErrorReason extracts a reason string from a gRPC error.
func grpcErrorReason(err error) string {
	if st, ok := status.FromError(err); ok {
		return st.Code().String()
	}
	return "UNKNOWN"
}

// auditExtractAuthToken extracts user token payload from the Authorization header.
func auditExtractAuthToken(r *http.Request) *authenticationV1.UserTokenPayload {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) == 0 {
		return nil
	}

	jwtToken := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := jwtutil.ParseJWTPayload(jwtToken)
	if err != nil {
		log.Errorf("auditExtractAuthToken ParseJWTPayload failed: %v", err)
		return nil
	}

	ut, err := appJwt.NewUserTokenPayloadWithJwtMapClaims(claims)
	if err != nil {
		log.Errorf("auditExtractAuthToken NewUserTokenPayloadWithJwtMapClaims failed: %v", err)
		return nil
	}

	return ut
}

// auditGetClientIP extracts the real client IP from the request.
func auditGetClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, ip := range strings.Split(xff, ",") {
			ip = strings.TrimSpace(ip)
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	if strings.Contains(r.RemoteAddr, ":") {
		host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
		if err == nil && net.ParseIP(host) != nil {
			return host
		}
	}
	if net.ParseIP(r.RemoteAddr) != nil {
		return r.RemoteAddr
	}

	return ""
}

// auditGetRequestID extracts request ID from standard headers.
func auditGetRequestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	if id := r.Header.Get("X-Request-ID"); id != "" {
		return id
	}
	if id := r.Header.Get("X-Correlation-ID"); id != "" {
		return id
	}
	if id := r.Header.Get("x-fc-request-id"); id != "" {
		return id
	}
	return ""
}

// auditGetClientID extracts client ID from request headers or token.
func auditGetClientID(r *http.Request, ut *authenticationV1.UserTokenPayload) string {
	if r == nil {
		return ""
	}
	if id := r.Header.Get("X-Client-IP"); id != "" {
		return id
	}
	if ut != nil {
		return ut.GetClientId()
	}
	return ""
}

// auditFillGeoLocation fills geographic location from client IP.
func auditFillGeoLocation(clientIP string) *auditV1.GeoLocation {
	info := &auditV1.GeoLocation{}

	if auditGeoIPClient == nil {
		return info
	}

	result, err := auditGeoIPClient.Query(clientIP)
	if err != nil {
		return info
	}

	localTerms := []string{"局域网", "本机", "内网", "Local Network", "LAN", "Localhost", "Intranet"}
	isLocal := false
	for _, term := range localTerms {
		if strings.Contains(result.Country, term) || strings.Contains(result.Province, term) || strings.Contains(result.City, term) {
			isLocal = true
			break
		}
	}

	if isLocal {
		info.City = trans.Ptr("Local Network")
		info.Province = trans.Ptr("")
		info.CountryCode = trans.Ptr("")
		info.Isp = trans.Ptr("")
		return info
	}

	info.CountryCode = trans.Ptr(result.Country)
	info.Province = trans.Ptr(result.Province)
	info.City = trans.Ptr(result.City)
	info.Isp = trans.Ptr(result.ISP)

	return info
}

// auditFillDeviceInfo fills device information from request headers.
func auditFillDeviceInfo(r *http.Request, ut *authenticationV1.UserTokenPayload) *auditV1.DeviceInfo {
	info := &auditV1.DeviceInfo{}

	userAgentStr := r.Header.Get("User-Agent")
	ua := useragent.Parse(userAgentStr)
	info.UserAgent = trans.Ptr(ua.String)

	var deviceName string
	if ua.Device != "" {
		deviceName = ua.Device
	} else if ua.Desktop {
		deviceName = "PC"
	}
	info.ClientName = trans.Ptr(deviceName)

	switch {
	case ua.Desktop:
		info.DeviceType = trans.Ptr(auditV1.DeviceInfo_DESKTOP)
	case ua.Tablet:
		info.DeviceType = trans.Ptr(auditV1.DeviceInfo_TABLET)
	case ua.Mobile:
		info.DeviceType = trans.Ptr(auditV1.DeviceInfo_MOBILE)
	case ua.Bot:
		info.DeviceType = trans.Ptr(auditV1.DeviceInfo_BOT)
	default:
		info.DeviceType = trans.Ptr(auditV1.DeviceInfo_OTHER)
	}

	info.BrowserVersion = trans.Ptr(ua.Version)
	info.BrowserName = trans.Ptr(ua.Name)
	info.OsName = trans.Ptr(ua.OS)
	info.OsVersion = trans.Ptr(ua.OSVersion)
	info.Platform = trans.Ptr(auditDetectPlatform(userAgentStr))
	info.ClientId = trans.Ptr(auditGetClientID(r, ut))

	return info
}

// auditDetectPlatform detects the client platform from the User-Agent string.
func auditDetectPlatform(userAgentStr string) string {
	if userAgentStr == "" {
		return "Other"
	}
	s := strings.ToLower(strings.TrimSpace(userAgentStr))

	if strings.Contains(s, "okhttp") || strings.Contains(s, "dalvik") {
		return "AndroidApp"
	}
	if strings.Contains(s, "cfnetwork") || strings.Contains(s, "darwin") {
		return "iOSApp"
	}
	if strings.Contains(s, "electron") || strings.Contains(s, "nwjs") {
		if strings.Contains(s, "windows nt") || strings.Contains(s, "windows") {
			return "DesktopWindows"
		}
		if strings.Contains(s, "macintosh") || strings.Contains(s, "mac os x") {
			return "DesktopMac"
		}
		if strings.Contains(s, "linux") || strings.Contains(s, "x11") {
			return "DesktopLinux"
		}
		return "Other"
	}
	if strings.Contains(s, "mozilla") && !strings.Contains(s, "okhttp") && !strings.Contains(s, "dalvik") && !strings.Contains(s, "cfnetwork") {
		return "Web"
	}
	return "Other"
}

// auditHashLog computes SHA-256 hash of the audit log entry.
func auditHashLog(apiLog *auditV1.ApiAuditLog) string {
	if apiLog == nil {
		return ""
	}

	apiLog.LogHash = nil
	apiLog.Signature = nil

	rawBytes, err := proto.Marshal(apiLog)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(rawBytes)
	return hex.EncodeToString(hash[:])
}

// auditSignLog generates an ECDSA signature for the audit log.
func auditSignLog(apiLog *auditV1.ApiAuditLog, key *ecdsa.PrivateKey) []byte {
	if apiLog == nil || key == nil {
		return nil
	}

	type signContent struct {
		TenantID uint32 `json:"tenant_id"`
		UserID   uint32 `json:"user_id"`
		Sec      int64  `json:"sec"`
		Nanos    int32  `json:"nanos"`
		LogHash  string `json:"log_hash"`
	}

	sc := signContent{
		TenantID: apiLog.GetTenantId(),
		UserID:   apiLog.GetUserId(),
		LogHash:  apiLog.GetLogHash(),
	}
	if apiLog.GetCreatedAt() != nil {
		sc.Sec = apiLog.GetCreatedAt().Seconds
		sc.Nanos = apiLog.GetCreatedAt().Nanos
	}

	scBytes, err := json.Marshal(sc)
	if err != nil {
		return nil
	}

	scHash := sha256.Sum256(scBytes)

	r, s, err := ecdsa.Sign(rand.Reader, key, scHash[:])
	if err != nil {
		return nil
	}

	signBytes, err := auditEncodeDER(r, s)
	if err != nil {
		return nil
	}

	return signBytes
}

// auditEncodeDER encodes ECDSA r, s values to DER format.
func auditEncodeDER(r, s *big.Int) ([]byte, error) {
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	if len(rBytes) > 0 && rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0x00}, rBytes...)
	}
	if len(sBytes) > 0 && sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0x00}, sBytes...)
	}

	der := make([]byte, 0, 6+len(rBytes)+len(sBytes))
	der = append(der, 0x30)
	der = append(der, byte(2+len(rBytes)+2+len(sBytes)))
	der = append(der, 0x02)
	der = append(der, byte(len(rBytes)))
	der = append(der, rBytes...)
	der = append(der, 0x02)
	der = append(der, byte(len(sBytes)))
	der = append(der, sBytes...)

	return der, nil
}

// generateECDSAKeyPair generates an ECDSA key pair for audit log signing.
func generateECDSAKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

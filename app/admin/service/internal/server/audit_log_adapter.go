package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/mileusna/useragent"
	"github.com/tx7do/go-utils/geoip/geolite"
	"github.com/tx7do/go-utils/jwtutil"
	"github.com/tx7do/go-utils/trans"
	"google.golang.org/protobuf/proto"

	auditV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/audit/service/v1"
	authenticationV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/authentication/service/v1"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"

	appViewer "github.com/go-tangra/go-tangra-portal/pkg/entgo/viewer"
	appJwt "github.com/go-tangra/go-tangra-portal/pkg/jwt"

	gatewayTranscoder "github.com/go-tangra/go-tangra-common/gateway/transcoder"
)

var auditGeoIPClient *geolite.Client

func init() {
	var err error
	auditGeoIPClient, err = geolite.NewClient()
	if err != nil {
		log.Warnf("Failed to initialize audit GeoIP client: %v", err)
	}
}

// AuditLogAdapter implements gateway/transcoder.AuditLogWriter
// with portal-specific proto mapping, GeoIP enrichment, device detection, and ECDSA signing.
type AuditLogAdapter struct {
	log          *log.Helper
	repo         *data.ApiAuditLogRepo
	ecPrivateKey *ecdsa.PrivateKey
}

// NewAuditLogAdapter creates a new AuditLogAdapter.
func NewAuditLogAdapter(logger *log.Helper, repo *data.ApiAuditLogRepo) *AuditLogAdapter {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Errorf("Failed to generate ECDSA key pair for audit signing: %v", err)
	}
	return &AuditLogAdapter{
		log:          logger,
		repo:         repo,
		ecPrivateKey: ecKey,
	}
}

// WriteAuditLog implements gateway/transcoder.AuditLogWriter.
func (a *AuditLogAdapter) WriteAuditLog(_ context.Context, entry *gatewayTranscoder.AuditLogEntry) error {
	r := entry.Request
	apiLog := &auditV1.ApiAuditLog{}

	referer, _ := url.QueryUnescape(r.Header.Get("Referer"))
	requestURI, _ := url.QueryUnescape(r.RequestURI)

	apiLog.HttpMethod = trans.Ptr(entry.HTTPMethod)
	if entry.Method != "" {
		apiLog.ApiOperation = trans.Ptr(fmt.Sprintf("module:%s/%s", entry.ModuleID, entry.Method))
	} else {
		apiLog.ApiOperation = trans.Ptr(fmt.Sprintf("module:%s%s", entry.ModuleID, entry.Path))
	}
	apiLog.Path = trans.Ptr(fmt.Sprintf("/admin/v1/modules/%s%s", entry.ModuleID, entry.Path))
	apiLog.Referer = trans.Ptr(referer)
	apiLog.IpAddress = trans.Ptr(entry.ClientIP)
	apiLog.RequestId = trans.Ptr(entry.RequestID)
	apiLog.RequestUri = trans.Ptr(requestURI)
	apiLog.RequestBody = trans.Ptr(string(entry.RequestBody))

	ut := a.extractAuthToken(r)
	if ut != nil {
		apiLog.UserId = trans.Ptr(ut.UserId)
		apiLog.TenantId = ut.TenantId
		apiLog.Username = ut.Username
	}

	apiLog.GeoLocation = a.fillGeoLocation(entry.ClientIP)
	apiLog.DeviceInfo = a.fillDeviceInfo(r, ut)

	apiLog.LatencyMs = trans.Ptr(uint32(entry.LatencyMs))
	apiLog.StatusCode = trans.Ptr(uint32(entry.StatusCode))
	apiLog.Reason = trans.Ptr(entry.Reason)
	apiLog.Success = trans.Ptr(entry.StatusCode < 400)

	apiLog.LogHash = trans.Ptr(auditHashLog(apiLog))
	apiLog.Signature = auditSignLog(apiLog, a.ecPrivateKey)

	logCtx := appViewer.NewSystemViewerContext(context.Background())
	return a.repo.Create(logCtx, &auditV1.CreateApiAuditLogRequest{Data: apiLog})
}

// extractAuthToken extracts user token payload from the Authorization header.
func (a *AuditLogAdapter) extractAuthToken(r *http.Request) *authenticationV1.UserTokenPayload {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) == 0 {
		return nil
	}

	jwtToken := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := jwtutil.ParseJWTPayload(jwtToken)
	if err != nil {
		a.log.Errorf("auditExtractAuthToken ParseJWTPayload failed: %v", err)
		return nil
	}

	ut, err := appJwt.NewUserTokenPayloadWithJwtMapClaims(claims)
	if err != nil {
		a.log.Errorf("auditExtractAuthToken NewUserTokenPayloadWithJwtMapClaims failed: %v", err)
		return nil
	}

	return ut
}

// fillGeoLocation fills geographic location from client IP.
func (a *AuditLogAdapter) fillGeoLocation(clientIP string) *auditV1.GeoLocation {
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

// fillDeviceInfo fills device information from request headers.
func (a *AuditLogAdapter) fillDeviceInfo(r *http.Request, ut *authenticationV1.UserTokenPayload) *auditV1.DeviceInfo {
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

	var clientID string
	if cid := r.Header.Get("X-Client-IP"); cid != "" {
		clientID = cid
	} else if ut != nil {
		clientID = ut.GetClientId()
	}
	info.ClientId = trans.Ptr(clientID)

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

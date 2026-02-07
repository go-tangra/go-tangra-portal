package data

import (
	"context"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	entCrud "github.com/tx7do/go-crud/entgo"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/issuedcertificate"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/issuer"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/lcmclient"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/mtlscertificate"
)

// StatisticsRepo handles statistics-related database queries
type StatisticsRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

// NewStatisticsRepo creates a new StatisticsRepo
func NewStatisticsRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *StatisticsRepo {
	return &StatisticsRepo{
		entClient: entClient,
		log:       ctx.NewLoggerHelper("statistics/repo/lcm-service"),
	}
}

// CertificateStats holds certificate statistics
type CertificateStats struct {
	TotalCount      int64
	ActiveCount     int64
	ExpiredCount    int64
	RevokedCount    int64
	SuspendedCount  int64
	ExpireSoonCount int64
	WildcardCount   int64
	ClientCerts     int64
	InternalCerts   int64
	CaCerts         int64
}

// IssuerCertStats holds certificate statistics for an issuer
type IssuerCertStats struct {
	IssuerName   string
	IssuerType   string
	TotalCount   int64
	ActiveCount  int64
	ExpiredCount int64
	RevokedCount int64
}

// ClientStats holds client statistics
type ClientStats struct {
	TotalCount     int64
	ActiveCount    int64
	DisabledCount  int64
	SuspendedCount int64
	ByStatus       map[string]int64
}

// IssuerStats holds issuer statistics
type IssuerStats struct {
	TotalCount    int64
	ActiveCount   int64
	DisabledCount int64
	ErrorCount    int64
	ByType        map[string]int64
}

// JobStats holds certificate job statistics (using IssuedCertificate)
type JobStats struct {
	TotalCount      int64
	PendingCount    int64
	ProcessingCount int64
	CompletedCount  int64 // "issued" status
	FailedCount     int64
	CancelledCount  int64 // "revoked" can be treated as cancelled in some contexts
}

// IssuedCertificateStats holds statistics for issued certificates (certificates issued to clients)
type IssuedCertificateStats struct {
	TotalCount           int64
	ActiveCount          int64 // status = issued
	ExpiredCount         int64
	RevokedCount         int64
	PendingCount         int64
	ProcessingCount      int64
	FailedCount          int64
	ExpireSoonCount      int64
	WildcardCount        int64
	AutoRenewEnabledCnt  int64
	ByIssuerType         map[string]int64
}

// JobTimeStats holds job statistics for a time period
type JobTimeStats struct {
	Total     int64
	Succeeded int64
	Failed    int64
}

// RecentErrorInfo holds information about a recent error
type RecentErrorInfo struct {
	OccurredAt   time.Time
	JobID        string
	ClientID     string
	CommonName   string
	IssuerName   string
	ErrorMessage string
	TenantID     uint32
}

// GetCertificateStats returns certificate statistics (from MtlsCertificate)
func (r *StatisticsRepo) GetCertificateStats(ctx context.Context, tenantID *uint32, expireSoonDays int) (*CertificateStats, error) {
	stats := &CertificateStats{}

	client := r.entClient.Client()
	now := time.Now()
	expireSoonDeadline := now.AddDate(0, 0, expireSoonDays)

	// Build base query with optional tenant filter
	baseQuery := func() *ent.MtlsCertificateQuery {
		q := client.MtlsCertificate.Query()
		if tenantID != nil {
			q = q.Where(mtlscertificate.TenantIDEQ(*tenantID))
		}
		return q
	}

	// Total count
	total, err := baseQuery().Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.TotalCount = int64(total)

	// Active count
	active, err := baseQuery().Where(mtlscertificate.StatusEQ(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_ACTIVE)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ActiveCount = int64(active)

	// Expired count
	expired, err := baseQuery().Where(mtlscertificate.StatusEQ(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_EXPIRED)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ExpiredCount = int64(expired)

	// Revoked count
	revoked, err := baseQuery().Where(mtlscertificate.StatusEQ(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_REVOKED)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.RevokedCount = int64(revoked)

	// Suspended count
	suspended, err := baseQuery().Where(mtlscertificate.StatusEQ(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_SUSPENDED)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.SuspendedCount = int64(suspended)

	// Expire soon count (active certificates expiring within expireSoonDays)
	expireSoon, err := baseQuery().
		Where(
			mtlscertificate.StatusEQ(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_ACTIVE),
			mtlscertificate.NotAfterLTE(expireSoonDeadline),
			mtlscertificate.NotAfterGT(now),
		).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ExpireSoonCount = int64(expireSoon)

	// Wildcard count (certificates with * in common_name)
	wildcardCount, err := baseQuery().
		Where(mtlscertificate.CommonNameContains("*")).
		Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.WildcardCount = int64(wildcardCount)

	// By type - client certs
	clientCerts, err := baseQuery().
		Where(mtlscertificate.CertTypeEQ(mtlscertificate.CertTypeMTLS_CERT_TYPE_CLIENT)).
		Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ClientCerts = int64(clientCerts)

	// By type - internal certs
	internalCerts, err := baseQuery().
		Where(mtlscertificate.CertTypeEQ(mtlscertificate.CertTypeMTLS_CERT_TYPE_INTERNAL)).
		Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.InternalCerts = int64(internalCerts)

	// CA certs
	caCerts, err := baseQuery().
		Where(mtlscertificate.IsCaEQ(true)).
		Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.CaCerts = int64(caCerts)

	return stats, nil
}

// GetIssuedCertificateStats returns statistics for issued certificates (certificates issued to clients)
func (r *StatisticsRepo) GetIssuedCertificateStats(ctx context.Context, tenantID *uint32, expireSoonDays int) (*IssuedCertificateStats, error) {
	stats := &IssuedCertificateStats{
		ByIssuerType: make(map[string]int64),
	}

	client := r.entClient.Client()
	now := time.Now()
	expireSoonDeadline := now.AddDate(0, 0, expireSoonDays)

	// Build base query with optional tenant filter
	baseQuery := func() *ent.IssuedCertificateQuery {
		q := client.IssuedCertificate.Query()
		if tenantID != nil {
			q = q.Where(issuedcertificate.TenantIDEQ(*tenantID))
		}
		return q
	}

	// Total count
	total, err := baseQuery().Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.TotalCount = int64(total)

	// Active count (issued status)
	active, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusIssued)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ActiveCount = int64(active)

	// Expired count
	expired, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusExpired)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ExpiredCount = int64(expired)

	// Revoked count
	revoked, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusRevoked)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.RevokedCount = int64(revoked)

	// Pending count
	pending, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusPending)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.PendingCount = int64(pending)

	// Processing count
	processing, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusProcessing)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ProcessingCount = int64(processing)

	// Failed count
	failed, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusFailed)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.FailedCount = int64(failed)

	// Expire soon count (issued certificates expiring within expireSoonDays)
	expireSoon, err := baseQuery().
		Where(
			issuedcertificate.StatusEQ(issuedcertificate.StatusIssued),
			issuedcertificate.ExpiresAtLTE(expireSoonDeadline),
			issuedcertificate.ExpiresAtGT(now),
		).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ExpireSoonCount = int64(expireSoon)

	// Wildcard count (certificates with domains containing *)
	// Query all issued certificates and check domains field
	issuedCerts, err := baseQuery().All(ctx)
	if err != nil {
		return nil, err
	}

	for _, cert := range issuedCerts {
		// Check for wildcard in common name
		if strings.Contains(cert.CommonName, "*") {
			stats.WildcardCount++
		} else if isWildcardDomain(cert.Domains) {
			stats.WildcardCount++
		}

		// Count auto-renew enabled
		if cert.AutoRenewEnabled {
			stats.AutoRenewEnabledCnt++
		}

		// Count by issuer type
		issuerType := cert.IssuerType
		if issuerType == "" {
			issuerType = "unknown"
		}
		stats.ByIssuerType[issuerType]++
	}

	return stats, nil
}

// GetCertificateStatsByIssuer returns certificate statistics grouped by issuer
// This queries both MtlsCertificate (internal mTLS certs) and IssuedCertificate (external issued certs)
func (r *StatisticsRepo) GetCertificateStatsByIssuer(ctx context.Context, tenantID *uint32) ([]*IssuerCertStats, error) {
	client := r.entClient.Client()
	statsMap := make(map[string]*IssuerCertStats)

	// First, get stats from MtlsCertificate table (grouped by issuer_name)
	mtlsCerts, err := client.MtlsCertificate.Query().All(ctx)
	if err == nil {
		for _, cert := range mtlsCerts {
			if tenantID != nil && cert.TenantID != nil && *cert.TenantID != *tenantID {
				continue
			}
			issuerName := cert.IssuerName
			if issuerName == "" {
				issuerName = "unknown"
			}

			if _, exists := statsMap[issuerName]; !exists {
				statsMap[issuerName] = &IssuerCertStats{
					IssuerName: issuerName,
					IssuerType: "internal",
				}
			}

			statsMap[issuerName].TotalCount++
			if cert.Status != nil {
				switch *cert.Status {
				case mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_ACTIVE:
					statsMap[issuerName].ActiveCount++
				case mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_EXPIRED:
					statsMap[issuerName].ExpiredCount++
				case mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_REVOKED:
					statsMap[issuerName].RevokedCount++
				}
			}
		}
	}

	// Then, get stats from IssuedCertificate table (external issuers)
	issuedCerts, err := client.IssuedCertificate.Query().All(ctx)
	if err == nil {
		for _, cert := range issuedCerts {
			if tenantID != nil && cert.TenantID != *tenantID {
				continue
			}
			issuerName := cert.IssuerName
			if issuerName == "" {
				issuerName = "unknown"
			}

			if _, exists := statsMap[issuerName]; !exists {
				issuerType := "external"
				if cert.IssuerType != "" {
					issuerType = cert.IssuerType
				}
				statsMap[issuerName] = &IssuerCertStats{
					IssuerName: issuerName,
					IssuerType: issuerType,
				}
			}

			statsMap[issuerName].TotalCount++
			switch cert.Status {
			case issuedcertificate.StatusIssued:
				statsMap[issuerName].ActiveCount++
			case issuedcertificate.StatusExpired:
				statsMap[issuerName].ExpiredCount++
			case issuedcertificate.StatusRevoked:
				statsMap[issuerName].RevokedCount++
			}
		}
	}

	// Convert map to slice
	stats := make([]*IssuerCertStats, 0, len(statsMap))
	for _, s := range statsMap {
		stats = append(stats, s)
	}

	return stats, nil
}

// GetClientStats returns client statistics
func (r *StatisticsRepo) GetClientStats(ctx context.Context, tenantID *uint32) (*ClientStats, error) {
	stats := &ClientStats{
		ByStatus: make(map[string]int64),
	}

	client := r.entClient.Client()

	baseQuery := func() *ent.LcmClientQuery {
		q := client.LcmClient.Query()
		if tenantID != nil {
			q = q.Where(lcmclient.TenantIDEQ(*tenantID))
		}
		return q
	}

	// Total count
	total, err := baseQuery().Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.TotalCount = int64(total)

	// Active count
	active, err := baseQuery().Where(lcmclient.StatusEQ(lcmclient.StatusLCM_CLIENT_ACTIVE)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ActiveCount = int64(active)
	stats.ByStatus["active"] = int64(active)

	// Disabled count
	disabled, err := baseQuery().Where(lcmclient.StatusEQ(lcmclient.StatusLCM_CLIENT_DISABLED)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.DisabledCount = int64(disabled)
	stats.ByStatus["disabled"] = int64(disabled)

	// Suspended count
	suspended, err := baseQuery().Where(lcmclient.StatusEQ(lcmclient.StatusLCM_CLIENT_SUSPENDED)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.SuspendedCount = int64(suspended)
	stats.ByStatus["suspended"] = int64(suspended)

	// Unspecified count
	unspecified, err := baseQuery().Where(lcmclient.StatusEQ(lcmclient.StatusLCM_CLIENT_UNSPECIFIED)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ByStatus["unspecified"] = int64(unspecified)

	return stats, nil
}

// GetIssuerStats returns issuer statistics
func (r *StatisticsRepo) GetIssuerStats(ctx context.Context, tenantID *uint32) (*IssuerStats, error) {
	stats := &IssuerStats{
		ByType: make(map[string]int64),
	}

	client := r.entClient.Client()

	baseQuery := func() *ent.IssuerQuery {
		q := client.Issuer.Query()
		if tenantID != nil {
			q = q.Where(issuer.TenantIDEQ(*tenantID))
		}
		return q
	}

	// Total count
	total, err := baseQuery().Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.TotalCount = int64(total)

	// Active count
	active, err := baseQuery().Where(issuer.StatusEQ(issuer.StatusISSUER_STATUS_ACTIVE)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ActiveCount = int64(active)

	// Disabled count
	disabled, err := baseQuery().Where(issuer.StatusEQ(issuer.StatusISSUER_STATUS_DISABLED)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.DisabledCount = int64(disabled)

	// Error count
	errorCount, err := baseQuery().Where(issuer.StatusEQ(issuer.StatusISSUER_STATUS_ERROR)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ErrorCount = int64(errorCount)

	// Get all issuers to count by type
	issuers, err := baseQuery().All(ctx)
	if err != nil {
		return nil, err
	}

	for _, iss := range issuers {
		issType := string(iss.Type)
		stats.ByType[issType]++
	}

	return stats, nil
}

// GetJobStats returns certificate job statistics (using IssuedCertificate)
func (r *StatisticsRepo) GetJobStats(ctx context.Context, tenantID *uint32) (*JobStats, error) {
	stats := &JobStats{}

	client := r.entClient.Client()

	baseQuery := func() *ent.IssuedCertificateQuery {
		q := client.IssuedCertificate.Query()
		if tenantID != nil {
			q = q.Where(issuedcertificate.TenantIDEQ(*tenantID))
		}
		return q
	}

	// Total count
	total, err := baseQuery().Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.TotalCount = int64(total)

	// Pending count
	pending, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusPending)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.PendingCount = int64(pending)

	// Processing count
	processing, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusProcessing)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ProcessingCount = int64(processing)

	// Completed count (issued status)
	completed, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusIssued)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.CompletedCount = int64(completed)

	// Failed count
	failed, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusFailed)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.FailedCount = int64(failed)

	// Cancelled count (revoked status)
	cancelled, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusRevoked)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.CancelledCount = int64(cancelled)

	return stats, nil
}

// GetJobTimeStats returns job statistics for a time period (using IssuedCertificate)
func (r *StatisticsRepo) GetJobTimeStats(ctx context.Context, tenantID *uint32, since time.Time) (*JobTimeStats, error) {
	stats := &JobTimeStats{}

	client := r.entClient.Client()

	baseQuery := func() *ent.IssuedCertificateQuery {
		q := client.IssuedCertificate.Query().Where(issuedcertificate.CreatedAtGTE(since))
		if tenantID != nil {
			q = q.Where(issuedcertificate.TenantIDEQ(*tenantID))
		}
		return q
	}

	// Total count
	total, err := baseQuery().Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.Total = int64(total)

	// Succeeded (issued)
	succeeded, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusIssued)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.Succeeded = int64(succeeded)

	// Failed
	failed, err := baseQuery().Where(issuedcertificate.StatusEQ(issuedcertificate.StatusFailed)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.Failed = int64(failed)

	return stats, nil
}

// GetRecentErrors returns recent certificate issuance errors (using IssuedCertificate)
func (r *StatisticsRepo) GetRecentErrors(ctx context.Context, tenantID *uint32, limit int) ([]*RecentErrorInfo, error) {
	client := r.entClient.Client()

	query := client.IssuedCertificate.Query().
		Where(issuedcertificate.StatusEQ(issuedcertificate.StatusFailed)).
		Order(ent.Desc(issuedcertificate.FieldUpdatedAt)).
		Limit(limit)

	if tenantID != nil {
		query = query.Where(issuedcertificate.TenantIDEQ(*tenantID))
	}

	certs, err := query.All(ctx)
	if err != nil {
		return nil, err
	}

	errors := make([]*RecentErrorInfo, 0, len(certs))
	for _, cert := range certs {
		errors = append(errors, &RecentErrorInfo{
			OccurredAt:   cert.UpdatedAt,
			JobID:        cert.ID,
			ClientID:     cert.ClientID,
			CommonName:   cert.CommonName,
			IssuerName:   cert.IssuerName,
			ErrorMessage: cert.ErrorMessage,
			TenantID:     cert.TenantID,
		})
	}

	return errors, nil
}

// GetTenantIDs returns all distinct tenant IDs
func (r *StatisticsRepo) GetTenantIDs(ctx context.Context) ([]uint32, error) {
	client := r.entClient.Client()
	seen := make(map[uint32]bool)
	tenantIDs := make([]uint32, 0)

	// Get tenant IDs from IssuedCertificate (TenantID is uint32, not pointer)
	certs, err := client.IssuedCertificate.Query().All(ctx)
	if err == nil {
		for _, cert := range certs {
			if cert.TenantID > 0 && !seen[cert.TenantID] {
				seen[cert.TenantID] = true
				tenantIDs = append(tenantIDs, cert.TenantID)
			}
		}
	}

	// Get tenant IDs from LcmClient (TenantID is *uint32, pointer)
	clients, err := client.LcmClient.Query().All(ctx)
	if err == nil {
		for _, c := range clients {
			if c.TenantID != nil && !seen[*c.TenantID] {
				seen[*c.TenantID] = true
				tenantIDs = append(tenantIDs, *c.TenantID)
			}
		}
	}

	// Get tenant IDs from MtlsCertificate (TenantID is *uint32, pointer)
	mtlsCerts, err := client.MtlsCertificate.Query().All(ctx)
	if err == nil {
		for _, cert := range mtlsCerts {
			if cert.TenantID != nil && !seen[*cert.TenantID] {
				seen[*cert.TenantID] = true
				tenantIDs = append(tenantIDs, *cert.TenantID)
			}
		}
	}

	return tenantIDs, nil
}

// isWildcardDomain checks if any domain in the list is a wildcard
func isWildcardDomain(domains []string) bool {
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") || strings.Contains(d, "*") {
			return true
		}
	}
	return false
}

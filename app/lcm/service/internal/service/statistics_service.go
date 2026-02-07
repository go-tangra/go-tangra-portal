package service

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
)

// StatisticsService implements the LcmStatisticsService gRPC service
type StatisticsService struct {
	lcmV1.UnimplementedLcmStatisticsServiceServer

	statsRepo *data.StatisticsRepo
	log       *log.Helper
}

// NewStatisticsService creates a new StatisticsService
func NewStatisticsService(ctx *bootstrap.Context, statsRepo *data.StatisticsRepo) *StatisticsService {
	return &StatisticsService{
		statsRepo: statsRepo,
		log:       ctx.NewLoggerHelper("lcm/service/statistics"),
	}
}

// GetStatistics returns comprehensive statistics about the LCM system
func (s *StatisticsService) GetStatistics(ctx context.Context, req *lcmV1.GetStatisticsRequest) (*lcmV1.GetStatisticsResponse, error) {
	s.log.Info("GetStatistics called")

	// Set defaults
	expireSoonDays := int32(30)
	if req.ExpireSoonDays != nil {
		expireSoonDays = *req.ExpireSoonDays
	}

	recentErrorsLimit := int32(10)
	if req.RecentErrorsLimit != nil {
		recentErrorsLimit = *req.RecentErrorsLimit
	}

	// Optional tenant filter
	var tenantID *uint32
	if req.TenantId != nil {
		tenantID = req.TenantId
	}

	response := &lcmV1.GetStatisticsResponse{
		GeneratedAt: timestamppb.Now(),
	}

	// Get MTLS certificate statistics (for mTLS authentication - internal use)
	mtlsCertStats, err := s.statsRepo.GetCertificateStats(ctx, tenantID, int(expireSoonDays))
	if err != nil {
		s.log.Errorf("Failed to get mTLS certificate stats: %v", err)
	} else {
		response.MtlsCertificates = &lcmV1.MtlsCertificateStatistics{
			TotalCount:      mtlsCertStats.TotalCount,
			ActiveCount:     mtlsCertStats.ActiveCount,
			ExpiredCount:    mtlsCertStats.ExpiredCount,
			RevokedCount:    mtlsCertStats.RevokedCount,
			SuspendedCount:  mtlsCertStats.SuspendedCount,
			ExpireSoonCount: mtlsCertStats.ExpireSoonCount,
			ExpireSoonDays:  expireSoonDays,
			ByType: &lcmV1.CertificateTypeBreakdown{
				ClientCerts:   mtlsCertStats.ClientCerts,
				InternalCerts: mtlsCertStats.InternalCerts,
				CaCerts:       mtlsCertStats.CaCerts,
			},
		}

		// Also populate the deprecated certificates field for backward compatibility
		// Get certificate stats by issuer
		byIssuer, err := s.statsRepo.GetCertificateStatsByIssuer(ctx, tenantID)
		if err != nil {
			s.log.Errorf("Failed to get certificate stats by issuer: %v", err)
		}

		issuerCounts := make([]*lcmV1.IssuerCertificateCount, 0, len(byIssuer))
		for _, is := range byIssuer {
			issuerCounts = append(issuerCounts, &lcmV1.IssuerCertificateCount{
				IssuerName:   is.IssuerName,
				IssuerType:   is.IssuerType,
				TotalCount:   is.TotalCount,
				ActiveCount:  is.ActiveCount,
				ExpiredCount: is.ExpiredCount,
				RevokedCount: is.RevokedCount,
			})
		}

		response.Certificates = &lcmV1.CertificateStatistics{
			TotalCount:      mtlsCertStats.TotalCount,
			ActiveCount:     mtlsCertStats.ActiveCount,
			ExpiredCount:    mtlsCertStats.ExpiredCount,
			RevokedCount:    mtlsCertStats.RevokedCount,
			SuspendedCount:  mtlsCertStats.SuspendedCount,
			ExpireSoonCount: mtlsCertStats.ExpireSoonCount,
			ExpireSoonDays:  expireSoonDays,
			WildcardCount:   mtlsCertStats.WildcardCount,
			ByType: &lcmV1.CertificateTypeBreakdown{
				ClientCerts:   mtlsCertStats.ClientCerts,
				InternalCerts: mtlsCertStats.InternalCerts,
				CaCerts:       mtlsCertStats.CaCerts,
			},
			ByIssuer: issuerCounts,
		}
	}

	// Get Issued certificate statistics (certificates issued to clients - the main certificates)
	issuedCertStats, err := s.statsRepo.GetIssuedCertificateStats(ctx, tenantID, int(expireSoonDays))
	if err != nil {
		s.log.Errorf("Failed to get issued certificate stats: %v", err)
	} else {
		response.IssuedCertificates = &lcmV1.IssuedCertificateStatistics{
			TotalCount:           issuedCertStats.TotalCount,
			ActiveCount:          issuedCertStats.ActiveCount,
			ExpiredCount:         issuedCertStats.ExpiredCount,
			RevokedCount:         issuedCertStats.RevokedCount,
			PendingCount:         issuedCertStats.PendingCount,
			ProcessingCount:      issuedCertStats.ProcessingCount,
			FailedCount:          issuedCertStats.FailedCount,
			ExpireSoonCount:      issuedCertStats.ExpireSoonCount,
			ExpireSoonDays:       expireSoonDays,
			WildcardCount:        issuedCertStats.WildcardCount,
			AutoRenewEnabledCount: issuedCertStats.AutoRenewEnabledCnt,
			ByIssuerType:         issuedCertStats.ByIssuerType,
		}
	}

	// Get client statistics
	clientStats, err := s.statsRepo.GetClientStats(ctx, tenantID)
	if err != nil {
		s.log.Errorf("Failed to get client stats: %v", err)
	} else {
		response.Clients = &lcmV1.ClientStatistics{
			TotalCount:     clientStats.TotalCount,
			ActiveCount:    clientStats.ActiveCount,
			DisabledCount:  clientStats.DisabledCount,
			SuspendedCount: clientStats.SuspendedCount,
			ByStatus:       clientStats.ByStatus,
		}
	}

	// Get issuer statistics
	issuerStats, err := s.statsRepo.GetIssuerStats(ctx, tenantID)
	if err != nil {
		s.log.Errorf("Failed to get issuer stats: %v", err)
	} else {
		response.Issuers = &lcmV1.IssuerStatistics{
			TotalCount:    issuerStats.TotalCount,
			ActiveCount:   issuerStats.ActiveCount,
			DisabledCount: issuerStats.DisabledCount,
			ErrorCount:    issuerStats.ErrorCount,
			ByType:        issuerStats.ByType,
		}
	}

	// Get job statistics
	jobStats, err := s.statsRepo.GetJobStats(ctx, tenantID)
	if err != nil {
		s.log.Errorf("Failed to get job stats: %v", err)
	} else {
		// Get time-based stats
		last24Hours := time.Now().Add(-24 * time.Hour)
		last7Days := time.Now().Add(-7 * 24 * time.Hour)

		stats24h, _ := s.statsRepo.GetJobTimeStats(ctx, tenantID, last24Hours)
		stats7d, _ := s.statsRepo.GetJobTimeStats(ctx, tenantID, last7Days)

		response.Jobs = &lcmV1.JobStatistics{
			TotalCount:      jobStats.TotalCount,
			PendingCount:    jobStats.PendingCount,
			ProcessingCount: jobStats.ProcessingCount,
			CompletedCount:  jobStats.CompletedCount,
			FailedCount:     jobStats.FailedCount,
			CancelledCount:  jobStats.CancelledCount,
		}

		if stats24h != nil {
			successRate := float64(0)
			if stats24h.Total > 0 {
				successRate = float64(stats24h.Succeeded) / float64(stats24h.Total) * 100
			}
			response.Jobs.Last_24Hours = &lcmV1.JobTimeBreakdown{
				Total:       stats24h.Total,
				Succeeded:   stats24h.Succeeded,
				Failed:      stats24h.Failed,
				SuccessRate: successRate,
			}
		}

		if stats7d != nil {
			successRate := float64(0)
			if stats7d.Total > 0 {
				successRate = float64(stats7d.Succeeded) / float64(stats7d.Total) * 100
			}
			response.Jobs.Last_7Days = &lcmV1.JobTimeBreakdown{
				Total:       stats7d.Total,
				Succeeded:   stats7d.Succeeded,
				Failed:      stats7d.Failed,
				SuccessRate: successRate,
			}
		}
	}

	// Get recent errors
	recentErrors, err := s.statsRepo.GetRecentErrors(ctx, tenantID, int(recentErrorsLimit))
	if err != nil {
		s.log.Errorf("Failed to get recent errors: %v", err)
	} else {
		response.RecentErrors = make([]*lcmV1.RecentError, 0, len(recentErrors))
		for _, e := range recentErrors {
			response.RecentErrors = append(response.RecentErrors, &lcmV1.RecentError{
				OccurredAt:   timestamppb.New(e.OccurredAt),
				JobId:        e.JobID,
				ClientId:     e.ClientID,
				CommonName:   e.CommonName,
				IssuerName:   e.IssuerName,
				ErrorMessage: e.ErrorMessage,
				TenantId:     e.TenantID,
			})
		}
	}

	// Get tenant breakdown (only if no specific tenant filter is applied)
	if tenantID == nil {
		tenantIDs, err := s.statsRepo.GetTenantIDs(ctx)
		if err != nil {
			s.log.Errorf("Failed to get tenant IDs: %v", err)
		} else {
			response.TenantBreakdown = make([]*lcmV1.TenantStatistics, 0, len(tenantIDs))
			for _, tid := range tenantIDs {
				tenantStats, err := s.getTenantStatistics(ctx, tid, int(expireSoonDays))
				if err != nil {
					s.log.Errorf("Failed to get tenant stats for tenant %d: %v", tid, err)
					continue
				}
				response.TenantBreakdown = append(response.TenantBreakdown, tenantStats)
			}
		}
	}

	return response, nil
}

// GetTenantStatistics returns statistics for a specific tenant
func (s *StatisticsService) GetTenantStatistics(ctx context.Context, req *lcmV1.GetTenantStatisticsRequest) (*lcmV1.TenantStatistics, error) {
	s.log.Infof("GetTenantStatistics called for tenant %d", req.TenantId)

	expireSoonDays := int32(30)
	if req.ExpireSoonDays != nil {
		expireSoonDays = *req.ExpireSoonDays
	}

	return s.getTenantStatistics(ctx, req.TenantId, int(expireSoonDays))
}

// getTenantStatistics is a helper function to get statistics for a specific tenant
func (s *StatisticsService) getTenantStatistics(ctx context.Context, tenantID uint32, expireSoonDays int) (*lcmV1.TenantStatistics, error) {
	tid := tenantID
	result := &lcmV1.TenantStatistics{
		TenantId: tenantID,
	}

	// Get mTLS certificate statistics
	mtlsCertStats, err := s.statsRepo.GetCertificateStats(ctx, &tid, expireSoonDays)
	if err == nil {
		result.MtlsCertificates = &lcmV1.MtlsCertificateStatistics{
			TotalCount:      mtlsCertStats.TotalCount,
			ActiveCount:     mtlsCertStats.ActiveCount,
			ExpiredCount:    mtlsCertStats.ExpiredCount,
			RevokedCount:    mtlsCertStats.RevokedCount,
			SuspendedCount:  mtlsCertStats.SuspendedCount,
			ExpireSoonCount: mtlsCertStats.ExpireSoonCount,
			ExpireSoonDays:  int32(expireSoonDays),
			ByType: &lcmV1.CertificateTypeBreakdown{
				ClientCerts:   mtlsCertStats.ClientCerts,
				InternalCerts: mtlsCertStats.InternalCerts,
				CaCerts:       mtlsCertStats.CaCerts,
			},
		}

		// Also populate deprecated certificates field for backward compatibility
		result.Certificates = &lcmV1.CertificateStatistics{
			TotalCount:      mtlsCertStats.TotalCount,
			ActiveCount:     mtlsCertStats.ActiveCount,
			ExpiredCount:    mtlsCertStats.ExpiredCount,
			RevokedCount:    mtlsCertStats.RevokedCount,
			SuspendedCount:  mtlsCertStats.SuspendedCount,
			ExpireSoonCount: mtlsCertStats.ExpireSoonCount,
			ExpireSoonDays:  int32(expireSoonDays),
			WildcardCount:   mtlsCertStats.WildcardCount,
			ByType: &lcmV1.CertificateTypeBreakdown{
				ClientCerts:   mtlsCertStats.ClientCerts,
				InternalCerts: mtlsCertStats.InternalCerts,
				CaCerts:       mtlsCertStats.CaCerts,
			},
		}
	}

	// Get issued certificate statistics
	issuedCertStats, err := s.statsRepo.GetIssuedCertificateStats(ctx, &tid, expireSoonDays)
	if err == nil {
		result.IssuedCertificates = &lcmV1.IssuedCertificateStatistics{
			TotalCount:            issuedCertStats.TotalCount,
			ActiveCount:           issuedCertStats.ActiveCount,
			ExpiredCount:          issuedCertStats.ExpiredCount,
			RevokedCount:          issuedCertStats.RevokedCount,
			PendingCount:          issuedCertStats.PendingCount,
			ProcessingCount:       issuedCertStats.ProcessingCount,
			FailedCount:           issuedCertStats.FailedCount,
			ExpireSoonCount:       issuedCertStats.ExpireSoonCount,
			ExpireSoonDays:        int32(expireSoonDays),
			WildcardCount:         issuedCertStats.WildcardCount,
			AutoRenewEnabledCount: issuedCertStats.AutoRenewEnabledCnt,
			ByIssuerType:          issuedCertStats.ByIssuerType,
		}
	}

	// Get client statistics
	clientStats, err := s.statsRepo.GetClientStats(ctx, &tid)
	if err == nil {
		result.Clients = &lcmV1.ClientStatistics{
			TotalCount:     clientStats.TotalCount,
			ActiveCount:    clientStats.ActiveCount,
			DisabledCount:  clientStats.DisabledCount,
			SuspendedCount: clientStats.SuspendedCount,
			ByStatus:       clientStats.ByStatus,
		}
	}

	// Get issuer statistics
	issuerStats, err := s.statsRepo.GetIssuerStats(ctx, &tid)
	if err == nil {
		result.Issuers = &lcmV1.IssuerStatistics{
			TotalCount:    issuerStats.TotalCount,
			ActiveCount:   issuerStats.ActiveCount,
			DisabledCount: issuerStats.DisabledCount,
			ErrorCount:    issuerStats.ErrorCount,
			ByType:        issuerStats.ByType,
		}
	}

	// Get job statistics
	jobStats, err := s.statsRepo.GetJobStats(ctx, &tid)
	if err == nil {
		result.Jobs = &lcmV1.JobStatistics{
			TotalCount:      jobStats.TotalCount,
			PendingCount:    jobStats.PendingCount,
			ProcessingCount: jobStats.ProcessingCount,
			CompletedCount:  jobStats.CompletedCount,
			FailedCount:     jobStats.FailedCount,
			CancelledCount:  jobStats.CancelledCount,
		}
	}

	return result, nil
}

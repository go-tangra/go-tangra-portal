package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/pkg/middleware/auth"
)

// TimeSeriesStatisticsService implements TimescaleDB-powered time-series analytics.
type TimeSeriesStatisticsService struct {
	adminV1.UnimplementedTimeSeriesStatisticsServiceServer
	log            *log.Helper
	timeSeriesRepo *data.TimeSeriesRepo
}

// NewTimeSeriesStatisticsService creates a new TimeSeriesStatisticsService.
func NewTimeSeriesStatisticsService(
	ctx *bootstrap.Context,
	timeSeriesRepo *data.TimeSeriesRepo,
) *TimeSeriesStatisticsService {
	return &TimeSeriesStatisticsService{
		log:            ctx.NewLoggerHelper("time-series-statistics/admin-service"),
		timeSeriesRepo: timeSeriesRepo,
	}
}

func getTenantID(ctx context.Context) uint32 {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return 0
	}
	return operator.GetTenantId()
}

func getInterval(req *adminV1.TimeSeriesRequest) string {
	if req != nil && req.Interval != nil {
		return *req.Interval
	}
	return "1h"
}

func getRange(req *adminV1.TimeSeriesRequest) string {
	if req != nil && req.Range != nil {
		return *req.Range
	}
	return "7d"
}

// bucketsToResponse converts TimeSeriesBucket slice to proto response.
func bucketsToResponse(buckets []data.TimeSeriesBucket, interval string) *adminV1.TimeSeriesDataResponse {
	resp := &adminV1.TimeSeriesDataResponse{
		Interval: interval,
		Series:   make(map[string]*adminV1.DoubleSeries),
	}

	if len(buckets) == 0 {
		return resp
	}

	// Discover series names from first bucket
	seriesNames := make([]string, 0)
	for name := range buckets[0].Values {
		seriesNames = append(seriesNames, name)
	}

	// Initialize series
	for _, name := range seriesNames {
		resp.Series[name] = &adminV1.DoubleSeries{
			Values: make([]float64, 0, len(buckets)),
		}
	}

	// Fill data
	for _, b := range buckets {
		resp.Buckets = append(resp.Buckets, b.Bucket.Format("2006-01-02T15:04:05Z"))
		for _, name := range seriesNames {
			resp.Series[name].Values = append(resp.Series[name].Values, b.Values[name])
		}
	}

	return resp
}

// GetApiRequestVolume returns API request counts over time.
func (s *TimeSeriesStatisticsService) GetApiRequestVolume(ctx context.Context, req *adminV1.TimeSeriesRequest) (*adminV1.TimeSeriesDataResponse, error) {
	tenantID := getTenantID(ctx)
	interval := getInterval(req)
	rangeStr := getRange(req)

	buckets, err := s.timeSeriesRepo.QueryApiRequestVolume(ctx, interval, rangeStr, tenantID)
	if err != nil {
		s.log.Errorf("GetApiRequestVolume failed: %v", err)
		return bucketsToResponse(nil, interval), nil
	}

	return bucketsToResponse(buckets, interval), nil
}

// GetApiLatencyPercentiles returns p50/p95/p99 latency over time.
func (s *TimeSeriesStatisticsService) GetApiLatencyPercentiles(ctx context.Context, req *adminV1.TimeSeriesRequest) (*adminV1.TimeSeriesDataResponse, error) {
	tenantID := getTenantID(ctx)
	interval := getInterval(req)
	rangeStr := getRange(req)

	buckets, err := s.timeSeriesRepo.QueryApiLatencyPercentiles(ctx, interval, rangeStr, tenantID)
	if err != nil {
		s.log.Errorf("GetApiLatencyPercentiles failed: %v", err)
		return bucketsToResponse(nil, interval), nil
	}

	return bucketsToResponse(buckets, interval), nil
}

// GetLoginActivity returns login success/failure counts over time.
func (s *TimeSeriesStatisticsService) GetLoginActivity(ctx context.Context, req *adminV1.TimeSeriesRequest) (*adminV1.TimeSeriesDataResponse, error) {
	tenantID := getTenantID(ctx)
	interval := getInterval(req)
	rangeStr := getRange(req)

	buckets, err := s.timeSeriesRepo.QueryLoginActivity(ctx, interval, rangeStr, tenantID)
	if err != nil {
		s.log.Errorf("GetLoginActivity failed: %v", err)
		return bucketsToResponse(nil, interval), nil
	}

	return bucketsToResponse(buckets, interval), nil
}

// GetActiveUsers returns unique active user counts over time.
func (s *TimeSeriesStatisticsService) GetActiveUsers(ctx context.Context, req *adminV1.TimeSeriesRequest) (*adminV1.TimeSeriesDataResponse, error) {
	tenantID := getTenantID(ctx)
	interval := getInterval(req)
	rangeStr := getRange(req)

	buckets, err := s.timeSeriesRepo.QueryActiveUsers(ctx, interval, rangeStr, tenantID)
	if err != nil {
		s.log.Errorf("GetActiveUsers failed: %v", err)
		return bucketsToResponse(nil, interval), nil
	}

	return bucketsToResponse(buckets, interval), nil
}

// GetLoginHeatmap returns login activity as an hour×day heatmap.
func (s *TimeSeriesStatisticsService) GetLoginHeatmap(ctx context.Context, req *adminV1.HeatmapRequest) (*adminV1.HeatmapResponse, error) {
	tenantID := getTenantID(ctx)
	rangeStr := "30d"
	if req != nil && req.Range != nil {
		rangeStr = *req.Range
	}

	cells, maxVal, err := s.timeSeriesRepo.QueryLoginHeatmap(ctx, rangeStr, tenantID)
	if err != nil {
		s.log.Errorf("GetLoginHeatmap failed: %v", err)
		return &adminV1.HeatmapResponse{}, nil
	}

	resp := &adminV1.HeatmapResponse{
		Hours:    make([]int32, 24),
		Days:     []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
		MaxValue: maxVal,
	}

	for i := int32(0); i < 24; i++ {
		resp.Hours[i] = i
	}

	for _, c := range cells {
		resp.Data = append(resp.Data, &adminV1.HeatmapCell{
			Hour:  int32(c.Hour),
			Day:   int32(c.Day),
			Value: c.Value,
		})
	}

	return resp, nil
}

// GetTopEndpoints returns most-used API endpoints.
func (s *TimeSeriesStatisticsService) GetTopEndpoints(ctx context.Context, req *adminV1.TopEndpointsRequest) (*adminV1.TopEndpointsResponse, error) {
	tenantID := getTenantID(ctx)
	rangeStr := "7d"
	limit := 10
	if req != nil {
		if req.Range != nil {
			rangeStr = *req.Range
		}
		if req.Limit != nil {
			limit = int(*req.Limit)
		}
	}

	endpoints, err := s.timeSeriesRepo.QueryTopEndpoints(ctx, rangeStr, limit, tenantID)
	if err != nil {
		s.log.Errorf("GetTopEndpoints failed: %v", err)
		return &adminV1.TopEndpointsResponse{}, nil
	}

	resp := &adminV1.TopEndpointsResponse{}
	for _, e := range endpoints {
		resp.Endpoints = append(resp.Endpoints, &adminV1.EndpointStats{
			Path:          e.Path,
			Method:        e.Method,
			Module:        e.Module,
			TotalRequests: e.TotalReqs,
			AvgLatencyMs:  e.AvgLatencyMs,
			P95LatencyMs:  e.P95LatencyMs,
			ErrorRate:     e.ErrorRate,
			ErrorCount:    e.ErrorCount,
			SuccessCount:  e.SuccessCount,
		})
	}

	return resp, nil
}

// GetSecurityOverview returns security-related trend metrics.
func (s *TimeSeriesStatisticsService) GetSecurityOverview(ctx context.Context, _ *adminV1.SecurityOverviewRequest) (*adminV1.SecurityOverviewResponse, error) {
	tenantID := getTenantID(ctx)

	metrics, err := s.timeSeriesRepo.QuerySecurityOverview(ctx, tenantID)
	if err != nil {
		s.log.Errorf("GetSecurityOverview failed: %v", err)
		return &adminV1.SecurityOverviewResponse{}, nil
	}

	resp := &adminV1.SecurityOverviewResponse{
		Value:           metrics.FailedLogins7d,
		PreviousValue:   metrics.FailedLoginsPrev7d,
		Label:           "Failed Logins (7d)",
		Sparkline:       metrics.FailedLoginSparkline,
		FailedLogins_24H: metrics.FailedLogins24h,
		FailedLogins_7D:  metrics.FailedLogins7d,
		AvgRiskScore:    metrics.AvgRiskScore,
		UniqueIps_24H:   metrics.UniqueIPs24h,
	}

	// Calculate change percent
	if metrics.FailedLoginsPrev7d > 0 {
		resp.ChangePercent = float64(metrics.FailedLogins7d-metrics.FailedLoginsPrev7d) / float64(metrics.FailedLoginsPrev7d) * 100
	}

	// Determine trend
	if resp.ChangePercent > 5 {
		resp.Trend = "up"
	} else if resp.ChangePercent < -5 {
		resp.Trend = "down"
	} else {
		resp.Trend = "stable"
	}

	return resp, nil
}

// GetApiErrorRate returns API error rate with trend.
func (s *TimeSeriesStatisticsService) GetApiErrorRate(ctx context.Context, _ *adminV1.SecurityOverviewRequest) (*adminV1.SecurityOverviewResponse, error) {
	tenantID := getTenantID(ctx)

	metrics, err := s.timeSeriesRepo.QueryApiErrorRate(ctx, tenantID)
	if err != nil {
		s.log.Errorf("GetApiErrorRate failed: %v", err)
		return &adminV1.SecurityOverviewResponse{}, nil
	}

	resp := &adminV1.SecurityOverviewResponse{
		Label:            "API Error Rate",
		ErrorRatePercent: metrics.ErrorRate24h,
		Sparkline:        metrics.ErrorSparkline,
	}

	// Use int representation for value (error rate * 100 for display)
	resp.Value = metrics.TotalErrors24h
	resp.PreviousValue = int64(metrics.ErrorRatePrev24h * 100)

	// Change percent
	if metrics.ErrorRatePrev24h > 0 {
		resp.ChangePercent = ((metrics.ErrorRate24h - metrics.ErrorRatePrev24h) / metrics.ErrorRatePrev24h) * 100
	}

	if resp.ChangePercent > 5 {
		resp.Trend = "up"
	} else if resp.ChangePercent < -5 {
		resp.Trend = "down"
	} else {
		resp.Trend = "stable"
	}

	return resp, nil
}

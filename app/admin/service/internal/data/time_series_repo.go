package data

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	entCrud "github.com/tx7do/go-crud/entgo"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent"
)

// TimeSeriesRepo provides raw SQL access for TimescaleDB time-series queries.
type TimeSeriesRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

// NewTimeSeriesRepo creates a new TimeSeriesRepo.
func NewTimeSeriesRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *TimeSeriesRepo {
	return &TimeSeriesRepo{
		log:       ctx.NewLoggerHelper("time-series/repo/admin-service"),
		entClient: entClient,
	}
}

// getDB returns the underlying *sql.DB from the EntClient wrapper.
func (r *TimeSeriesRepo) getDB() *sql.DB {
	return r.entClient.DB()
}

// TimeSeriesBucket represents a single time bucket with named values.
type TimeSeriesBucket struct {
	Bucket time.Time
	Values map[string]float64
}

// HeatmapCell represents a cell in a heatmap matrix.
type HeatmapCell struct {
	Hour  int
	Day   int
	Value int64
}

// EndpointStat represents statistics for an API endpoint.
type EndpointStat struct {
	Path         string
	Method       string
	Module       string
	TotalReqs    int64
	AvgLatencyMs float64
	P95LatencyMs float64
	ErrorRate    float64
	ErrorCount   int64
	SuccessCount int64
}

// parseRange converts range string to time.Duration.
func parseRange(r string) time.Duration {
	switch r {
	case "24h":
		return 24 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	case "90d":
		return 90 * 24 * time.Hour
	default:
		return 7 * 24 * time.Hour
	}
}

// normalizeInterval returns a valid interval string.
func normalizeInterval(interval string) string {
	switch interval {
	case "1h", "6h", "1d", "1w":
		return interval
	default:
		return "1h"
	}
}

// QueryApiRequestVolume returns API request volume over time using time_bucket.
func (r *TimeSeriesRepo) QueryApiRequestVolume(ctx context.Context, interval, rangeStr string, tenantID uint32) ([]TimeSeriesBucket, error) {
	db := r.getDB()
	if db == nil {
		return nil, fmt.Errorf("database connection unavailable")
	}

	interval = normalizeInterval(interval)
	dur := parseRange(rangeStr)
	since := time.Now().Add(-dur)

	query := fmt.Sprintf(`
		SELECT
			time_bucket('%s', created_at) AS bucket,
			COUNT(*)::float8 AS total,
			COUNT(*) FILTER (WHERE success = true)::float8 AS success,
			COUNT(*) FILTER (WHERE success = false)::float8 AS errors
		FROM sys_api_audit_logs
		WHERE created_at >= $1
		  AND ($2::int = 0 OR tenant_id = $2)
		GROUP BY bucket
		ORDER BY bucket ASC
	`, interval)

	rows, err := db.QueryContext(ctx, query, since, tenantID)
	if err != nil {
		r.log.Errorf("QueryApiRequestVolume failed: %v", err)
		return nil, err
	}
	defer rows.Close()

	var result []TimeSeriesBucket
	for rows.Next() {
		var b TimeSeriesBucket
		var total, success, errors float64
		if err := rows.Scan(&b.Bucket, &total, &success, &errors); err != nil {
			return nil, err
		}
		b.Values = map[string]float64{
			"total":   total,
			"success": success,
			"errors":  errors,
		}
		result = append(result, b)
	}
	return result, rows.Err()
}

// QueryApiLatencyPercentiles returns p50/p95/p99 latency over time.
func (r *TimeSeriesRepo) QueryApiLatencyPercentiles(ctx context.Context, interval, rangeStr string, tenantID uint32) ([]TimeSeriesBucket, error) {
	db := r.getDB()
	if db == nil {
		return nil, fmt.Errorf("database connection unavailable")
	}

	interval = normalizeInterval(interval)
	dur := parseRange(rangeStr)
	since := time.Now().Add(-dur)

	query := fmt.Sprintf(`
		SELECT
			time_bucket('%s', created_at) AS bucket,
			AVG(latency_ms)::float8 AS avg,
			PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms)::float8 AS p50,
			PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms)::float8 AS p95,
			PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms)::float8 AS p99
		FROM sys_api_audit_logs
		WHERE created_at >= $1
		  AND ($2::int = 0 OR tenant_id = $2)
		GROUP BY bucket
		ORDER BY bucket ASC
	`, interval)

	rows, err := db.QueryContext(ctx, query, since, tenantID)
	if err != nil {
		r.log.Errorf("QueryApiLatencyPercentiles failed: %v", err)
		return nil, err
	}
	defer rows.Close()

	var result []TimeSeriesBucket
	for rows.Next() {
		var b TimeSeriesBucket
		var avg, p50, p95, p99 float64
		if err := rows.Scan(&b.Bucket, &avg, &p50, &p95, &p99); err != nil {
			return nil, err
		}
		b.Values = map[string]float64{
			"avg": avg,
			"p50": p50,
			"p95": p95,
			"p99": p99,
		}
		result = append(result, b)
	}
	return result, rows.Err()
}

// QueryLoginActivity returns login success/failure counts over time.
func (r *TimeSeriesRepo) QueryLoginActivity(ctx context.Context, interval, rangeStr string, tenantID uint32) ([]TimeSeriesBucket, error) {
	db := r.getDB()
	if db == nil {
		return nil, fmt.Errorf("database connection unavailable")
	}

	interval = normalizeInterval(interval)
	dur := parseRange(rangeStr)
	since := time.Now().Add(-dur)

	query := fmt.Sprintf(`
		SELECT
			time_bucket('%s', created_at) AS bucket,
			COUNT(*)::float8 AS total,
			COUNT(*) FILTER (WHERE status = 'SUCCESS')::float8 AS success,
			COUNT(*) FILTER (WHERE status = 'FAILED')::float8 AS failed,
			COUNT(*) FILTER (WHERE status = 'LOCKED')::float8 AS locked
		FROM sys_login_audit_logs
		WHERE created_at >= $1
		  AND ($2::int = 0 OR tenant_id = $2)
		GROUP BY bucket
		ORDER BY bucket ASC
	`, interval)

	rows, err := db.QueryContext(ctx, query, since, tenantID)
	if err != nil {
		r.log.Errorf("QueryLoginActivity failed: %v", err)
		return nil, err
	}
	defer rows.Close()

	var result []TimeSeriesBucket
	for rows.Next() {
		var b TimeSeriesBucket
		var total, success, failed, locked float64
		if err := rows.Scan(&b.Bucket, &total, &success, &failed, &locked); err != nil {
			return nil, err
		}
		b.Values = map[string]float64{
			"total":   total,
			"success": success,
			"failed":  failed,
			"locked":  locked,
		}
		result = append(result, b)
	}
	return result, rows.Err()
}

// QueryActiveUsers returns unique active user counts over time.
func (r *TimeSeriesRepo) QueryActiveUsers(ctx context.Context, interval, rangeStr string, tenantID uint32) ([]TimeSeriesBucket, error) {
	db := r.getDB()
	if db == nil {
		return nil, fmt.Errorf("database connection unavailable")
	}

	interval = normalizeInterval(interval)
	dur := parseRange(rangeStr)
	since := time.Now().Add(-dur)

	query := fmt.Sprintf(`
		SELECT
			time_bucket('%s', created_at) AS bucket,
			COUNT(DISTINCT user_id)::float8 AS unique_users,
			COUNT(DISTINCT ip_address)::float8 AS unique_ips
		FROM sys_api_audit_logs
		WHERE created_at >= $1
		  AND ($2::int = 0 OR tenant_id = $2)
		  AND user_id > 0
		GROUP BY bucket
		ORDER BY bucket ASC
	`, interval)

	rows, err := db.QueryContext(ctx, query, since, tenantID)
	if err != nil {
		r.log.Errorf("QueryActiveUsers failed: %v", err)
		return nil, err
	}
	defer rows.Close()

	var result []TimeSeriesBucket
	for rows.Next() {
		var b TimeSeriesBucket
		var users, ips float64
		if err := rows.Scan(&b.Bucket, &users, &ips); err != nil {
			return nil, err
		}
		b.Values = map[string]float64{
			"unique_users": users,
			"unique_ips":   ips,
		}
		result = append(result, b)
	}
	return result, rows.Err()
}

// QueryLoginHeatmap returns login activity as hour-of-day x day-of-week matrix.
func (r *TimeSeriesRepo) QueryLoginHeatmap(ctx context.Context, rangeStr string, tenantID uint32) ([]HeatmapCell, int64, error) {
	db := r.getDB()
	if db == nil {
		return nil, 0, fmt.Errorf("database connection unavailable")
	}

	dur := parseRange(rangeStr)
	since := time.Now().Add(-dur)

	query := `
		SELECT
			EXTRACT(HOUR FROM created_at)::int AS hour,
			EXTRACT(ISODOW FROM created_at)::int - 1 AS day,
			COUNT(*)::bigint AS count
		FROM sys_login_audit_logs
		WHERE created_at >= $1
		  AND ($2::int = 0 OR tenant_id = $2)
		GROUP BY hour, day
		ORDER BY day, hour
	`

	rows, err := db.QueryContext(ctx, query, since, tenantID)
	if err != nil {
		r.log.Errorf("QueryLoginHeatmap failed: %v", err)
		return nil, 0, err
	}
	defer rows.Close()

	var result []HeatmapCell
	var maxVal int64
	for rows.Next() {
		var c HeatmapCell
		if err := rows.Scan(&c.Hour, &c.Day, &c.Value); err != nil {
			return nil, 0, err
		}
		if c.Value > maxVal {
			maxVal = c.Value
		}
		result = append(result, c)
	}
	return result, maxVal, rows.Err()
}

// QueryTopEndpoints returns most-called API endpoints with performance metrics.
func (r *TimeSeriesRepo) QueryTopEndpoints(ctx context.Context, rangeStr string, limit int, tenantID uint32) ([]EndpointStat, error) {
	db := r.getDB()
	if db == nil {
		return nil, fmt.Errorf("database connection unavailable")
	}

	dur := parseRange(rangeStr)
	since := time.Now().Add(-dur)
	if limit <= 0 {
		limit = 10
	}

	query := `
		SELECT
			path,
			http_method,
			COALESCE(api_module, 'unknown'),
			COUNT(*) AS total_requests,
			AVG(latency_ms)::float8 AS avg_latency_ms,
			PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms)::float8 AS p95_latency_ms,
			CASE WHEN COUNT(*) > 0
				THEN (COUNT(*) FILTER (WHERE success = false))::float8 / COUNT(*)::float8 * 100
				ELSE 0 END AS error_rate,
			COUNT(*) FILTER (WHERE success = false) AS error_count,
			COUNT(*) FILTER (WHERE success = true) AS success_count
		FROM sys_api_audit_logs
		WHERE created_at >= $1
		  AND ($2::int = 0 OR tenant_id = $2)
		GROUP BY path, http_method, api_module
		ORDER BY total_requests DESC
		LIMIT $3
	`

	rows, err := db.QueryContext(ctx, query, since, tenantID, limit)
	if err != nil {
		r.log.Errorf("QueryTopEndpoints failed: %v", err)
		return nil, err
	}
	defer rows.Close()

	var result []EndpointStat
	for rows.Next() {
		var s EndpointStat
		if err := rows.Scan(&s.Path, &s.Method, &s.Module, &s.TotalReqs, &s.AvgLatencyMs, &s.P95LatencyMs, &s.ErrorRate, &s.ErrorCount, &s.SuccessCount); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

// SecurityMetrics holds aggregated security metrics.
type SecurityMetrics struct {
	FailedLogins24h      int64
	FailedLogins7d       int64
	FailedLoginsPrev7d   int64
	AvgRiskScore         float64
	AvgRiskScorePrev     float64
	UniqueIPs24h         int64
	FailedLoginSparkline []float64 // daily values for last 7 days
}

// QuerySecurityOverview returns security metrics.
func (r *TimeSeriesRepo) QuerySecurityOverview(ctx context.Context, tenantID uint32) (*SecurityMetrics, error) {
	db := r.getDB()
	if db == nil {
		return nil, fmt.Errorf("database connection unavailable")
	}

	m := &SecurityMetrics{}
	now := time.Now()

	// Failed logins 24h
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sys_login_audit_logs
		WHERE status = 'FAILED' AND created_at >= $1 AND ($2::int = 0 OR tenant_id = $2)
	`, now.Add(-24*time.Hour), tenantID).Scan(&m.FailedLogins24h)
	if err != nil {
		return nil, err
	}

	// Failed logins last 7 days
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sys_login_audit_logs
		WHERE status = 'FAILED' AND created_at >= $1 AND ($2::int = 0 OR tenant_id = $2)
	`, now.Add(-7*24*time.Hour), tenantID).Scan(&m.FailedLogins7d)
	if err != nil {
		return nil, err
	}

	// Failed logins previous 7 days (for comparison)
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sys_login_audit_logs
		WHERE status = 'FAILED' AND created_at >= $1 AND created_at < $2 AND ($3::int = 0 OR tenant_id = $3)
	`, now.Add(-14*24*time.Hour), now.Add(-7*24*time.Hour), tenantID).Scan(&m.FailedLoginsPrev7d)
	if err != nil {
		return nil, err
	}

	// Average risk score last 7 days
	err = db.QueryRowContext(ctx, `
		SELECT COALESCE(AVG(risk_score)::float8, 0) FROM sys_login_audit_logs
		WHERE created_at >= $1 AND ($2::int = 0 OR tenant_id = $2)
	`, now.Add(-7*24*time.Hour), tenantID).Scan(&m.AvgRiskScore)
	if err != nil {
		return nil, err
	}

	// Average risk score previous 7 days
	err = db.QueryRowContext(ctx, `
		SELECT COALESCE(AVG(risk_score)::float8, 0) FROM sys_login_audit_logs
		WHERE created_at >= $1 AND created_at < $2 AND ($3::int = 0 OR tenant_id = $3)
	`, now.Add(-14*24*time.Hour), now.Add(-7*24*time.Hour), tenantID).Scan(&m.AvgRiskScorePrev)
	if err != nil {
		return nil, err
	}

	// Unique IPs 24h
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT ip_address) FROM sys_login_audit_logs
		WHERE created_at >= $1 AND ($2::int = 0 OR tenant_id = $2)
	`, now.Add(-24*time.Hour), tenantID).Scan(&m.UniqueIPs24h)
	if err != nil {
		return nil, err
	}

	// Daily sparkline of failed logins (last 7 days)
	sparkRows, err := db.QueryContext(ctx, `
		SELECT
			time_bucket('1 day', created_at) AS bucket,
			COUNT(*)::float8 AS count
		FROM sys_login_audit_logs
		WHERE status = 'FAILED' AND created_at >= $1 AND ($2::int = 0 OR tenant_id = $2)
		GROUP BY bucket
		ORDER BY bucket ASC
	`, now.Add(-7*24*time.Hour), tenantID)
	if err != nil {
		return nil, err
	}
	defer sparkRows.Close()

	for sparkRows.Next() {
		var bucket time.Time
		var count float64
		if err := sparkRows.Scan(&bucket, &count); err != nil {
			return nil, err
		}
		m.FailedLoginSparkline = append(m.FailedLoginSparkline, count)
	}

	return m, sparkRows.Err()
}

// ApiErrorMetrics holds API error rate metrics.
type ApiErrorMetrics struct {
	ErrorRate24h      float64
	ErrorRatePrev24h  float64
	TotalErrors24h    int64
	TotalRequests24h  int64
	ErrorSparkline    []float64 // hourly error rates for last 24h
}

// QueryApiErrorRate returns API error rate metrics.
func (r *TimeSeriesRepo) QueryApiErrorRate(ctx context.Context, tenantID uint32) (*ApiErrorMetrics, error) {
	db := r.getDB()
	if db == nil {
		return nil, fmt.Errorf("database connection unavailable")
	}

	m := &ApiErrorMetrics{}
	now := time.Now()

	// Current 24h
	err := db.QueryRowContext(ctx, `
		SELECT
			COALESCE(COUNT(*), 0),
			COALESCE(COUNT(*) FILTER (WHERE success = false), 0)
		FROM sys_api_audit_logs
		WHERE created_at >= $1 AND ($2::int = 0 OR tenant_id = $2)
	`, now.Add(-24*time.Hour), tenantID).Scan(&m.TotalRequests24h, &m.TotalErrors24h)
	if err != nil {
		return nil, err
	}

	if m.TotalRequests24h > 0 {
		m.ErrorRate24h = float64(m.TotalErrors24h) / float64(m.TotalRequests24h) * 100
	}

	// Previous 24h error rate
	var prevTotal, prevErrors int64
	err = db.QueryRowContext(ctx, `
		SELECT
			COALESCE(COUNT(*), 0),
			COALESCE(COUNT(*) FILTER (WHERE success = false), 0)
		FROM sys_api_audit_logs
		WHERE created_at >= $1 AND created_at < $2 AND ($3::int = 0 OR tenant_id = $3)
	`, now.Add(-48*time.Hour), now.Add(-24*time.Hour), tenantID).Scan(&prevTotal, &prevErrors)
	if err != nil {
		return nil, err
	}

	if prevTotal > 0 {
		m.ErrorRatePrev24h = float64(prevErrors) / float64(prevTotal) * 100
	}

	// Hourly sparkline for last 24h
	sparkRows, err := db.QueryContext(ctx, `
		SELECT
			time_bucket('1 hour', created_at) AS bucket,
			CASE WHEN COUNT(*) > 0
				THEN (COUNT(*) FILTER (WHERE success = false))::float8 / COUNT(*)::float8 * 100
				ELSE 0 END AS error_rate
		FROM sys_api_audit_logs
		WHERE created_at >= $1 AND ($2::int = 0 OR tenant_id = $2)
		GROUP BY bucket
		ORDER BY bucket ASC
	`, now.Add(-24*time.Hour), tenantID)
	if err != nil {
		return nil, err
	}
	defer sparkRows.Close()

	for sparkRows.Next() {
		var bucket time.Time
		var rate float64
		if err := sparkRows.Scan(&bucket, &rate); err != nil {
			return nil, err
		}
		m.ErrorSparkline = append(m.ErrorSparkline, rate)
	}

	return m, sparkRows.Err()
}

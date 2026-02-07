package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/ipscanjob"
	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
)

// IpScanJobRepo is the repository for IP scan jobs
type IpScanJobRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

// NewIpScanJobRepo creates a new IpScanJobRepo
func NewIpScanJobRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *IpScanJobRepo {
	return &IpScanJobRepo{
		log:       ctx.NewLoggerHelper("ipam/ip_scan_job/repo"),
		entClient: entClient,
	}
}

// ScanConfig holds configuration options for a scan job
type ScanConfig struct {
	TimeoutMs      int32
	Concurrency    int32
	SkipReverseDNS bool
	TCPProbePorts  string
	MaxRetries     int32
}

// Create creates a new scan job
func (r *IpScanJobRepo) Create(ctx context.Context, tenantID uint32, subnetID string, triggeredBy ipscanjob.TriggeredBy, totalAddresses int64, config *ScanConfig) (*ent.IpScanJob, error) {
	id := uuid.New().String()

	create := r.entClient.Client().IpScanJob.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetSubnetID(subnetID).
		SetTriggeredBy(triggeredBy).
		SetTotalAddresses(totalAddresses).
		SetStatus(ipscanjob.StatusPENDING).
		SetProgress(0).
		SetCreateTime(time.Now())

	// Apply configuration if provided
	if config != nil {
		if config.TimeoutMs > 0 {
			create = create.SetTimeoutMs(config.TimeoutMs)
		}
		if config.Concurrency > 0 {
			create = create.SetConcurrency(config.Concurrency)
		}
		if config.SkipReverseDNS {
			create = create.SetSkipReverseDNS(config.SkipReverseDNS)
		}
		if config.TCPProbePorts != "" {
			create = create.SetTCPProbePorts(config.TCPProbePorts)
		}
		if config.MaxRetries > 0 {
			create = create.SetMaxRetries(config.MaxRetries)
		}
	}

	entity, err := create.Save(ctx)
	if err != nil {
		r.log.Errorf("create scan job failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("create scan job failed")
	}
	return entity, nil
}

// GetByID gets a scan job by ID
func (r *IpScanJobRepo) GetByID(ctx context.Context, id string) (*ent.IpScanJob, error) {
	entity, err := r.entClient.Client().IpScanJob.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get scan job failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get scan job failed")
	}
	return entity, nil
}

// ListBySubnet lists all scan jobs for a subnet
func (r *IpScanJobRepo) ListBySubnet(ctx context.Context, tenantID uint32, subnetID string, page, pageSize int) ([]*ent.IpScanJob, int, error) {
	query := r.entClient.Client().IpScanJob.Query().
		Where(
			ipscanjob.TenantID(tenantID),
			ipscanjob.SubnetID(subnetID),
		)

	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count scan jobs failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list scan jobs failed")
	}

	if page > 0 && pageSize > 0 {
		query = query.Offset((page - 1) * pageSize).Limit(pageSize)
	}

	entities, err := query.Order(ent.Desc(ipscanjob.FieldCreateTime)).All(ctx)
	if err != nil {
		r.log.Errorf("list scan jobs failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list scan jobs failed")
	}

	return entities, total, nil
}

// ListPending lists pending scan jobs that are ready to be processed
func (r *IpScanJobRepo) ListPending(ctx context.Context, limit int) ([]*ent.IpScanJob, error) {
	entities, err := r.entClient.Client().IpScanJob.Query().
		Where(ipscanjob.StatusEQ(ipscanjob.StatusPENDING)).
		Order(ent.Asc(ipscanjob.FieldCreateTime)).
		Limit(limit).
		All(ctx)
	if err != nil {
		r.log.Errorf("list pending scan jobs failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("list pending scan jobs failed")
	}
	return entities, nil
}

// ListRetryable lists jobs that are ready for retry
func (r *IpScanJobRepo) ListRetryable(ctx context.Context, limit int) ([]*ent.IpScanJob, error) {
	now := time.Now()
	// Get all failed jobs with next_retry_at <= now
	entities, err := r.entClient.Client().IpScanJob.Query().
		Where(
			ipscanjob.StatusEQ(ipscanjob.StatusFAILED),
			ipscanjob.NextRetryAtLTE(now),
		).
		Order(ent.Asc(ipscanjob.FieldNextRetryAt)).
		Limit(limit * 2). // Fetch more to account for filtering
		All(ctx)
	if err != nil {
		r.log.Errorf("list retryable scan jobs failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("list retryable scan jobs failed")
	}

	// Filter to only include jobs where retry_count < max_retries
	result := make([]*ent.IpScanJob, 0, limit)
	for _, job := range entities {
		if job.RetryCount < job.MaxRetries {
			result = append(result, job)
			if len(result) >= limit {
				break
			}
		}
	}

	return result, nil
}

// ClaimJob atomically claims a job for processing
// Returns true if this caller successfully claimed the job, false otherwise
func (r *IpScanJobRepo) ClaimJob(ctx context.Context, id string, expectedStatus ipscanjob.Status) (bool, error) {
	now := time.Now()
	affected, err := r.entClient.Client().IpScanJob.Update().
		Where(
			ipscanjob.IDEQ(id),
			ipscanjob.StatusEQ(expectedStatus),
		).
		SetStatus(ipscanjob.StatusSCANNING).
		SetStatusMessage("Scanning...").
		SetStartedAt(now).
		SetUpdateTime(now).
		Save(ctx)

	if err != nil {
		r.log.Errorf("claim scan job failed: %s", err.Error())
		return false, ipamV1.ErrorInternalServerError("claim scan job failed")
	}

	return affected > 0, nil
}

// UpdateProgress updates the progress of a scan job
func (r *IpScanJobRepo) UpdateProgress(ctx context.Context, id string, scannedCount, aliveCount, newCount, updatedCount int64, progress int32, message string) error {
	_, err := r.entClient.Client().IpScanJob.UpdateOneID(id).
		SetScannedCount(scannedCount).
		SetAliveCount(aliveCount).
		SetNewCount(newCount).
		SetUpdatedCount(updatedCount).
		SetProgress(progress).
		SetStatusMessage(message).
		SetUpdateTime(time.Now()).
		Save(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorScanJobNotFound("scan job not found")
		}
		r.log.Errorf("update scan job progress failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("update scan job progress failed")
	}
	return nil
}

// UpdateStatus updates the status of a scan job
func (r *IpScanJobRepo) UpdateStatus(ctx context.Context, id string, status ipscanjob.Status, message string, progress int32) (*ent.IpScanJob, error) {
	update := r.entClient.Client().IpScanJob.UpdateOneID(id).
		SetStatus(status).
		SetStatusMessage(message).
		SetProgress(progress).
		SetUpdateTime(time.Now())

	// Set completed_at for terminal states
	if status == ipscanjob.StatusCOMPLETED || status == ipscanjob.StatusFAILED || status == ipscanjob.StatusCANCELLED {
		update = update.SetCompletedAt(time.Now())
	}

	entity, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ipamV1.ErrorScanJobNotFound("scan job not found")
		}
		r.log.Errorf("update scan job status failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update scan job status failed")
	}
	return entity, nil
}

// MarkForRetry marks a job for retry with exponential backoff
func (r *IpScanJobRepo) MarkForRetry(ctx context.Context, id string, nextRetryAt time.Time) (*ent.IpScanJob, error) {
	entity, err := r.entClient.Client().IpScanJob.UpdateOneID(id).
		SetStatus(ipscanjob.StatusFAILED).
		SetNillableNextRetryAt(&nextRetryAt).
		AddRetryCount(1).
		SetUpdateTime(time.Now()).
		Save(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ipamV1.ErrorScanJobNotFound("scan job not found")
		}
		r.log.Errorf("mark scan job for retry failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("mark scan job for retry failed")
	}
	return entity, nil
}

// Cancel cancels a scan job
func (r *IpScanJobRepo) Cancel(ctx context.Context, id string) (*ent.IpScanJob, error) {
	entity, err := r.entClient.Client().IpScanJob.UpdateOneID(id).
		SetStatus(ipscanjob.StatusCANCELLED).
		SetStatusMessage("Cancelled by user").
		SetCompletedAt(time.Now()).
		SetUpdateTime(time.Now()).
		Save(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ipamV1.ErrorScanJobNotFound("scan job not found")
		}
		r.log.Errorf("cancel scan job failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("cancel scan job failed")
	}
	return entity, nil
}

// Delete deletes a scan job
func (r *IpScanJobRepo) Delete(ctx context.Context, id string) error {
	err := r.entClient.Client().IpScanJob.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorScanJobNotFound("scan job not found")
		}
		r.log.Errorf("delete scan job failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete scan job failed")
	}
	return nil
}

// CleanupOld removes completed/failed/cancelled jobs older than the specified days
func (r *IpScanJobRepo) CleanupOld(ctx context.Context, days int) (int, error) {
	cutoff := time.Now().AddDate(0, 0, -days)

	affected, err := r.entClient.Client().IpScanJob.Delete().
		Where(
			ipscanjob.Or(
				ipscanjob.StatusEQ(ipscanjob.StatusCOMPLETED),
				ipscanjob.StatusEQ(ipscanjob.StatusFAILED),
				ipscanjob.StatusEQ(ipscanjob.StatusCANCELLED),
			),
			ipscanjob.CompletedAtLT(cutoff),
		).
		Exec(ctx)

	if err != nil {
		r.log.Errorf("cleanup old scan jobs failed: %s", err.Error())
		return 0, ipamV1.ErrorInternalServerError("cleanup old scan jobs failed")
	}

	return affected, nil
}

// GetLatestBySubnet gets the most recent scan job for a subnet
func (r *IpScanJobRepo) GetLatestBySubnet(ctx context.Context, tenantID uint32, subnetID string) (*ent.IpScanJob, error) {
	entity, err := r.entClient.Client().IpScanJob.Query().
		Where(
			ipscanjob.TenantID(tenantID),
			ipscanjob.SubnetID(subnetID),
		).
		Order(ent.Desc(ipscanjob.FieldCreateTime)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get latest scan job failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get latest scan job failed")
	}
	return entity, nil
}

// HasActiveScan checks if there's an active (pending/scanning) scan for the subnet
func (r *IpScanJobRepo) HasActiveScan(ctx context.Context, tenantID uint32, subnetID string) (bool, error) {
	count, err := r.entClient.Client().IpScanJob.Query().
		Where(
			ipscanjob.TenantID(tenantID),
			ipscanjob.SubnetID(subnetID),
			ipscanjob.Or(
				ipscanjob.StatusEQ(ipscanjob.StatusPENDING),
				ipscanjob.StatusEQ(ipscanjob.StatusSCANNING),
			),
		).
		Count(ctx)

	if err != nil {
		r.log.Errorf("check active scan failed: %s", err.Error())
		return false, ipamV1.ErrorInternalServerError("check active scan failed")
	}

	return count > 0, nil
}

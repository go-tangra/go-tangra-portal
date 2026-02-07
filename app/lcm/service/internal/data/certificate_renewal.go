package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/certificaterenewal"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
)

// CertificateRenewalRepo handles certificate renewal job data operations
type CertificateRenewalRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

// NewCertificateRenewalRepo creates a new CertificateRenewalRepo
func NewCertificateRenewalRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *CertificateRenewalRepo {
	return &CertificateRenewalRepo{
		log:       ctx.NewLoggerHelper("certificate-renewal/repo"),
		entClient: entClient,
	}
}

// Create creates a new certificate renewal job
func (r *CertificateRenewalRepo) Create(ctx context.Context, renewal *ent.CertificateRenewal) (*ent.CertificateRenewal, error) {
	builder := r.entClient.Client().CertificateRenewal.Create().
		SetCertificateID(renewal.CertificateID).
		SetClientID(renewal.ClientID).
		SetIssuerName(renewal.IssuerName).
		SetDomains(renewal.Domains).
		SetOriginalExpiresAt(renewal.OriginalExpiresAt).
		SetScheduledAt(renewal.ScheduledAt).
		SetMaxAttempts(renewal.MaxAttempts)

	if renewal.RenewalConfig != nil {
		builder.SetRenewalConfig(renewal.RenewalConfig)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create certificate renewal failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create certificate renewal failed")
	}
	return entity, nil
}

// GetByID retrieves a certificate renewal by ID
func (r *CertificateRenewalRepo) GetByID(ctx context.Context, id int) (*ent.CertificateRenewal, error) {
	entity, err := r.entClient.Client().CertificateRenewal.Query().
		Where(certificaterenewal.IDEQ(id)).
		WithIssuedCertificate().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("query certificate renewal failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate renewal failed")
	}
	return entity, nil
}

// GetPendingByCertificateID checks if there's already a pending renewal for a certificate
func (r *CertificateRenewalRepo) GetPendingByCertificateID(ctx context.Context, certificateID string) (*ent.CertificateRenewal, error) {
	entity, err := r.entClient.Client().CertificateRenewal.Query().
		Where(
			certificaterenewal.CertificateIDEQ(certificateID),
			certificaterenewal.StatusIn(
				certificaterenewal.StatusPending,
				certificaterenewal.StatusProcessing,
			),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("query pending renewal failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query pending renewal failed")
	}
	return entity, nil
}

// FindPendingRenewals finds pending renewals that are due for processing
// Returns renewals where:
// - status = 'pending'
// - scheduled_at <= now
// - not locked or lock expired
func (r *CertificateRenewalRepo) FindPendingRenewals(ctx context.Context, batchSize int) ([]*ent.CertificateRenewal, error) {
	now := time.Now()

	entities, err := r.entClient.Client().CertificateRenewal.Query().
		Where(
			certificaterenewal.StatusEQ(certificaterenewal.StatusPending),
			certificaterenewal.ScheduledAtLTE(now),
			certificaterenewal.Or(
				certificaterenewal.LockExpiresAtIsNil(),
				certificaterenewal.LockExpiresAtLT(now),
			),
		).
		WithIssuedCertificate().
		Order(ent.Asc(certificaterenewal.FieldScheduledAt)).
		Limit(batchSize).
		All(ctx)
	if err != nil {
		r.log.Errorf("find pending renewals failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("find pending renewals failed")
	}
	return entities, nil
}

// TryLock attempts to acquire a lock on a renewal job
// Returns true if lock acquired, false if already locked by another worker
func (r *CertificateRenewalRepo) TryLock(ctx context.Context, id int, workerID string, lockTimeout time.Duration) (bool, error) {
	now := time.Now()
	lockExpires := now.Add(lockTimeout)

	// Use optimistic locking - only update if not locked or lock expired
	affected, err := r.entClient.Client().CertificateRenewal.Update().
		Where(
			certificaterenewal.IDEQ(id),
			certificaterenewal.StatusEQ(certificaterenewal.StatusPending),
			certificaterenewal.Or(
				certificaterenewal.LockExpiresAtIsNil(),
				certificaterenewal.LockExpiresAtLT(now),
			),
		).
		SetWorkerID(workerID).
		SetLockedAt(now).
		SetLockExpiresAt(lockExpires).
		SetStatus(certificaterenewal.StatusProcessing).
		SetStartedAt(now).
		Save(ctx)
	if err != nil {
		r.log.Errorf("try lock renewal failed: %s", err.Error())
		return false, lcmV1.ErrorInternalServerError("try lock renewal failed")
	}
	return affected > 0, nil
}

// MarkCompleted marks a renewal as completed
func (r *CertificateRenewalRepo) MarkCompleted(ctx context.Context, id int) error {
	now := time.Now()
	_, err := r.entClient.Client().CertificateRenewal.UpdateOneID(id).
		SetStatus(certificaterenewal.StatusCompleted).
		SetCompletedAt(now).
		ClearWorkerID().
		ClearLockedAt().
		ClearLockExpiresAt().
		Save(ctx)
	if err != nil {
		r.log.Errorf("mark renewal completed failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("mark renewal completed failed")
	}
	return nil
}

// MarkFailed marks a renewal as failed
func (r *CertificateRenewalRepo) MarkFailed(ctx context.Context, id int, errorMsg string) error {
	now := time.Now()
	_, err := r.entClient.Client().CertificateRenewal.UpdateOneID(id).
		SetStatus(certificaterenewal.StatusFailed).
		SetCompletedAt(now).
		SetErrorMessage(errorMsg).
		ClearWorkerID().
		ClearLockedAt().
		ClearLockExpiresAt().
		Save(ctx)
	if err != nil {
		r.log.Errorf("mark renewal failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("mark renewal failed")
	}
	return nil
}

// ScheduleRetry reschedules a renewal for retry
func (r *CertificateRenewalRepo) ScheduleRetry(ctx context.Context, id int, retryAt time.Time, errorMsg string) error {
	_, err := r.entClient.Client().CertificateRenewal.UpdateOneID(id).
		SetStatus(certificaterenewal.StatusPending).
		SetScheduledAt(retryAt).
		SetErrorMessage(errorMsg).
		AddAttemptNumber(1).
		ClearWorkerID().
		ClearLockedAt().
		ClearLockExpiresAt().
		ClearStartedAt().
		Save(ctx)
	if err != nil {
		r.log.Errorf("schedule retry failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("schedule retry failed")
	}
	return nil
}

// Cancel cancels a pending renewal
func (r *CertificateRenewalRepo) Cancel(ctx context.Context, id int) error {
	_, err := r.entClient.Client().CertificateRenewal.UpdateOneID(id).
		SetStatus(certificaterenewal.StatusCancelled).
		ClearWorkerID().
		ClearLockedAt().
		ClearLockExpiresAt().
		Save(ctx)
	if err != nil {
		r.log.Errorf("cancel renewal failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("cancel renewal failed")
	}
	return nil
}

// ListByCertificateID lists all renewals for a certificate
func (r *CertificateRenewalRepo) ListByCertificateID(ctx context.Context, certificateID string) ([]*ent.CertificateRenewal, error) {
	entities, err := r.entClient.Client().CertificateRenewal.Query().
		Where(certificaterenewal.CertificateIDEQ(certificateID)).
		Order(ent.Desc(certificaterenewal.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list renewals by certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list renewals failed")
	}
	return entities, nil
}

// ListByClientID lists all renewals for a client
func (r *CertificateRenewalRepo) ListByClientID(ctx context.Context, clientID string) ([]*ent.CertificateRenewal, error) {
	entities, err := r.entClient.Client().CertificateRenewal.Query().
		Where(certificaterenewal.ClientIDEQ(clientID)).
		WithIssuedCertificate().
		Order(ent.Desc(certificaterenewal.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list renewals by client failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list renewals failed")
	}
	return entities, nil
}

// CleanupExpiredLocks releases locks that have expired
// This is a maintenance function to recover from worker crashes
func (r *CertificateRenewalRepo) CleanupExpiredLocks(ctx context.Context) (int, error) {
	now := time.Now()
	affected, err := r.entClient.Client().CertificateRenewal.Update().
		Where(
			certificaterenewal.StatusEQ(certificaterenewal.StatusProcessing),
			certificaterenewal.LockExpiresAtLT(now),
		).
		SetStatus(certificaterenewal.StatusPending).
		ClearWorkerID().
		ClearLockedAt().
		ClearLockExpiresAt().
		ClearStartedAt().
		Save(ctx)
	if err != nil {
		r.log.Errorf("cleanup expired locks failed: %s", err.Error())
		return 0, lcmV1.ErrorInternalServerError("cleanup expired locks failed")
	}
	if affected > 0 {
		r.log.Infof("cleaned up %d expired locks", affected)
	}
	return affected, nil
}

// GenerateWorkerID generates a unique worker ID
func GenerateWorkerID() string {
	return uuid.New().String()
}

package data

import (
	"context"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/biz"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/certificatepermission"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/issuedcertificate"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
)

// IssuedCertificateRepo handles issued certificate data operations
type IssuedCertificateRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

// NewIssuedCertificateRepo creates a new IssuedCertificateRepo
func NewIssuedCertificateRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *IssuedCertificateRepo {
	return &IssuedCertificateRepo{
		log:       ctx.NewLoggerHelper("issued-certificate/repo"),
		entClient: entClient,
	}
}

// GetByID retrieves an issued certificate by its ID
func (r *IssuedCertificateRepo) GetByID(ctx context.Context, id string) (*ent.IssuedCertificate, error) {
	entity, err := r.entClient.Client().IssuedCertificate.Query().
		Where(issuedcertificate.IDEQ(id)).
		WithLcmClient().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("query issued certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query issued certificate failed")
	}
	return entity, nil
}

// Create creates a new issued certificate record
func (r *IssuedCertificateRepo) Create(ctx context.Context, cert *ent.IssuedCertificate) (*ent.IssuedCertificate, error) {
	builder := r.entClient.Client().IssuedCertificate.Create().
		SetID(cert.ID).
		SetIssuerName(cert.IssuerName).
		SetDomains(cert.Domains).
		SetStatus(cert.Status)

	if cert.ClientID != "" {
		builder.SetClientID(cert.ClientID)
	}
	if cert.CertPem != "" {
		builder.SetCertPem(cert.CertPem)
	}
	if cert.PrivateKeyPem != "" {
		builder.SetPrivateKeyPem(cert.PrivateKeyPem)
	}
	if cert.CaCertPem != "" {
		builder.SetCaCertPem(cert.CaCertPem)
	}
	if cert.CsrPem != "" {
		builder.SetCsrPem(cert.CsrPem)
	}
	if cert.CertificateFingerprint != "" {
		builder.SetCertificateFingerprint(cert.CertificateFingerprint)
	}
	if cert.KeyType != "" {
		builder.SetKeyType(cert.KeyType)
	}
	if cert.KeySize != 0 {
		builder.SetKeySize(cert.KeySize)
	}
	if !cert.ExpiresAt.IsZero() {
		builder.SetExpiresAt(cert.ExpiresAt)
	}

	// Auto-renewal settings
	builder.SetAutoRenewEnabled(cert.AutoRenewEnabled)
	if cert.AutoRenewDaysBeforeExpiry != 0 {
		builder.SetAutoRenewDaysBeforeExpiry(cert.AutoRenewDaysBeforeExpiry)
	}
	if cert.AutoRenewMaxAttempts != 0 {
		builder.SetAutoRenewMaxAttempts(cert.AutoRenewMaxAttempts)
	}
	if cert.AutoRenewRetryIntervalSeconds != 0 {
		builder.SetAutoRenewRetryIntervalSeconds(cert.AutoRenewRetryIntervalSeconds)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create issued certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create issued certificate failed")
	}
	return entity, nil
}

// CreateFromJob creates an issued certificate record from a completed job
func (r *IssuedCertificateRepo) CreateFromJob(
	ctx context.Context,
	jobID string,
	certReq *biz.CertificateRequest,
	issuedCert *biz.IssuedCertificate,
	csrPEM string,
	encryptedKeyPEM string,
	serverGeneratedKey bool,
) error {
	builder := r.entClient.Client().IssuedCertificate.Create().
		SetID(jobID).
		SetClientID(certReq.ClientID).
		SetIssuerName(certReq.IssuerName).
		SetIssuerType(certReq.IssuerType).
		SetDomains(certReq.DNSNames).
		SetStatus(issuedcertificate.StatusIssued).
		SetCertPem(issuedCert.Certificate).
		SetCaCertPem(issuedCert.CACertificate).
		SetCertificateFingerprint(issuedCert.SerialNumber).
		SetExpiresAt(issuedCert.ExpiresAt).
		SetServerGeneratedKey(serverGeneratedKey)

	if csrPEM != "" {
		builder.SetCsrPem(csrPEM)
	}
	if encryptedKeyPEM != "" {
		builder.SetPrivateKeyPem(encryptedKeyPEM)
	}
	if certReq.KeyType != "" {
		builder.SetKeyType(issuedcertificate.KeyType(strings.ToLower(certReq.KeyType)))
	}
	if certReq.KeySize > 0 {
		builder.SetKeySize(int32(certReq.KeySize))
	}

	_, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create issued certificate from job failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("create issued certificate from job failed")
	}
	return nil
}

// UpdateStatus updates the status of an issued certificate
func (r *IssuedCertificateRepo) UpdateStatus(ctx context.Context, id string, status issuedcertificate.Status, errorMsg string) error {
	builder := r.entClient.Client().IssuedCertificate.UpdateOneID(id).
		SetStatus(status)

	if errorMsg != "" {
		builder.SetErrorMessage(errorMsg)
	}

	_, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("update issued certificate status failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("update issued certificate status failed")
	}
	return nil
}

// UpdateCertificate updates the certificate data after issuance
func (r *IssuedCertificateRepo) UpdateCertificate(ctx context.Context, id string, certPEM, keyPEM, caPEM, fingerprint string, expiresAt time.Time) error {
	_, err := r.entClient.Client().IssuedCertificate.UpdateOneID(id).
		SetCertPem(certPEM).
		SetPrivateKeyPem(keyPEM).
		SetCaCertPem(caPEM).
		SetCertificateFingerprint(fingerprint).
		SetExpiresAt(expiresAt).
		SetStatus(issuedcertificate.StatusIssued).
		Save(ctx)
	if err != nil {
		r.log.Errorf("update issued certificate failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("update issued certificate failed")
	}
	return nil
}

// FindCertificatesDueForRenewal finds certificates that are due for renewal
// Returns certificates where:
// - auto_renew_enabled = true
// - status = 'issued'
// - expires_at <= now + days_before_expiry
// - renewal_attempts < max_attempts (or no active renewal exists)
func (r *IssuedCertificateRepo) FindCertificatesDueForRenewal(ctx context.Context, defaultDaysBeforeExpiry int32, batchSize int) ([]*ent.IssuedCertificate, error) {
	now := time.Now()

	entities, err := r.entClient.Client().IssuedCertificate.Query().
		Where(
			issuedcertificate.AutoRenewEnabledEQ(true),
			issuedcertificate.StatusEQ(issuedcertificate.StatusIssued),
			issuedcertificate.ExpiresAtNotNil(),
		).
		WithLcmClient().
		Order(ent.Asc(issuedcertificate.FieldExpiresAt)).
		Limit(batchSize * 2). // Get extra to filter
		All(ctx)
	if err != nil {
		r.log.Errorf("find certificates due for renewal failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("find certificates due for renewal failed")
	}

	// Filter certificates that are due for renewal
	var result []*ent.IssuedCertificate
	for _, cert := range entities {
		if cert.ExpiresAt.IsZero() {
			continue
		}

		// Use certificate's own setting or default
		daysBeforeExpiry := defaultDaysBeforeExpiry
		if cert.AutoRenewDaysBeforeExpiry != 0 {
			daysBeforeExpiry = cert.AutoRenewDaysBeforeExpiry
		}

		renewalThreshold := now.Add(time.Duration(daysBeforeExpiry) * 24 * time.Hour)
		if cert.ExpiresAt.Before(renewalThreshold) {
			// Check if max attempts not exceeded
			maxAttempts := cert.AutoRenewMaxAttempts
			if maxAttempts == 0 {
				maxAttempts = 3 // Default
			}
			if cert.RenewalAttempts < maxAttempts {
				result = append(result, cert)
				if len(result) >= batchSize {
					break
				}
			}
		}
	}

	return result, nil
}

// IncrementRenewalAttempts increments the renewal attempt counter
func (r *IssuedCertificateRepo) IncrementRenewalAttempts(ctx context.Context, id string) error {
	_, err := r.entClient.Client().IssuedCertificate.UpdateOneID(id).
		AddRenewalAttempts(1).
		SetLastRenewalAt(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("increment renewal attempts failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("increment renewal attempts failed")
	}
	return nil
}

// ResetRenewalAttempts resets the renewal attempt counter after successful renewal
func (r *IssuedCertificateRepo) ResetRenewalAttempts(ctx context.Context, id string) error {
	_, err := r.entClient.Client().IssuedCertificate.UpdateOneID(id).
		SetRenewalAttempts(0).
		SetLastRenewalAt(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("reset renewal attempts failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("reset renewal attempts failed")
	}
	return nil
}

// MarkAsRenewed marks a certificate as renewed (old certificate after successful renewal)
func (r *IssuedCertificateRepo) MarkAsRenewed(ctx context.Context, id string) error {
	_, err := r.entClient.Client().IssuedCertificate.UpdateOneID(id).
		SetStatus(issuedcertificate.StatusRenewed).
		SetLastRenewalAt(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("mark certificate as renewed failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("mark certificate as renewed failed")
	}
	return nil
}

// ListByClientID lists all issued certificates for a client
func (r *IssuedCertificateRepo) ListByClientID(ctx context.Context, clientID string) ([]*ent.IssuedCertificate, error) {
	entities, err := r.entClient.Client().IssuedCertificate.Query().
		Where(issuedcertificate.ClientIDEQ(clientID)).
		Order(ent.Desc(issuedcertificate.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list issued certificates by client failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list issued certificates failed")
	}
	return entities, nil
}

// ListByIssuerName lists all issued certificates for an issuer
func (r *IssuedCertificateRepo) ListByIssuerName(ctx context.Context, issuerName string) ([]*ent.IssuedCertificate, error) {
	entities, err := r.entClient.Client().IssuedCertificate.Query().
		Where(issuedcertificate.IssuerNameEQ(issuerName)).
		Order(ent.Desc(issuedcertificate.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list issued certificates by issuer failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list issued certificates failed")
	}
	return entities, nil
}

// ListFilter represents filters for listing issued certificates
type ListFilter struct {
	TenantID   *uint32
	Status     *issuedcertificate.Status
	IssuerName string
	Page       uint32
	PageSize   uint32
}

// CreateJobRequest contains all data needed to create a new certificate job
type CreateJobRequest struct {
	ID             string
	TenantID       uint32
	ClientID       string
	IssuerName     string
	IssuerType     string
	CommonName     string
	DNSNames       []string
	IPAddresses    []string
	CSR            string
	PrivateKey     string // Encrypted
	KeyType        string
	KeySize        int32
	ServerGenKey   bool
}

// CreateJob creates a new certificate job record with pending status
func (r *IssuedCertificateRepo) CreateJob(ctx context.Context, req *CreateJobRequest) (*ent.IssuedCertificate, error) {
	builder := r.entClient.Client().IssuedCertificate.Create().
		SetID(req.ID).
		SetTenantID(req.TenantID).
		SetClientID(req.ClientID).
		SetIssuerName(req.IssuerName).
		SetIssuerType(req.IssuerType).
		SetCommonName(req.CommonName).
		SetDomains(req.DNSNames).
		SetIPAddresses(req.IPAddresses).
		SetStatus(issuedcertificate.StatusPending).
		SetServerGeneratedKey(req.ServerGenKey)

	if req.CSR != "" {
		builder.SetCsrPem(req.CSR)
	}
	if req.PrivateKey != "" {
		builder.SetPrivateKeyPem(req.PrivateKey)
	}
	if req.KeyType != "" {
		builder.SetKeyType(issuedcertificate.KeyType(strings.ToLower(req.KeyType)))
	}
	if req.KeySize > 0 {
		builder.SetKeySize(req.KeySize)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create certificate job failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create certificate job failed")
	}
	return entity, nil
}

// CompleteJobRequest contains data for completing a certificate job
type CompleteJobRequest struct {
	Certificate     string
	CACertificate   string
	SerialNumber    string
	ExpiresAt       time.Time
}

// CompleteJob updates a job to completed status with certificate data
func (r *IssuedCertificateRepo) CompleteJob(ctx context.Context, id string, req *CompleteJobRequest) error {
	_, err := r.entClient.Client().IssuedCertificate.UpdateOneID(id).
		SetStatus(issuedcertificate.StatusIssued).
		SetCertPem(req.Certificate).
		SetCaCertPem(req.CACertificate).
		SetCertificateFingerprint(req.SerialNumber).
		SetExpiresAt(req.ExpiresAt).
		Save(ctx)
	if err != nil {
		r.log.Errorf("complete certificate job failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("complete certificate job failed")
	}
	return nil
}

// FailJob updates a job to failed status with error message
func (r *IssuedCertificateRepo) FailJob(ctx context.Context, id string, errorMsg string) error {
	_, err := r.entClient.Client().IssuedCertificate.UpdateOneID(id).
		SetStatus(issuedcertificate.StatusFailed).
		SetErrorMessage(errorMsg).
		Save(ctx)
	if err != nil {
		r.log.Errorf("fail certificate job failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("fail certificate job failed")
	}
	return nil
}

// List lists issued certificates with pagination and filters
func (r *IssuedCertificateRepo) List(ctx context.Context, filter *ListFilter) ([]*ent.IssuedCertificate, uint32, error) {
	query := r.entClient.Client().IssuedCertificate.Query()

	// Apply filters
	if filter != nil {
		if filter.TenantID != nil {
			query = query.Where(issuedcertificate.TenantIDEQ(*filter.TenantID))
		}
		if filter.Status != nil {
			query = query.Where(issuedcertificate.StatusEQ(*filter.Status))
		}
		if filter.IssuerName != "" {
			query = query.Where(issuedcertificate.IssuerNameEQ(filter.IssuerName))
		}
	}

	// Get total count
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count issued certificates failed: %s", err.Error())
		return nil, 0, lcmV1.ErrorInternalServerError("count issued certificates failed")
	}

	// Apply pagination
	if filter != nil && filter.PageSize > 0 {
		offset := (filter.Page - 1) * filter.PageSize
		if filter.Page == 0 {
			offset = 0
		}
		query = query.Offset(int(offset)).Limit(int(filter.PageSize))
	}

	// Order by created_at descending
	query = query.Order(ent.Desc(issuedcertificate.FieldCreatedAt))

	entities, err := query.All(ctx)
	if err != nil {
		r.log.Errorf("list issued certificates failed: %s", err.Error())
		return nil, 0, lcmV1.ErrorInternalServerError("list issued certificates failed")
	}

	return entities, uint32(total), nil
}

// Delete deletes an issued certificate
func (r *IssuedCertificateRepo) Delete(ctx context.Context, id string) error {
	err := r.entClient.Client().IssuedCertificate.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return lcmV1.ErrorNotFound("issued certificate not found")
		}
		r.log.Errorf("delete issued certificate failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("delete issued certificate failed")
	}
	return nil
}

// IssuedCertificateWithAccess represents a certificate with its access type
type IssuedCertificateWithAccess struct {
	Certificate *ent.IssuedCertificate
	IsOwner     bool
	Permission  *ent.CertificatePermission
}

// ListAccessibleByClient lists all certificates accessible to a client (either owned or via permission grant)
func (r *IssuedCertificateRepo) ListAccessibleByClient(ctx context.Context, clientID string, granteeID uint32) ([]*IssuedCertificateWithAccess, error) {
	// Get owned certificates
	ownedCerts, err := r.entClient.Client().IssuedCertificate.Query().
		Where(issuedcertificate.ClientIDEQ(clientID)).
		WithLcmClient().
		Order(ent.Desc(issuedcertificate.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list owned certificates failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list accessible certificates failed")
	}

	// Get certificates via permission grants
	permissions, err := r.entClient.Client().CertificatePermission.Query().
		Where(certificatepermission.GranteeIDEQ(granteeID)).
		WithIssuedCertificate(func(q *ent.IssuedCertificateQuery) {
			q.WithLcmClient()
		}).
		All(ctx)
	if err != nil {
		r.log.Errorf("list permission grants failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list accessible certificates failed")
	}

	// Build result list, avoiding duplicates
	seenIDs := make(map[string]bool)
	var result []*IssuedCertificateWithAccess

	// Add owned certificates first (owner takes precedence)
	for _, cert := range ownedCerts {
		seenIDs[cert.ID] = true
		result = append(result, &IssuedCertificateWithAccess{
			Certificate: cert,
			IsOwner:     true,
			Permission:  nil,
		})
	}

	// Add certificates from permission grants (only if not already added as owned)
	for _, perm := range permissions {
		if perm.Edges.IssuedCertificate != nil && !seenIDs[perm.Edges.IssuedCertificate.ID] {
			seenIDs[perm.Edges.IssuedCertificate.ID] = true
			result = append(result, &IssuedCertificateWithAccess{
				Certificate: perm.Edges.IssuedCertificate,
				IsOwner:     false,
				Permission:  perm,
			})
		}
	}

	return result, nil
}

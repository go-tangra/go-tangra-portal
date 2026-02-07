package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/dnsconfig"
	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
)

type DnsConfigRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewDnsConfigRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *DnsConfigRepo {
	return &DnsConfigRepo{
		log:       ctx.NewLoggerHelper("ipam/dns_config/repo"),
		entClient: entClient,
	}
}

// GetByTenantID retrieves the DNS config for a tenant
func (r *DnsConfigRepo) GetByTenantID(ctx context.Context, tenantID uint32) (*ent.DnsConfig, error) {
	entity, err := r.entClient.Client().DnsConfig.Query().
		Where(dnsconfig.TenantID(tenantID)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get dns config failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get dns config failed")
	}
	return entity, nil
}

// CreateOrUpdate creates or updates DNS config for a tenant
func (r *DnsConfigRepo) CreateOrUpdate(ctx context.Context, tenantID uint32, dnsServers []string, timeoutMs int32, useSystemFallback, reverseDnsEnabled bool) (*ent.DnsConfig, error) {
	// Check if config exists
	existing, err := r.GetByTenantID(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		// Update existing
		update := r.entClient.Client().DnsConfig.UpdateOne(existing).
			SetDNSServers(dnsServers).
			SetTimeoutMs(timeoutMs).
			SetUseSystemDNSFallback(useSystemFallback).
			SetReverseDNSEnabled(reverseDnsEnabled).
			SetUpdateTime(time.Now())

		entity, err := update.Save(ctx)
		if err != nil {
			r.log.Errorf("update dns config failed: %s", err.Error())
			return nil, ipamV1.ErrorInternalServerError("update dns config failed")
		}
		return entity, nil
	}

	// Create new
	id := uuid.New().String()
	entity, err := r.entClient.Client().DnsConfig.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetDNSServers(dnsServers).
		SetTimeoutMs(timeoutMs).
		SetUseSystemDNSFallback(useSystemFallback).
		SetReverseDNSEnabled(reverseDnsEnabled).
		SetCreateTime(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("create dns config failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("create dns config failed")
	}
	return entity, nil
}

// GetDnsServers retrieves the DNS servers for a tenant, returning defaults if not configured
func (r *DnsConfigRepo) GetDnsServers(ctx context.Context, tenantID uint32) ([]string, int32, bool, error) {
	entity, err := r.GetByTenantID(ctx, tenantID)
	if err != nil {
		return nil, 0, false, err
	}

	if entity == nil || !entity.ReverseDNSEnabled {
		// Return empty - disabled or not configured
		return nil, 5000, false, nil
	}

	servers := entity.DNSServers
	timeout := entity.TimeoutMs
	if timeout <= 0 {
		timeout = 5000
	}

	return servers, timeout, entity.UseSystemDNSFallback, nil
}

package service

import (
	"context"
	"net"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent"
)

var version = "1.0.0"

type SystemService struct {
	ipamV1.UnimplementedSystemServiceServer

	log           *log.Helper
	dnsConfigRepo *data.DnsConfigRepo
}

func NewSystemService(ctx *bootstrap.Context, dnsConfigRepo *data.DnsConfigRepo) *SystemService {
	return &SystemService{
		log:           ctx.NewLoggerHelper("ipam/service/system"),
		dnsConfigRepo: dnsConfigRepo,
	}
}

func (s *SystemService) HealthCheck(ctx context.Context, req *ipamV1.HealthCheckRequest) (*ipamV1.HealthCheckResponse, error) {
	return &ipamV1.HealthCheckResponse{
		Status:    "healthy",
		Version:   version,
		Timestamp: timestamppb.New(time.Now()),
	}, nil
}

func (s *SystemService) GetStats(ctx context.Context, req *ipamV1.GetStatsRequest) (*ipamV1.GetStatsResponse, error) {
	// TODO: Implement actual statistics collection
	return &ipamV1.GetStatsResponse{
		TotalSubnets:       0,
		TotalAddresses:     0,
		UsedAddresses:      0,
		AvailableAddresses: 0,
		TotalVlans:         0,
		TotalDevices:       0,
		TotalLocations:     0,
		OverallUtilization: 0,
	}, nil
}

func (s *SystemService) GetDnsConfig(ctx context.Context, req *ipamV1.GetDnsConfigRequest) (*ipamV1.GetDnsConfigResponse, error) {
	entity, err := s.dnsConfigRepo.GetByTenantID(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}

	return &ipamV1.GetDnsConfigResponse{
		Config: dnsConfigToProto(entity),
	}, nil
}

func (s *SystemService) UpdateDnsConfig(ctx context.Context, req *ipamV1.UpdateDnsConfigRequest) (*ipamV1.UpdateDnsConfigResponse, error) {
	timeoutMs := int32(5000)
	if req.TimeoutMs != nil {
		timeoutMs = *req.TimeoutMs
	}

	useSystemFallback := true
	if req.UseSystemDnsFallback != nil {
		useSystemFallback = *req.UseSystemDnsFallback
	}

	reverseDnsEnabled := true
	if req.ReverseDnsEnabled != nil {
		reverseDnsEnabled = *req.ReverseDnsEnabled
	}

	entity, err := s.dnsConfigRepo.CreateOrUpdate(
		ctx,
		req.GetTenantId(),
		req.DnsServers,
		timeoutMs,
		useSystemFallback,
		reverseDnsEnabled,
	)
	if err != nil {
		return nil, err
	}

	return &ipamV1.UpdateDnsConfigResponse{
		Config: dnsConfigToProto(entity),
	}, nil
}

func (s *SystemService) TestDnsConfig(ctx context.Context, req *ipamV1.TestDnsConfigRequest) (*ipamV1.TestDnsConfigResponse, error) {
	startTime := time.Now()

	// Determine which DNS servers to use
	var servers []string
	var timeoutMs int32 = 5000

	if len(req.DnsServers) > 0 {
		// Use servers from request for testing
		servers = req.DnsServers
	} else {
		// Use configured servers
		var err error
		servers, timeoutMs, _, err = s.dnsConfigRepo.GetDnsServers(ctx, req.GetTenantId())
		if err != nil {
			return &ipamV1.TestDnsConfigResponse{
				Success:      false,
				ErrorMessage: ptrString("Failed to get DNS config: " + err.Error()),
			}, nil
		}
	}

	// Perform reverse DNS lookup
	hostname, err := performReverseDNS(req.TestIp, servers, timeoutMs)
	latency := int32(time.Since(startTime).Milliseconds())

	if err != nil {
		return &ipamV1.TestDnsConfigResponse{
			Success:      false,
			ErrorMessage: ptrString(err.Error()),
			LatencyMs:    &latency,
		}, nil
	}

	return &ipamV1.TestDnsConfigResponse{
		Success:   true,
		Hostname:  ptrString(hostname),
		LatencyMs: &latency,
	}, nil
}

func dnsConfigToProto(e *ent.DnsConfig) *ipamV1.DnsConfig {
	if e == nil {
		// Return default config
		return &ipamV1.DnsConfig{
			DnsServers:           []string{},
			TimeoutMs:            ptrInt32(5000),
			UseSystemDnsFallback: ptrBool(true),
			ReverseDnsEnabled:    ptrBool(true),
		}
	}

	result := &ipamV1.DnsConfig{
		Id:                   &e.ID,
		TenantId:             e.TenantID,
		DnsServers:           e.DNSServers,
		TimeoutMs:            ptrInt32(e.TimeoutMs),
		UseSystemDnsFallback: ptrBool(e.UseSystemDNSFallback),
		ReverseDnsEnabled:    ptrBool(e.ReverseDNSEnabled),
	}

	if e.CreateTime != nil {
		result.CreatedAt = timestamppb.New(*e.CreateTime)
	}
	if e.UpdateTime != nil {
		result.UpdatedAt = timestamppb.New(*e.UpdateTime)
	}

	return result
}

// performReverseDNS performs a reverse DNS lookup with optional custom DNS servers
func performReverseDNS(ip string, servers []string, timeoutMs int32) (string, error) {
	if len(servers) == 0 {
		// Use system default resolver
		names, err := net.LookupAddr(ip)
		if err != nil {
			return "", err
		}
		if len(names) > 0 {
			return names[0], nil
		}
		return "", nil
	}

	// Use custom resolver with specified servers
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Duration(timeoutMs) * time.Millisecond,
			}
			// Try each DNS server
			for _, server := range servers {
				addr := server
				if _, _, err := net.SplitHostPort(server); err != nil {
					addr = net.JoinHostPort(server, "53")
				}
				conn, err := d.DialContext(ctx, "udp", addr)
				if err == nil {
					return conn, nil
				}
			}
			return nil, net.UnknownNetworkError("no DNS server available")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		return "", err
	}
	if len(names) > 0 {
		return names[0], nil
	}
	return "", nil
}

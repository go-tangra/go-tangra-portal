package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/biz"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/ipscanjob"
)

// IpScanService implements the IpScanService gRPC interface
type IpScanService struct {
	ipamV1.UnimplementedIpScanServiceServer

	log           *log.Helper
	scanJobRepo   *data.IpScanJobRepo
	subnetRepo    *data.SubnetRepo
	ipAddressRepo *data.IpAddressRepo
}

// NewIpScanService creates a new IpScanService
func NewIpScanService(
	ctx *bootstrap.Context,
	scanJobRepo *data.IpScanJobRepo,
	subnetRepo *data.SubnetRepo,
	ipAddressRepo *data.IpAddressRepo,
) *IpScanService {
	return &IpScanService{
		log:           ctx.NewLoggerHelper("ipam/service/ip_scan"),
		scanJobRepo:   scanJobRepo,
		subnetRepo:    subnetRepo,
		ipAddressRepo: ipAddressRepo,
	}
}

// StartScan starts a new scan for a subnet
func (s *IpScanService) StartScan(ctx context.Context, req *ipamV1.StartScanRequest) (*ipamV1.StartScanResponse, error) {
	tenantID := req.GetTenantId()
	subnetID := req.GetSubnetId()

	// Get the subnet
	subnet, err := s.subnetRepo.GetByID(ctx, subnetID)
	if err != nil {
		return nil, err
	}
	if subnet == nil {
		return nil, ipamV1.ErrorSubnetNotFound("subnet not found")
	}

	// Verify tenant access
	if subnet.TenantID != nil && *subnet.TenantID != tenantID {
		return nil, ipamV1.ErrorSubnetNotFound("subnet not found")
	}

	// Check if there's already an active scan
	hasActive, err := s.scanJobRepo.HasActiveScan(ctx, tenantID, subnetID)
	if err != nil {
		return nil, err
	}
	if hasActive {
		return nil, ipamV1.ErrorScanAlreadyInProgress("scan already in progress for this subnet")
	}

	// Validate CIDR for scanning
	if err := biz.ValidateCIDRForScanning(subnet.Cidr); err != nil {
		if err.Error() == "IPv6 subnets not supported for scanning" {
			return nil, ipamV1.ErrorIpv6NotSupported("IPv6 subnets not supported for scanning")
		}
		return nil, ipamV1.ErrorSubnetTooLarge("subnet too large for scanning: %s", err.Error())
	}

	// Calculate total addresses
	totalAddresses, err := biz.GetHostAddressCount(subnet.Cidr)
	if err != nil {
		return nil, ipamV1.ErrorInternalServerError("failed to calculate address count: %s", err.Error())
	}

	// Build scan config
	var scanConfig *data.ScanConfig
	if req.ScanConfig != nil {
		scanConfig = &data.ScanConfig{}
		if req.ScanConfig.TimeoutMs != nil {
			scanConfig.TimeoutMs = *req.ScanConfig.TimeoutMs
		}
		if req.ScanConfig.Concurrency != nil {
			scanConfig.Concurrency = *req.ScanConfig.Concurrency
		}
		if req.ScanConfig.SkipReverseDns != nil {
			scanConfig.SkipReverseDNS = *req.ScanConfig.SkipReverseDns
		}
		if req.ScanConfig.TcpProbePorts != nil {
			scanConfig.TCPProbePorts = *req.ScanConfig.TcpProbePorts
		}
	}

	// Create the scan job
	job, err := s.scanJobRepo.Create(ctx, tenantID, subnetID, ipscanjob.TriggeredByMANUAL, totalAddresses, scanConfig)
	if err != nil {
		return nil, err
	}

	return &ipamV1.StartScanResponse{
		Job: scanJobToProto(job),
	}, nil
}

// GetScanJob gets a scan job by ID
func (s *IpScanService) GetScanJob(ctx context.Context, req *ipamV1.GetScanJobRequest) (*ipamV1.GetScanJobResponse, error) {
	job, err := s.scanJobRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if job == nil {
		return nil, ipamV1.ErrorScanJobNotFound("scan job not found")
	}

	return &ipamV1.GetScanJobResponse{
		Job: scanJobToProto(job),
	}, nil
}

// ListScanJobs lists scan jobs for a subnet
func (s *IpScanService) ListScanJobs(ctx context.Context, req *ipamV1.ListScanJobsRequest) (*ipamV1.ListScanJobsResponse, error) {
	if req.SubnetId == nil || *req.SubnetId == "" {
		return nil, ipamV1.ErrorBadRequest("subnet_id is required")
	}

	page := int(req.GetPage())
	pageSize := int(req.GetPageSize())

	jobs, total, err := s.scanJobRepo.ListBySubnet(ctx, req.GetTenantId(), *req.SubnetId, page, pageSize)
	if err != nil {
		return nil, err
	}

	items := make([]*ipamV1.IpScanJob, len(jobs))
	for i, job := range jobs {
		items[i] = scanJobToProto(job)
	}

	return &ipamV1.ListScanJobsResponse{
		Items: items,
		Total: ptrInt32(int32(total)),
	}, nil
}

// CancelScan cancels a running or pending scan
func (s *IpScanService) CancelScan(ctx context.Context, req *ipamV1.CancelScanRequest) (*ipamV1.CancelScanResponse, error) {
	job, err := s.scanJobRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if job == nil {
		return nil, ipamV1.ErrorScanJobNotFound("scan job not found")
	}

	// Can only cancel pending or scanning jobs
	if job.Status != ipscanjob.StatusPENDING && job.Status != ipscanjob.StatusSCANNING {
		return nil, ipamV1.ErrorBadRequest("can only cancel pending or scanning jobs")
	}

	updatedJob, err := s.scanJobRepo.Cancel(ctx, job.ID)
	if err != nil {
		return nil, err
	}

	return &ipamV1.CancelScanResponse{
		Job: scanJobToProto(updatedJob),
	}, nil
}

// Helper function to convert ent entity to proto
func scanJobToProto(e *ent.IpScanJob) *ipamV1.IpScanJob {
	if e == nil {
		return nil
	}

	status := statusToProto(e.Status)
	triggeredBy := triggeredByToProto(e.TriggeredBy)

	result := &ipamV1.IpScanJob{
		Id:             &e.ID,
		SubnetId:       &e.SubnetID,
		Status:         &status,
		Progress:       &e.Progress,
		StatusMessage:  ptrString(e.StatusMessage),
		TotalAddresses: &e.TotalAddresses,
		ScannedCount:   &e.ScannedCount,
		AliveCount:     &e.AliveCount,
		NewCount:       &e.NewCount,
		UpdatedCount:   &e.UpdatedCount,
		TriggeredBy:    &triggeredBy,
		RetryCount:     &e.RetryCount,
		MaxRetries:     &e.MaxRetries,
		TimeoutMs:      &e.TimeoutMs,
		Concurrency:    &e.Concurrency,
		SkipReverseDns: &e.SkipReverseDNS,
		TcpProbePorts:  &e.TCPProbePorts,
		CreatedBy:      e.CreateBy,
	}

	if e.TenantID != nil {
		result.TenantId = e.TenantID
	}

	if e.StartedAt != nil {
		result.StartedAt = timestamppb.New(*e.StartedAt)
	}
	if e.CompletedAt != nil {
		result.CompletedAt = timestamppb.New(*e.CompletedAt)
	}
	if e.CreateTime != nil {
		result.CreatedAt = timestamppb.New(*e.CreateTime)
	}
	if e.UpdateTime != nil {
		result.UpdatedAt = timestamppb.New(*e.UpdateTime)
	}

	return result
}

func statusToProto(s ipscanjob.Status) ipamV1.IpScanJobStatus {
	switch s {
	case ipscanjob.StatusPENDING:
		return ipamV1.IpScanJobStatus_IP_SCAN_JOB_STATUS_PENDING
	case ipscanjob.StatusSCANNING:
		return ipamV1.IpScanJobStatus_IP_SCAN_JOB_STATUS_SCANNING
	case ipscanjob.StatusCOMPLETED:
		return ipamV1.IpScanJobStatus_IP_SCAN_JOB_STATUS_COMPLETED
	case ipscanjob.StatusFAILED:
		return ipamV1.IpScanJobStatus_IP_SCAN_JOB_STATUS_FAILED
	case ipscanjob.StatusCANCELLED:
		return ipamV1.IpScanJobStatus_IP_SCAN_JOB_STATUS_CANCELLED
	default:
		return ipamV1.IpScanJobStatus_IP_SCAN_JOB_STATUS_UNSPECIFIED
	}
}

func triggeredByToProto(t ipscanjob.TriggeredBy) ipamV1.IpScanJobTrigger {
	switch t {
	case ipscanjob.TriggeredByAUTO:
		return ipamV1.IpScanJobTrigger_IP_SCAN_JOB_TRIGGER_AUTO
	case ipscanjob.TriggeredByMANUAL:
		return ipamV1.IpScanJobTrigger_IP_SCAN_JOB_TRIGGER_MANUAL
	default:
		return ipamV1.IpScanJobTrigger_IP_SCAN_JOB_TRIGGER_UNSPECIFIED
	}
}

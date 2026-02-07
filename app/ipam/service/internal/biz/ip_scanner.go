package biz

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// MaxScanAddresses is the maximum number of addresses that can be scanned
	MaxScanAddresses = 1024

	// DefaultTimeout is the default TCP probe timeout
	DefaultTimeout = 1000 * time.Millisecond

	// DefaultConcurrency is the default number of parallel probes
	DefaultConcurrency = 50

	// DefaultPorts are the default ports to probe
	DefaultPorts = "22,80,443,3389,445"
)

// ScanConfig holds configuration for a scan
type ScanConfig struct {
	TimeoutMs            int32
	Concurrency          int32
	SkipReverseDNS       bool
	TCPProbePorts        string
	DNSServers           []string // Custom DNS servers for reverse lookup
	DNSTimeoutMs         int32    // Timeout for DNS queries
	UseSystemDNSFallback bool     // Whether to use system DNS as fallback
}

// ScanResult represents the result of scanning a single IP
type ScanResult struct {
	Address  string
	Alive    bool
	Hostname string
	Ports    []int // Ports that responded
}

// ScanProgress represents the current progress of a scan
type ScanProgress struct {
	TotalAddresses int64
	ScannedCount   int64
	AliveCount     int64
	NewCount       int64
	UpdatedCount   int64
	Progress       int32
}

// ProgressCallback is called during scanning to report progress
type ProgressCallback func(progress ScanProgress)

// Scanner performs network scanning
type Scanner struct {
	config ScanConfig
	ports  []int
}

// NewScanner creates a new Scanner with the given config
func NewScanner(config ScanConfig) *Scanner {
	s := &Scanner{
		config: config,
	}

	// Parse ports
	portsStr := config.TCPProbePorts
	if portsStr == "" {
		portsStr = DefaultPorts
	}
	s.ports = parsePorts(portsStr)

	return s
}

// parsePorts parses a comma-separated port string
func parsePorts(portsStr string) []int {
	parts := strings.Split(portsStr, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if port, err := strconv.Atoi(p); err == nil && port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		// Default ports
		ports = []int{22, 80, 443, 3389, 445}
	}
	return ports
}

// GenerateIPs generates all host IPs in a CIDR range
// Excludes network and broadcast addresses for IPv4
func GenerateIPs(cidr string) ([]net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	// Check if IPv6
	if ipNet.IP.To4() == nil {
		return nil, fmt.Errorf("IPv6 subnets not supported for scanning")
	}

	// Calculate the number of addresses
	ones, bits := ipNet.Mask.Size()
	numAddresses := 1 << (bits - ones)

	// Check size limit
	if numAddresses > MaxScanAddresses+2 { // +2 for network and broadcast
		return nil, fmt.Errorf("subnet too large: %d addresses (max %d)", numAddresses-2, MaxScanAddresses)
	}

	// Special case for /31 and /32
	if ones >= 31 {
		ips := make([]net.IP, 0, numAddresses)
		ip := ipNet.IP.To4()
		start := binary.BigEndian.Uint32(ip)
		for i := 0; i < numAddresses; i++ {
			newIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(newIP, start+uint32(i))
			ips = append(ips, newIP)
		}
		return ips, nil
	}

	// For /30 and larger, exclude network and broadcast
	ips := make([]net.IP, 0, numAddresses-2)
	ip := ipNet.IP.To4()
	start := binary.BigEndian.Uint32(ip)

	for i := 1; i < numAddresses-1; i++ {
		newIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(newIP, start+uint32(i))
		ips = append(ips, newIP)
	}

	return ips, nil
}

// ValidateCIDRForScanning validates if a CIDR can be scanned
func ValidateCIDRForScanning(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	// Check if IPv6
	if ipNet.IP.To4() == nil {
		return fmt.Errorf("IPv6 subnets not supported for scanning")
	}

	// Calculate the number of addresses
	ones, bits := ipNet.Mask.Size()
	numAddresses := 1 << (bits - ones)

	// Exclude network and broadcast for standard subnets
	hostCount := numAddresses
	if ones < 31 {
		hostCount = numAddresses - 2
	}

	if hostCount > MaxScanAddresses {
		return fmt.Errorf("subnet too large: %d addresses (max %d)", hostCount, MaxScanAddresses)
	}

	return nil
}

// ScanSubnet scans all IPs in the given CIDR range
func (s *Scanner) ScanSubnet(ctx context.Context, cidr string, progressCb ProgressCallback) ([]ScanResult, error) {
	// Generate IPs
	ips, err := GenerateIPs(cidr)
	if err != nil {
		return nil, err
	}

	totalAddresses := int64(len(ips))
	if totalAddresses == 0 {
		return []ScanResult{}, nil
	}

	// Configure concurrency
	concurrency := int(s.config.Concurrency)
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency > len(ips) {
		concurrency = len(ips)
	}

	// Configure timeout
	timeout := time.Duration(s.config.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	// Results collection
	results := make([]ScanResult, 0, len(ips))
	resultsMu := sync.Mutex{}

	// Progress tracking
	var scannedCount int64
	var aliveCount int64

	// Work queue
	ipChan := make(chan net.IP, len(ips))
	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-ipChan:
					if !ok {
						return
					}

					result := s.scanIP(ctx, ip, timeout)

					// Update counters
					atomic.AddInt64(&scannedCount, 1)
					if result.Alive {
						atomic.AddInt64(&aliveCount, 1)
					}

					// Collect result
					resultsMu.Lock()
					results = append(results, result)
					resultsMu.Unlock()

					// Report progress
					if progressCb != nil {
						current := atomic.LoadInt64(&scannedCount)
						progress := int32(float64(current) / float64(totalAddresses) * 100)
						progressCb(ScanProgress{
							TotalAddresses: totalAddresses,
							ScannedCount:   current,
							AliveCount:     atomic.LoadInt64(&aliveCount),
							Progress:       progress,
						})
					}
				}
			}
		}()
	}

	// Wait for completion
	wg.Wait()

	// Check if cancelled
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return results, nil
}

// scanIP scans a single IP address
func (s *Scanner) scanIP(ctx context.Context, ip net.IP, timeout time.Duration) ScanResult {
	address := ip.String()
	result := ScanResult{
		Address: address,
		Alive:   false,
		Ports:   []int{},
	}

	// Probe each port
	for _, port := range s.ports {
		select {
		case <-ctx.Done():
			return result
		default:
		}

		if s.probePort(ctx, address, port, timeout) {
			result.Alive = true
			result.Ports = append(result.Ports, port)
			// Once we find one open port, we know it's alive
			// Continue to find other open ports for information
		}
	}

	// If alive and not skipping DNS, do reverse lookup
	if result.Alive && !s.config.SkipReverseDNS {
		result.Hostname = s.reverseDNS(address)
	}

	return result
}

// probePort attempts to connect to a specific port
func (s *Scanner) probePort(ctx context.Context, address string, port int, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%d", address, port)

	// Create a context with timeout
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Use DialContext for cancellation support
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", target)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// reverseDNS performs a reverse DNS lookup using custom DNS servers if configured
func (s *Scanner) reverseDNS(address string) string {
	// Determine timeout
	timeout := time.Duration(s.config.DNSTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var names []string
	var err error

	if len(s.config.DNSServers) > 0 {
		// Use custom DNS servers
		names, err = s.reverseDNSWithServers(address, s.config.DNSServers, timeout)

		// Fall back to system DNS if configured and custom lookup failed
		if (err != nil || len(names) == 0) && s.config.UseSystemDNSFallback {
			names, err = net.LookupAddr(address)
		}
	} else {
		// Use system default resolver
		names, err = net.LookupAddr(address)
	}

	if err != nil || len(names) == 0 {
		return ""
	}

	// Return the first hostname, stripping trailing dot
	hostname := names[0]
	return strings.TrimSuffix(hostname, ".")
}

// reverseDNSWithServers performs reverse DNS using specified servers
func (s *Scanner) reverseDNSWithServers(address string, servers []string, timeout time.Duration) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: timeout,
			}
			// Try each DNS server
			for _, server := range servers {
				serverAddr := server
				if _, _, err := net.SplitHostPort(server); err != nil {
					serverAddr = net.JoinHostPort(server, "53")
				}
				conn, err := d.DialContext(ctx, "udp", serverAddr)
				if err == nil {
					return conn, nil
				}
			}
			return nil, net.UnknownNetworkError("no DNS server available")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return resolver.LookupAddr(ctx, address)
}

// QuickScan performs a quick scan to just check if an IP is alive
func QuickScan(ctx context.Context, address string, timeout time.Duration) bool {
	ports := []int{22, 80, 443, 3389, 445}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		target := net.JoinHostPort(address, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}

// GetHostAddressCount returns the number of host addresses in a CIDR
func GetHostAddressCount(cidr string) (int64, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, fmt.Errorf("invalid CIDR: %w", err)
	}

	// Check if IPv6
	if ipNet.IP.To4() == nil {
		return 0, fmt.Errorf("IPv6 subnets not supported")
	}

	ones, bits := ipNet.Mask.Size()
	numAddresses := int64(1 << (bits - ones))

	// Exclude network and broadcast for standard subnets
	if ones < 31 {
		numAddresses -= 2
	}

	return numAddresses, nil
}

package machine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

// GetClientID returns a unique client ID based on machine identification
// Priority: /etc/machine-id → hostname hash → "unknown-client"
func GetClientID() string {
	// Try to read machine-id (Linux)
	if machineID, err := os.ReadFile("/etc/machine-id"); err == nil {
		id := strings.TrimSpace(string(machineID))
		if id != "" {
			// Return first 12 characters of machine-id
			if len(id) > 12 {
				return id[:12]
			}
			return id
		}
	}

	// Try /var/lib/dbus/machine-id as fallback
	if machineID, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		id := strings.TrimSpace(string(machineID))
		if id != "" {
			if len(id) > 12 {
				return id[:12]
			}
			return id
		}
	}

	// Fallback: hash of hostname + username + OS
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows
	}

	data := fmt.Sprintf("%s-%s-%s", hostname, username, runtime.GOOS)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:12]
}

// GetHostname returns the system hostname
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// GetMetadata returns system metadata for registration
func GetMetadata() map[string]string {
	metadata := make(map[string]string)

	metadata["os"] = runtime.GOOS
	metadata["arch"] = runtime.GOARCH
	metadata["goversion"] = runtime.Version()

	if hostname, err := os.Hostname(); err == nil {
		metadata["hostname"] = hostname
	}

	// Try to get kernel version on Linux
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/version"); err == nil {
			version := strings.TrimSpace(string(data))
			// Extract just the kernel version
			parts := strings.Fields(version)
			if len(parts) >= 3 {
				metadata["kernel"] = parts[2]
			}
		}

		// Try to get distribution info
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					name := strings.TrimPrefix(line, "PRETTY_NAME=")
					name = strings.Trim(name, "\"")
					metadata["distro"] = name
					break
				}
			}
		}
	}

	return metadata
}

// GetLocalIPAddresses returns non-loopback, non-link-local IP addresses
func GetLocalIPAddresses() []string {
	var ips []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range interfaces {
		// Skip down interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		// Skip loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil {
				continue
			}

			// Skip loopback
			if ip.IsLoopback() {
				continue
			}

			// Skip link-local
			if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}

			// Convert to string
			ipStr := ip.String()
			if ipStr != "" {
				ips = append(ips, ipStr)
			}
		}
	}

	return ips
}

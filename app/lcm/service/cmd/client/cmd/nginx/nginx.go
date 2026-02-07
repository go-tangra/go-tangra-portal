package nginx

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/cmd"
	nginxPkg "github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/internal/nginx"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/internal/storage"
)

var (
	// Flags for nginx command
	certName     string
	domains      []string
	httpsOnly    bool
	http2        bool
	hsts         bool
	hstsMaxAge   int
	ocspStapling bool
	sslProtocols string
	sslCiphers   string
	dhParamPath  string
	noBackup     bool
	dryRun       bool
	noReload     bool
	nginxPath    string
)

// nginxCmd represents the nginx command
var nginxCmd = &cobra.Command{
	Use:   "nginx",
	Short: "Nginx SSL/TLS configuration management",
	Long: `Manage Nginx SSL/TLS configuration with LCM certificates.

This command provides certbot-like functionality for Nginx:
- Auto-detect Nginx installation and configuration
- Install certificates from LCM storage into Nginx
- Configure SSL/TLS settings (protocols, ciphers, HSTS, etc.)
- Reload Nginx to apply changes

Examples:
  # Show nginx installation info
  lcm-client nginx info

  # Install a certificate into nginx
  lcm-client nginx install --cert-name example.com

  # Install with custom domains
  lcm-client nginx install --cert-name example.com --domain www.example.com --domain api.example.com

  # Dry run (show what would be done)
  lcm-client nginx install --cert-name example.com --dry-run

  # Show current SSL status
  lcm-client nginx status
`,
}

// infoCmd shows nginx installation information
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show Nginx installation information",
	Long:  `Discover and display information about the Nginx installation.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInfo()
	},
}

// installCmd installs SSL certificates into nginx
var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install SSL certificate into Nginx",
	Long: `Install an LCM certificate into Nginx configuration.

This command will:
1. Find the certificate in LCM storage
2. Locate the corresponding server block in Nginx config
3. Configure SSL/TLS settings
4. Create a backup of the original configuration
5. Test the new configuration
6. Reload Nginx to apply changes

The certificate must already exist in LCM storage (downloaded via 'lcm-client download').
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if certName == "" {
			return fmt.Errorf("--cert-name is required")
		}
		return runInstall()
	},
}

// statusCmd shows current SSL configuration status
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Nginx SSL configuration status",
	Long:  `Display the current SSL/TLS configuration status for all server blocks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStatus()
	},
}

// listCertsCmd lists available certificates
var listCertsCmd = &cobra.Command{
	Use:   "list-certs",
	Short: "List available certificates in LCM storage",
	Long:  `List all certificates that are available in LCM storage for installation.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runListCerts()
	},
}

func init() {
	// Add nginx command to root
	cmd.GetRootCmd().AddCommand(nginxCmd)

	// Add subcommands
	nginxCmd.AddCommand(infoCmd)
	nginxCmd.AddCommand(installCmd)
	nginxCmd.AddCommand(statusCmd)
	nginxCmd.AddCommand(listCertsCmd)

	// Install command flags
	installCmd.Flags().StringVar(&certName, "cert-name", "", "Name of the certificate in LCM storage (required)")
	installCmd.Flags().StringArrayVar(&domains, "domain", nil, "Domain(s) to configure (defaults to certificate's DNS names)")
	installCmd.Flags().BoolVar(&httpsOnly, "https-only", false, "Remove HTTP listeners after installation")
	installCmd.Flags().BoolVar(&http2, "http2", true, "Enable HTTP/2")
	installCmd.Flags().BoolVar(&hsts, "hsts", true, "Enable HSTS header")
	installCmd.Flags().IntVar(&hstsMaxAge, "hsts-max-age", 31536000, "HSTS max-age in seconds")
	installCmd.Flags().BoolVar(&ocspStapling, "ocsp-stapling", true, "Enable OCSP stapling")
	installCmd.Flags().StringVar(&sslProtocols, "ssl-protocols", "TLSv1.2 TLSv1.3", "SSL protocols to enable")
	installCmd.Flags().StringVar(&sslCiphers, "ssl-ciphers", "", "SSL ciphers (leave empty for default)")
	installCmd.Flags().StringVar(&dhParamPath, "dhparam", "", "Path to DH parameters file")
	installCmd.Flags().BoolVar(&noBackup, "no-backup", false, "Don't create backup of modified files")
	installCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	installCmd.Flags().BoolVar(&noReload, "no-reload", false, "Don't reload Nginx after installation")

	// Global nginx flags
	nginxCmd.PersistentFlags().StringVar(&nginxPath, "nginx-bin", "", "Path to nginx binary (auto-detected if empty)")
}

// runInfo displays nginx installation information
func runInfo() error {
	fmt.Println("Discovering Nginx installation...")

	info, err := nginxPkg.Discover()
	if err != nil {
		return fmt.Errorf("failed to discover nginx: %w", err)
	}

	fmt.Println()
	fmt.Println("=== Nginx Installation ===")
	fmt.Print(info.String())

	// List configuration files
	files, err := info.GetIncludedFiles()
	if err == nil && len(files) > 0 {
		fmt.Printf("\nConfiguration files (%d):\n", len(files))
		for _, f := range files {
			fmt.Printf("  - %s\n", f)
		}
	}

	return nil
}

// runInstall installs SSL certificates into nginx
func runInstall() error {
	// Discover nginx
	fmt.Println("Discovering Nginx installation...")
	nginxInfo, err := nginxPkg.Discover()
	if err != nil {
		return fmt.Errorf("failed to discover nginx: %w", err)
	}
	fmt.Printf("Found Nginx %s at %s\n", nginxInfo.Version, nginxInfo.BinaryPath)

	// Initialize certificate store
	configDir := cmd.GetConfigDir()
	certStore, err := storage.NewCertStore(configDir)
	if err != nil {
		return fmt.Errorf("failed to initialize certificate store: %w", err)
	}

	// Check if certificate exists
	if !certStore.CertificateExists(certName) {
		return fmt.Errorf("certificate '%s' not found in storage\n\nUse 'lcm-client list-certs' to see available certificates\nOr download a certificate with 'lcm-client download'", certName)
	}

	// Create installer with options
	options := &nginxPkg.InstallOptions{
		CertName:     certName,
		Domains:      domains,
		HTTPSOnly:    httpsOnly,
		HTTP2:        http2,
		HSTS:         hsts,
		HSTSMaxAge:   hstsMaxAge,
		OCSPStapling: ocspStapling,
		SSLProtocols: sslProtocols,
		SSLCiphers:   sslCiphers,
		DHParamPath:  dhParamPath,
		CreateBackup: !noBackup,
		DryRun:       dryRun,
		ReloadNginx:  !noReload,
	}

	installer := nginxPkg.NewInstaller(nginxInfo, certStore, options)

	// Run installation
	if dryRun {
		fmt.Println("\n=== DRY RUN MODE ===")
	}
	fmt.Println("\nInstalling certificate...")

	result, err := installer.Install()
	if err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	// Print result
	fmt.Println()
	fmt.Print(result.Summary())

	if !result.Success {
		os.Exit(1)
	}

	return nil
}

// runStatus shows SSL configuration status
func runStatus() error {
	// Discover nginx
	nginxInfo, err := nginxPkg.Discover()
	if err != nil {
		return fmt.Errorf("failed to discover nginx: %w", err)
	}

	// Parse configuration
	parsedConfig, err := nginxPkg.ParseConfig(nginxInfo)
	if err != nil {
		return fmt.Errorf("failed to parse nginx config: %w", err)
	}

	fmt.Println("=== Nginx SSL Status ===")
	fmt.Printf("Nginx Version: %s\n", nginxInfo.Version)
	fmt.Printf("Configuration: %s\n", nginxInfo.ConfigPath)
	fmt.Printf("Running: %v\n", nginxInfo.IsRunning)
	fmt.Println()

	// List server blocks
	httpsBlocks := parsedConfig.FindHTTPSServerBlocks()
	httpBlocks := parsedConfig.FindHTTPServerBlocks()

	if len(httpsBlocks) > 0 {
		fmt.Printf("=== HTTPS Server Blocks (%d) ===\n", len(httpsBlocks))
		for _, block := range httpsBlocks {
			printServerBlockStatus(block)
		}
	}

	if len(httpBlocks) > 0 {
		fmt.Printf("\n=== HTTP Server Blocks (%d) ===\n", len(httpBlocks))
		for _, block := range httpBlocks {
			printServerBlockStatus(block)
		}
	}

	// Summary
	fmt.Println("\n=== Summary ===")
	fmt.Printf("Total server blocks: %d\n", len(parsedConfig.ServerBlocks))
	fmt.Printf("HTTPS enabled: %d\n", len(httpsBlocks))
	fmt.Printf("HTTP only: %d\n", len(httpBlocks)-len(httpsBlocks))

	// List all domains
	domains := parsedConfig.GetAllDomains()
	if len(domains) > 0 {
		fmt.Printf("\nConfigured domains:\n")
		for _, d := range domains {
			// Find if domain has SSL
			block := parsedConfig.FindServerBlockByDomain(d)
			sslStatus := "HTTP"
			if block != nil && block.SSLEnabled {
				sslStatus = "HTTPS"
			}
			fmt.Printf("  - %s [%s]\n", d, sslStatus)
		}
	}

	return nil
}

// runListCerts lists available certificates in storage
func runListCerts() error {
	configDir := cmd.GetConfigDir()
	certStore, err := storage.NewCertStore(configDir)
	if err != nil {
		return fmt.Errorf("failed to initialize certificate store: %w", err)
	}

	certs, err := certStore.ListCertificates()
	if err != nil {
		return fmt.Errorf("failed to list certificates: %w", err)
	}

	if len(certs) == 0 {
		fmt.Println("No certificates found in storage.")
		fmt.Println("\nUse 'lcm-client download' to download certificates from the LCM server.")
		return nil
	}

	fmt.Println("=== Available Certificates ===")
	for _, name := range certs {
		metadata, err := certStore.LoadMetadata(name)
		if err != nil || metadata == nil {
			fmt.Printf("\n%s (no metadata)\n", name)
			continue
		}

		fmt.Printf("\n%s\n", name)
		fmt.Printf("  Common Name: %s\n", metadata.CommonName)
		if len(metadata.DNSNames) > 0 {
			fmt.Printf("  DNS Names: %s\n", strings.Join(metadata.DNSNames, ", "))
		}
		fmt.Printf("  Expires: %s\n", metadata.ExpiresAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Serial: %s\n", metadata.SerialNumber)
	}

	return nil
}

// printServerBlockStatus prints status for a single server block
func printServerBlockStatus(block *nginxPkg.ServerBlock) {
	fmt.Printf("\nFile: %s (lines %d-%d)\n", block.FilePath, block.LineStart, block.LineEnd)

	if len(block.ServerNames) > 0 {
		fmt.Printf("  Domains: %s\n", strings.Join(block.ServerNames, ", "))
	} else {
		fmt.Printf("  Domains: (none)\n")
	}

	// Listen directives
	var listens []string
	for _, l := range block.Listen {
		listens = append(listens, l.RawValue)
	}
	if len(listens) > 0 {
		fmt.Printf("  Listen: %s\n", strings.Join(listens, ", "))
	}

	// SSL status
	if block.SSLEnabled {
		fmt.Printf("  SSL: ✓ enabled\n")
		if block.SSLCertPath != "" {
			fmt.Printf("    Certificate: %s\n", block.SSLCertPath)
		}
		if block.SSLKeyPath != "" {
			fmt.Printf("    Key: %s\n", block.SSLKeyPath)
		}
	} else {
		fmt.Printf("  SSL: ✗ not configured\n")
	}
}

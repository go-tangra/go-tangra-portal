package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/internal/machine"
)

var (
	// Global flags
	serverAddr string
	clientID   string
	certFile   string
	keyFile    string
	caFile     string
	configDir  string
	configFile string
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "lcm-client",
	Short: "LCM Client - Certificate lifecycle management client",
	Long: `LCM Client is a command-line tool for managing certificates with the LCM server.

It works like a Puppet agent - register with the server, get a certificate,
and use that certificate for subsequent authenticated operations.

Example workflow:
  1. Register:  lcm-client register --secret <shared-secret>
  2. Status:    lcm-client status --request-id <id>
  3. Download:  lcm-client download --request-id <id>
`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initConfig()
	},
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

// GetRootCmd returns the root command for subcommand registration
func GetRootCmd() *cobra.Command {
	return rootCmd
}

// GetServerAddr returns the server address
func GetServerAddr() string {
	return viper.GetString("server")
}

// GetClientID returns the client ID (from flag, config, or auto-generated)
func GetClientID() string {
	id := viper.GetString("client-id")
	if id == "" {
		id = machine.GetClientID()
	}
	return id
}

// GetConfigDir returns the config directory path (expanded)
func GetConfigDir() string {
	dir := viper.GetString("config-dir")
	expanded, err := expandPath(dir)
	if err != nil {
		return dir
	}
	return expanded
}

// GetCertFile returns the certificate file path
func GetCertFile() string {
	return viper.GetString("cert")
}

// GetKeyFile returns the key file path
func GetKeyFile() string {
	return viper.GetString("key")
}

// GetCAFile returns the CA file path
func GetCAFile() string {
	return viper.GetString("ca")
}

// EnsureConfigDir ensures the config directory exists
func EnsureConfigDir() error {
	dir := GetConfigDir()
	return os.MkdirAll(dir, 0755)
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "localhost:9000", "LCM server address")
	rootCmd.PersistentFlags().StringVar(&clientID, "client-id", "", "Client ID (auto-generated from machine ID if empty)")
	rootCmd.PersistentFlags().StringVar(&certFile, "cert", "", "Client certificate file path")
	rootCmd.PersistentFlags().StringVar(&keyFile, "key", "", "Client private key file path")
	rootCmd.PersistentFlags().StringVar(&caFile, "ca", "", "CA certificate file path")
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "~/.lcm-client", "Configuration directory")
	rootCmd.PersistentFlags().StringVar(&configFile, "config-file", "", "Configuration file path")

	// Bind flags to viper
	_ = viper.BindPFlag("server", rootCmd.PersistentFlags().Lookup("server"))
	_ = viper.BindPFlag("client-id", rootCmd.PersistentFlags().Lookup("client-id"))
	_ = viper.BindPFlag("cert", rootCmd.PersistentFlags().Lookup("cert"))
	_ = viper.BindPFlag("key", rootCmd.PersistentFlags().Lookup("key"))
	_ = viper.BindPFlag("ca", rootCmd.PersistentFlags().Lookup("ca"))
	_ = viper.BindPFlag("config-dir", rootCmd.PersistentFlags().Lookup("config-dir"))
}

func initConfig() error {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		// Search for config in config directory
		dir := GetConfigDir()
		viper.AddConfigPath(dir)
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Read config file if exists (ignore errors if not found)
	_ = viper.ReadInConfig()

	// Set default cert paths based on client ID if not specified
	clientID := GetClientID()
	configDir := GetConfigDir()

	if viper.GetString("cert") == "" {
		viper.Set("cert", filepath.Join(configDir, fmt.Sprintf("%s.crt", clientID)))
	}
	if viper.GetString("key") == "" {
		viper.Set("key", filepath.Join(configDir, fmt.Sprintf("%s.key", clientID)))
	}
	if viper.GetString("ca") == "" {
		viper.Set("ca", filepath.Join(configDir, "ca.crt"))
	}

	return nil
}

// expandPath expands tilde (~) to home directory
func expandPath(path string) (string, error) {
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	} else if path == "~" {
		return os.UserHomeDir()
	}
	return path, nil
}

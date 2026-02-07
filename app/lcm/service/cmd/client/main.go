package main

import (
	"fmt"
	"os"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/cmd"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/cmd/daemon"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/cmd/download"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/cmd/health"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/cmd/issuer"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/cmd/job"
	_ "github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/cmd/nginx" // nginx SSL/TLS management
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/cmd/register"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/cmd/status"
)

func main() {
	// Add subcommands to root
	rootCmd := cmd.GetRootCmd()
	rootCmd.AddCommand(register.Command)
	rootCmd.AddCommand(status.Command)
	rootCmd.AddCommand(download.Command)
	rootCmd.AddCommand(health.Command)
	rootCmd.AddCommand(issuer.Command)
	rootCmd.AddCommand(daemon.Command)
	rootCmd.AddCommand(job.Command)

	// Execute root command
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

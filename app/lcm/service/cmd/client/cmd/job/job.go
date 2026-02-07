package job

import (
	"github.com/spf13/cobra"
)

// Command is the job parent command
var Command = &cobra.Command{
	Use:   "job",
	Short: "Certificate job management commands",
	Long: `Manage certificate jobs - request, check status, get results, and cancel jobs.

Certificate jobs allow you to request certificates asynchronously. The server will
process the request and you can check the status later.

Example workflow:
  1. Request:  lcm-client job request --issuer my-issuer --cn example.com
  2. Status:   lcm-client job status --job-id <id>
  3. Result:   lcm-client job result --job-id <id>
`,
}

func init() {
	// Add subcommands
	Command.AddCommand(requestCmd)
	Command.AddCommand(statusCmd)
	Command.AddCommand(resultCmd)
	Command.AddCommand(listCmd)
	Command.AddCommand(cancelCmd)
}

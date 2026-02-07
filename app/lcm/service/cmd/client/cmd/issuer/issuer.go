package issuer

import (
	"github.com/spf13/cobra"
)

// Command is the issuer command - parent for issuer subcommands
var Command = &cobra.Command{
	Use:   "issuer",
	Short: "Manage certificate issuers",
	Long: `Manage certificate issuers for your tenant.

Issuers are configurations used to create certificates. They can be:
- self-signed: Creates certificates using a self-signed CA
- acme: Uses ACME protocol (Let's Encrypt, etc.) for certificates

This command requires mTLS authentication. Make sure you have registered
and downloaded your client certificate first.

Examples:
  lcm-client issuer list
  lcm-client issuer get my-issuer
  lcm-client issuer create --name my-issuer --type self-signed ...
  lcm-client issuer delete my-issuer
`,
}

func init() {
	// Add subcommands
	Command.AddCommand(listCmd)
	Command.AddCommand(getCmd)
	Command.AddCommand(createCmd)
	Command.AddCommand(deleteCmd)
}

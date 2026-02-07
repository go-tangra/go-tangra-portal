// Package providers registers all deployment providers.
// Import this package in main to register all providers.
package providers

import (
	// Import providers to register them
	_ "github.com/go-tangra/go-tangra-portal/app/deployer/service/pkg/deploy/providers/aws_acm"
	_ "github.com/go-tangra/go-tangra-portal/app/deployer/service/pkg/deploy/providers/bigip"
	_ "github.com/go-tangra/go-tangra-portal/app/deployer/service/pkg/deploy/providers/cloudflare"
	_ "github.com/go-tangra/go-tangra-portal/app/deployer/service/pkg/deploy/providers/dummy"
	_ "github.com/go-tangra/go-tangra-portal/app/deployer/service/pkg/deploy/providers/fortigate"
	_ "github.com/go-tangra/go-tangra-portal/app/deployer/service/pkg/deploy/providers/webhook"
)

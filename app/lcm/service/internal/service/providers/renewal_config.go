package providers

import (
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/conf"

	"github.com/tx7do/kratos-bootstrap/bootstrap"
)

// ProvideRenewalConfig extracts the RenewalConfig from the bootstrap context
func ProvideRenewalConfig(ctx *bootstrap.Context) *conf.RenewalConfig {
	customConfig, ok := ctx.GetCustomConfig("lcm")
	if !ok {
		return nil
	}
	lcmConfig, ok := customConfig.(*conf.LCM)
	if !ok || lcmConfig == nil {
		return nil
	}
	return lcmConfig.GetRenewal()
}

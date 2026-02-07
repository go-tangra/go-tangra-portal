package providers

import (
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/conf"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/crypto"

	"github.com/tx7do/kratos-bootstrap/bootstrap"
)

// ProvidePrivateKeyEncryptor creates a PrivateKeyEncryptor from the LCM config
func ProvidePrivateKeyEncryptor(ctx *bootstrap.Context) (*crypto.PrivateKeyEncryptor, error) {
	customConfig, ok := ctx.GetCustomConfig("lcm")
	if !ok {
		// No config, create disabled encryptor
		return crypto.NewPrivateKeyEncryptor("")
	}
	lcmConfig, ok := customConfig.(*conf.LCM)
	if !ok || lcmConfig == nil {
		return crypto.NewPrivateKeyEncryptor("")
	}
	return crypto.NewPrivateKeyEncryptor(lcmConfig.GetSharedSecret())
}

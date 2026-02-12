package data

import (
	"os"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"gopkg.in/yaml.v3"
)

// webAuthnYAMLConfig mirrors the "webauthn:" section in auth.yaml.
type webAuthnYAMLConfig struct {
	WebAuthn struct {
		RPDisplayName string   `yaml:"rp_display_name"`
		RPID          string   `yaml:"rp_id"`
		RPOrigins     []string `yaml:"rp_origins"`
	} `yaml:"webauthn"`
}

// configSearchPaths returns candidate auth.yaml paths ordered by priority.
func configSearchPaths() []string {
	paths := []string{
		"configs/auth.yaml",       // Docker: /app/configs/auth.yaml (CWD = /app)
		"../../configs/auth.yaml", // Local dev: cmd/server -> ../../configs
	}
	if dir := os.Getenv("ADMIN_CONFIGS_DIR"); dir != "" {
		paths = append([]string{dir + "/auth.yaml"}, paths...)
	}
	return paths
}

// NewWebAuthn reads the webauthn section from auth.yaml and creates a
// *webauthn.WebAuthn instance. Returns nil if not configured (graceful degradation).
func NewWebAuthn(ctx *bootstrap.Context) *webauthn.WebAuthn {
	logger := ctx.NewLoggerHelper("webauthn/provider/admin-service")

	var cfg webAuthnYAMLConfig
	var loaded bool
	for _, p := range configSearchPaths() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if err = yaml.Unmarshal(data, &cfg); err != nil {
			logger.Warnf("parse %s: %v", p, err)
			continue
		}
		loaded = true
		break
	}

	if !loaded || cfg.WebAuthn.RPID == "" {
		logger.Info("webauthn config not found or rp_id empty, WebAuthn disabled")
		return nil
	}

	rpDisplayName := cfg.WebAuthn.RPDisplayName
	if rpDisplayName == "" {
		rpDisplayName = "GoTangra"
	}

	wconfig := &webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          cfg.WebAuthn.RPID,
		RPOrigins:     cfg.WebAuthn.RPOrigins,
	}

	w, err := webauthn.New(wconfig)
	if err != nil {
		logger.Errorf("create webauthn instance: %v", err)
		return nil
	}

	logger.Infof("WebAuthn enabled: rpID=%s origins=%s", wconfig.RPID, strings.Join(wconfig.RPOrigins, ","))
	return w
}

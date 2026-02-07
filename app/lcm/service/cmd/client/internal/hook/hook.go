package hook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	scripts "github.com/tx7do/go-scripts"
)

// HookType represents different types of hooks
type HookType string

const (
	// HookDeploy is called after a certificate is obtained or renewed
	HookDeploy HookType = "deploy"
	// HookPreRenewal is called before attempting renewal
	HookPreRenewal HookType = "pre-renewal"
	// HookPostRenewal is called after successful renewal
	HookPostRenewal HookType = "post-renewal"
)

// ScriptType represents the type of script
type ScriptType string

const (
	ScriptTypeBash       ScriptType = "bash"
	ScriptTypeLua        ScriptType = "lua"
	ScriptTypeJavaScript ScriptType = "javascript"
)

// HookConfig contains configuration for hook execution
type HookConfig struct {
	// BashScript is a path to a bash script file
	BashScript string
	// ScriptFile is a path to a Lua or JavaScript script file
	ScriptFile string
	// ScriptType is the type of script (lua or javascript)
	ScriptType ScriptType
	// WorkDir is the working directory for script execution
	WorkDir string
	// Timeout is the maximum execution time
	Timeout time.Duration
	// Environment contains additional environment variables
	Environment map[string]string
}

// HookContext contains information passed to hooks
type HookContext struct {
	CertName      string   // Certificate name (e.g., hostname)
	CertPath      string   // Path to the certificate file
	KeyPath       string   // Path to the private key file
	ChainPath     string   // Path to the CA chain file
	FullChainPath string   // Path to the fullchain file
	CommonName    string   // Certificate common name
	DNSNames      []string // Certificate DNS names
	IPAddresses   []string // Certificate IP addresses
	SerialNumber  string   // Certificate serial number
	ExpiresAt     string   // Certificate expiry time (RFC3339)
	IsRenewal     bool     // True if this is a renewal
}

// HookResult contains the result of a hook execution
type HookResult struct {
	Success  bool
	Output   string
	ErrorMsg string
	Duration time.Duration
	ExitCode int
}

// Runner executes hooks
type Runner struct {
	defaultTimeout time.Duration
	luaPool        *scripts.AutoGrowEnginePool
	jsPool         *scripts.AutoGrowEnginePool
}

// NewRunner creates a new hook runner
func NewRunner() *Runner {
	return &Runner{
		defaultTimeout: 5 * time.Minute,
	}
}

// Close releases resources
func (r *Runner) Close() {
	if r.luaPool != nil {
		r.luaPool.Close()
	}
	if r.jsPool != nil {
		r.jsPool.Close()
	}
}

// Run executes a hook with the given configuration and context
func (r *Runner) Run(ctx context.Context, hookType HookType, config *HookConfig, hookCtx *HookContext) *HookResult {
	if config == nil {
		return &HookResult{Success: true, Output: "No hook configured"}
	}

	// Prefer bash script if configured
	if config.BashScript != "" {
		return r.runBashScript(ctx, hookType, config, hookCtx)
	}

	// Run Lua/JavaScript script if configured
	if config.ScriptFile != "" {
		return r.runScriptEngine(ctx, hookType, config, hookCtx)
	}

	return &HookResult{Success: true, Output: "No hook configured"}
}

// runBashScript executes a bash script file
func (r *Runner) runBashScript(ctx context.Context, hookType HookType, config *HookConfig, hookCtx *HookContext) *HookResult {
	start := time.Now()
	result := &HookResult{}

	// Verify script exists
	scriptPath := config.BashScript
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		result.Success = false
		result.ErrorMsg = fmt.Sprintf("bash script not found: %s", scriptPath)
		return result
	}

	// Set timeout
	timeout := config.Timeout
	if timeout == 0 {
		timeout = r.defaultTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Execute bash script
	cmd := exec.CommandContext(execCtx, "bash", scriptPath)

	// Set working directory
	if config.WorkDir != "" {
		cmd.Dir = config.WorkDir
	} else {
		cmd.Dir = filepath.Dir(scriptPath)
	}

	// Build environment
	env := os.Environ()
	env = append(env, r.buildEnvVars(hookType, hookCtx)...)
	for k, v := range config.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute
	err := cmd.Run()
	result.Duration = time.Since(start)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.Success = false
		result.ErrorMsg = err.Error()
		result.Output = combineOutput(stdout.String(), stderr.String())
	} else {
		result.Success = true
		result.ExitCode = 0
		result.Output = combineOutput(stdout.String(), stderr.String())
	}

	return result
}

// runScriptEngine executes a Lua or JavaScript script using go-scripts engine
func (r *Runner) runScriptEngine(ctx context.Context, hookType HookType, config *HookConfig, hookCtx *HookContext) *HookResult {
	start := time.Now()
	result := &HookResult{}

	// Determine script type
	scriptType := config.ScriptType
	if scriptType == "" {
		// Auto-detect from file extension
		ext := strings.ToLower(filepath.Ext(config.ScriptFile))
		switch ext {
		case ".lua":
			scriptType = ScriptTypeLua
		case ".js":
			scriptType = ScriptTypeJavaScript
		default:
			result.Success = false
			result.ErrorMsg = fmt.Sprintf("unknown script type for extension: %s", ext)
			return result
		}
	}

	// Get or create engine pool
	pool, err := r.getEnginePool(scriptType)
	if err != nil {
		result.Success = false
		result.ErrorMsg = fmt.Sprintf("failed to initialize script engine: %v", err)
		return result
	}

	// Set timeout
	timeout := config.Timeout
	if timeout == 0 {
		timeout = r.defaultTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Register hook context as globals
	r.registerHookContext(pool, hookType, hookCtx)

	// Execute script file
	_, err = pool.ExecuteFile(execCtx, config.ScriptFile)
	result.Duration = time.Since(start)

	if err != nil {
		result.Success = false
		result.ErrorMsg = err.Error()
	} else {
		result.Success = true
	}

	return result
}

// getEnginePool returns or creates an engine pool for the given script type
func (r *Runner) getEnginePool(scriptType ScriptType) (*scripts.AutoGrowEnginePool, error) {
	switch scriptType {
	case ScriptTypeLua:
		if r.luaPool == nil {
			pool, err := scripts.NewAutoGrowEnginePool(1, 5, scripts.LuaType)
			if err != nil {
				return nil, err
			}
			r.luaPool = pool
		}
		return r.luaPool, nil
	case ScriptTypeJavaScript:
		if r.jsPool == nil {
			pool, err := scripts.NewAutoGrowEnginePool(1, 5, scripts.JavaScriptType)
			if err != nil {
				return nil, err
			}
			r.jsPool = pool
		}
		return r.jsPool, nil
	default:
		return nil, fmt.Errorf("unsupported script type: %s", scriptType)
	}
}

// registerHookContext registers hook context variables in the script engine pool
func (r *Runner) registerHookContext(pool *scripts.AutoGrowEnginePool, hookType HookType, hookCtx *HookContext) {
	// Register individual variables as globals
	_ = pool.RegisterGlobal("LCM_HOOK_TYPE", string(hookType))

	if hookCtx != nil {
		_ = pool.RegisterGlobal("LCM_CERT_NAME", hookCtx.CertName)
		_ = pool.RegisterGlobal("LCM_CERT_PATH", hookCtx.CertPath)
		_ = pool.RegisterGlobal("LCM_KEY_PATH", hookCtx.KeyPath)
		_ = pool.RegisterGlobal("LCM_CHAIN_PATH", hookCtx.ChainPath)
		_ = pool.RegisterGlobal("LCM_FULLCHAIN_PATH", hookCtx.FullChainPath)
		_ = pool.RegisterGlobal("LCM_COMMON_NAME", hookCtx.CommonName)
		_ = pool.RegisterGlobal("LCM_DNS_NAMES", strings.Join(hookCtx.DNSNames, ","))
		_ = pool.RegisterGlobal("LCM_IP_ADDRESSES", strings.Join(hookCtx.IPAddresses, ","))
		_ = pool.RegisterGlobal("LCM_SERIAL_NUMBER", hookCtx.SerialNumber)
		_ = pool.RegisterGlobal("LCM_EXPIRES_AT", hookCtx.ExpiresAt)
		_ = pool.RegisterGlobal("LCM_IS_RENEWAL", hookCtx.IsRenewal)

		// Register context as a table/object
		_ = pool.RegisterGlobal("LCM_CONTEXT", map[string]interface{}{
			"hookType":      string(hookType),
			"certName":      hookCtx.CertName,
			"certPath":      hookCtx.CertPath,
			"keyPath":       hookCtx.KeyPath,
			"chainPath":     hookCtx.ChainPath,
			"fullChainPath": hookCtx.FullChainPath,
			"commonName":    hookCtx.CommonName,
			"dnsNames":      hookCtx.DNSNames,
			"ipAddresses":   hookCtx.IPAddresses,
			"serialNumber":  hookCtx.SerialNumber,
			"expiresAt":     hookCtx.ExpiresAt,
			"isRenewal":     hookCtx.IsRenewal,
		})
	}

	// Register utility functions
	_ = pool.RegisterFunction("exec", func(command string) (string, error) {
		cmd := exec.Command("sh", "-c", command)
		output, err := cmd.CombinedOutput()
		return string(output), err
	})

	_ = pool.RegisterFunction("readFile", func(path string) (string, error) {
		data, err := os.ReadFile(path)
		return string(data), err
	})

	_ = pool.RegisterFunction("writeFile", func(path, content string) error {
		return os.WriteFile(path, []byte(content), 0644)
	})

	_ = pool.RegisterFunction("fileExists", func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	})

	_ = pool.RegisterFunction("getEnv", func(key string) string {
		return os.Getenv(key)
	})

	_ = pool.RegisterFunction("log", func(msg string) {
		fmt.Println(msg)
	})
}

// buildEnvVars builds environment variables for bash scripts
func (r *Runner) buildEnvVars(hookType HookType, hookCtx *HookContext) []string {
	env := []string{
		fmt.Sprintf("LCM_HOOK_TYPE=%s", hookType),
	}

	if hookCtx != nil {
		env = append(env,
			fmt.Sprintf("LCM_CERT_NAME=%s", hookCtx.CertName),
			fmt.Sprintf("LCM_CERT_PATH=%s", hookCtx.CertPath),
			fmt.Sprintf("LCM_KEY_PATH=%s", hookCtx.KeyPath),
			fmt.Sprintf("LCM_CHAIN_PATH=%s", hookCtx.ChainPath),
			fmt.Sprintf("LCM_FULLCHAIN_PATH=%s", hookCtx.FullChainPath),
			fmt.Sprintf("LCM_COMMON_NAME=%s", hookCtx.CommonName),
			fmt.Sprintf("LCM_DNS_NAMES=%s", strings.Join(hookCtx.DNSNames, ",")),
			fmt.Sprintf("LCM_IP_ADDRESSES=%s", strings.Join(hookCtx.IPAddresses, ",")),
			fmt.Sprintf("LCM_SERIAL_NUMBER=%s", hookCtx.SerialNumber),
			fmt.Sprintf("LCM_EXPIRES_AT=%s", hookCtx.ExpiresAt),
		)
		if hookCtx.IsRenewal {
			env = append(env, "LCM_IS_RENEWAL=true")
		} else {
			env = append(env, "LCM_IS_RENEWAL=false")
		}
	}

	return env
}

// RunDeployHook is a convenience method for running deploy hooks
func (r *Runner) RunDeployHook(ctx context.Context, config *HookConfig, hookCtx *HookContext) *HookResult {
	return r.Run(ctx, HookDeploy, config, hookCtx)
}

// RunFromDirectory runs all executable scripts in a directory
func (r *Runner) RunFromDirectory(ctx context.Context, hookType HookType, dir string, hookCtx *HookContext) ([]*HookResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read hooks directory: %w", err)
	}

	var results []*HookResult
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		ext := strings.ToLower(filepath.Ext(entry.Name()))

		var config *HookConfig

		switch ext {
		case ".sh", ".bash":
			// Check if executable
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.Mode()&0111 == 0 {
				continue
			}
			config = &HookConfig{
				BashScript: path,
				Timeout:    r.defaultTimeout,
			}
		case ".lua":
			config = &HookConfig{
				ScriptFile: path,
				ScriptType: ScriptTypeLua,
				Timeout:    r.defaultTimeout,
			}
		case ".js":
			config = &HookConfig{
				ScriptFile: path,
				ScriptType: ScriptTypeJavaScript,
				Timeout:    r.defaultTimeout,
			}
		default:
			continue
		}

		result := r.Run(ctx, hookType, config, hookCtx)
		results = append(results, result)
	}

	return results, nil
}

// combineOutput combines stdout and stderr into a single string
func combineOutput(stdout, stderr string) string {
	stdout = strings.TrimSpace(stdout)
	stderr = strings.TrimSpace(stderr)

	if stdout == "" && stderr == "" {
		return ""
	}
	if stdout == "" {
		return stderr
	}
	if stderr == "" {
		return stdout
	}
	return fmt.Sprintf("stdout:\n%s\nstderr:\n%s", stdout, stderr)
}

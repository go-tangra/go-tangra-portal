package transcoder

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/go-tangra/go-tangra-portal/pkg/middleware/auth"
)

// ModuleConnection represents a gRPC connection to a module
type ModuleConnection struct {
	ModuleID     string
	Endpoint     string
	Conn         *grpc.ClientConn
	Descriptor   *ParsedDescriptor
	CreatedAt    time.Time
	LastUsed     time.Time
	mu           sync.RWMutex
}

// Transcoder manages gRPC connections to modules and handles HTTP-to-gRPC transcoding
type Transcoder struct {
	log                 *log.Helper
	descParser          *DescriptorParser
	requestBuilder      *RequestBuilder
	responseTransformer *ResponseTransformer

	// Module connections (module_id -> connection)
	connections sync.Map

	// Default connection options
	connectTimeout time.Duration
	requestTimeout time.Duration

	// API audit logging
	writeApiLogFunc WriteApiLogFunc
	ecPrivateKey    *ecdsa.PrivateKey
}

// NewTranscoder creates a new Transcoder
func NewTranscoder(
	ctx *bootstrap.Context,
	descParser *DescriptorParser,
	requestBuilder *RequestBuilder,
	responseTransformer *ResponseTransformer,
) *Transcoder {
	ecKey, err := generateECDSAKeyPair()
	if err != nil {
		panic(fmt.Sprintf("failed to generate ECDSA key pair for audit signing: %v", err))
	}
	return &Transcoder{
		log:                 ctx.NewLoggerHelper("transcoder/admin-service"),
		descParser:          descParser,
		requestBuilder:      requestBuilder,
		responseTransformer: responseTransformer,
		connectTimeout:      10 * time.Second,
		requestTimeout:      30 * time.Second,
		ecPrivateKey:        ecKey,
	}
}

// RegisterModule registers a module and establishes a gRPC connection
func (t *Transcoder) RegisterModule(moduleID, endpoint string, protoDescriptor []byte) error {
	// Parse the proto descriptor
	parsedDesc, err := t.descParser.Parse(protoDescriptor)
	if err != nil {
		return fmt.Errorf("failed to parse proto descriptor: %w", err)
	}

	// Create gRPC connection with module-specific TLS credentials
	conn, err := t.createConnection(moduleID, endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to module %s at %s: %w", moduleID, endpoint, err)
	}

	moduleConn := &ModuleConnection{
		ModuleID:   moduleID,
		Endpoint:   endpoint,
		Conn:       conn,
		Descriptor: parsedDesc,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
	}

	// Store connection
	t.connections.Store(moduleID, moduleConn)
	t.log.Infof("Registered module %s at %s with %d services",
		moduleID, endpoint, len(parsedDesc.Services))

	return nil
}

// UnregisterModule removes a module and closes its connection
func (t *Transcoder) UnregisterModule(moduleID string) error {
	val, ok := t.connections.LoadAndDelete(moduleID)
	if !ok {
		return fmt.Errorf("module not found: %s", moduleID)
	}

	moduleConn := val.(*ModuleConnection)
	if moduleConn.Conn != nil {
		if err := moduleConn.Conn.Close(); err != nil {
			t.log.Warnf("Error closing connection for module %s: %v", moduleID, err)
		}
	}

	t.log.Infof("Unregistered module: %s", moduleID)
	return nil
}

// GetModuleConnection returns the connection for a module
func (t *Transcoder) GetModuleConnection(moduleID string) (*ModuleConnection, bool) {
	val, ok := t.connections.Load(moduleID)
	if !ok {
		return nil, false
	}
	return val.(*ModuleConnection), true
}

// Handle processes an HTTP request and transcodes it to gRPC
func (t *Transcoder) Handle(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	moduleID string,
	modulePath string, // Path relative to module prefix, e.g., /v1/messages
) {
	startTime := time.Now()

	// Buffer request body for audit logging
	var bodyBytes []byte
	if t.writeApiLogFunc != nil && r.Body != nil {
		bodyBytes = bufferRequestBody(r)
	}

	var (
		method     *MethodInfo
		pathParams map[string]string
		statusCode = http.StatusOK
		reason     string
	)

	defer func() {
		latencyMs := time.Since(startTime).Milliseconds()
		t.writeAuditLog(ctx, r, moduleID, method, modulePath, statusCode, reason, latencyMs, bodyBytes)
	}()

	// Get module connection
	moduleConn, ok := t.GetModuleConnection(moduleID)
	if !ok {
		statusCode = http.StatusNotFound
		reason = "MODULE_NOT_FOUND"
		t.writeError(w, http.StatusNotFound, "module not found: %s", moduleID)
		return
	}

	// Update last used time
	moduleConn.mu.Lock()
	moduleConn.LastUsed = time.Now()
	moduleConn.mu.Unlock()

	// Find matching method
	method, pathParams, ok = moduleConn.Descriptor.FindMethodByHTTP(r.Method, modulePath)
	if !ok {
		statusCode = http.StatusNotFound
		reason = "METHOD_NOT_FOUND"
		t.writeError(w, http.StatusNotFound, "no matching method for %s %s", r.Method, modulePath)
		return
	}

	// Check for streaming (not supported via HTTP)
	if method.IsClientStreaming || method.IsServerStreaming {
		statusCode = http.StatusNotImplemented
		reason = "STREAMING_NOT_SUPPORTED"
		t.writeError(w, http.StatusNotImplemented, "streaming methods not supported via HTTP")
		return
	}

	// Find the matching HTTP rule
	var matchingRule HTTPRule
	for _, rule := range method.HTTPRules {
		if strings.EqualFold(rule.Method, r.Method) {
			if _, matched := matchPath(rule.Pattern, modulePath); matched {
				matchingRule = rule
				break
			}
		}
	}

	// Build request message
	requestMsg, err := t.requestBuilder.BuildRequest(r, method, matchingRule, pathParams)
	if err != nil {
		statusCode = http.StatusBadRequest
		reason = "BAD_REQUEST"
		t.writeError(w, http.StatusBadRequest, "failed to build request: %v", err)
		return
	}

	// Inject tenant_id from auth context into the proto request if not already set
	t.injectTenantID(requestMsg, r)

	// Prepare gRPC context with auth metadata
	grpcCtx, cancel := context.WithTimeout(ctx, t.requestTimeout)
	defer cancel()

	// Inject auth context from HTTP request
	grpcCtx = t.injectAuthContext(grpcCtx, r)

	// Make gRPC call
	responseMsg, err := t.invokeMethod(grpcCtx, moduleConn, method, requestMsg)
	if err != nil {
		httpCode, errJSON := t.responseTransformer.TransformError(err)
		statusCode = httpCode
		reason = grpcErrorReason(err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpCode)
		if _, err := w.Write(errJSON); err != nil {
			t.log.Warnf("Failed to write HTTP error response: %v", err)
		}
		return
	}

	// Transform response
	jsonBytes, err := t.responseTransformer.TransformResponse(responseMsg, matchingRule.ResponseBody)
	if err != nil {
		statusCode = http.StatusInternalServerError
		reason = "RESPONSE_TRANSFORM_ERROR"
		t.writeError(w, http.StatusInternalServerError, "failed to transform response: %v", err)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(jsonBytes); err != nil {
		t.log.Warnf("Failed to write HTTP response: %v", err)
	}
}

// invokeMethod makes the actual gRPC call using dynamic invocation
func (t *Transcoder) invokeMethod(
	ctx context.Context,
	moduleConn *ModuleConnection,
	method *MethodInfo,
	request *dynamicpb.Message,
) (proto.Message, error) {
	// Create response message
	response := dynamicpb.NewMessage(method.OutputType)

	// Build full method name: /{package}.{service}/{method}
	// Extract service full name from method.FullName (e.g. "lcm.service.v1.LcmIssuerService.ListIssuers")
	// by stripping the last segment (the method name)
	serviceFullName := method.FullName
	if lastDot := strings.LastIndex(method.FullName, "."); lastDot > 0 {
		serviceFullName = method.FullName[:lastDot]
	}
	fullMethod := fmt.Sprintf("/%s/%s", serviceFullName, method.MethodName)

	// Make unary call
	err := moduleConn.Conn.Invoke(ctx, fullMethod, request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// injectAuthContext extracts auth info from the HTTP request and adds it to gRPC metadata
func (t *Transcoder) injectAuthContext(ctx context.Context, r *http.Request) context.Context {
	md := metadata.New(nil)

	// Try to get auth context from the request context
	tokenPayload, err := auth.FromContext(r.Context())
	if err == nil && tokenPayload != nil {
		md.Set("x-md-global-tenant-id", strconv.FormatUint(uint64(tokenPayload.GetTenantId()), 10))
		md.Set("x-md-global-user-id", strconv.FormatUint(uint64(tokenPayload.GetUserId()), 10))
		if tokenPayload.Username != nil {
			md.Set("x-md-global-username", *tokenPayload.Username)
		}
		if roles := tokenPayload.GetRoles(); len(roles) > 0 {
			md.Set("x-md-global-roles", strings.Join(roles, ","))
		}
	} else {
		t.log.Warnf("No auth context available for module request: %v", err)
	}

	// Pass through request ID if present
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		md.Set("x-request-id", reqID)
	}

	// Pass through trace ID if present
	if traceID := r.Header.Get("X-Trace-ID"); traceID != "" {
		md.Set("x-trace-id", traceID)
	}

	// Forward authorization header
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		md.Set("authorization", authHeader)
	}

	return metadata.NewOutgoingContext(ctx, md)
}

// injectTenantID injects the tenant_id from the authenticated user's JWT token
// into the proto request message if the message has a tenant_id field and it
// was not explicitly provided in the HTTP request.
func (t *Transcoder) injectTenantID(msg *dynamicpb.Message, r *http.Request) {
	tokenPayload, err := auth.FromContext(r.Context())
	if err != nil || tokenPayload == nil {
		return
	}

	tenantID := tokenPayload.GetTenantId()

	// Look for tenant_id field in the proto message
	fd := msg.Descriptor().Fields().ByName("tenant_id")
	if fd == nil {
		return
	}

	// Only set if not already provided in the request
	if !msg.Has(fd) {
		msg.Set(fd, protoreflect.ValueOfUint32(tenantID))
	}
}

// createConnection creates a gRPC client connection with retry, keepalive, and optional mTLS
func (t *Transcoder) createConnection(moduleID, endpoint string) (*grpc.ClientConn, error) {
	// Configure connection parameters for automatic reconnection
	connectParams := grpc.ConnectParams{
		Backoff: backoff.Config{
			BaseDelay:  1 * time.Second,
			Multiplier: 1.5,
			Jitter:     0.2,
			MaxDelay:   30 * time.Second,
		},
		MinConnectTimeout: t.connectTimeout,
	}

	// Configure keepalive to detect dead connections
	keepaliveParams := keepalive.ClientParameters{
		Time:                5 * time.Minute,
		Timeout:             20 * time.Second,
		PermitWithoutStream: false,
	}

	// Try to load mTLS credentials for this module
	var transportCreds grpc.DialOption
	tlsCreds, err := t.loadModuleTLSCredentials(moduleID)
	if err != nil {
		t.log.Warnf("Failed to load TLS credentials for module %s, using insecure connection: %v", moduleID, err)
		transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else if tlsCreds != nil {
		t.log.Infof("Using mTLS credentials for module %s", moduleID)
		transportCreds = grpc.WithTransportCredentials(tlsCreds)
	} else {
		t.log.Infof("No TLS credentials configured for module %s, using insecure connection", moduleID)
		transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	// Create gRPC connection
	conn, err := grpc.NewClient(
		endpoint,
		transportCreds,
		grpc.WithConnectParams(connectParams),
		grpc.WithKeepaliveParams(keepaliveParams),
		grpc.WithDefaultServiceConfig(`{
			"loadBalancingConfig": [{"round_robin":{}}],
			"methodConfig": [{
				"name": [{"service": ""}],
				"waitForReady": true,
				"retryPolicy": {
					"MaxAttempts": 3,
					"InitialBackoff": "0.5s",
					"MaxBackoff": "5s",
					"BackoffMultiplier": 2,
					"RetryableStatusCodes": ["UNAVAILABLE", "RESOURCE_EXHAUSTED"]
				}
			}]
		}`),
	)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// loadModuleTLSCredentials loads TLS credentials for connecting to a specific module
// Environment variable naming convention: {MODULE}_CA_CERT_PATH, {MODULE}_CLIENT_CERT_PATH, etc.
func (t *Transcoder) loadModuleTLSCredentials(moduleID string) (credentials.TransportCredentials, error) {
	// Convert module ID to uppercase for environment variable lookup
	prefix := strings.ToUpper(moduleID)

	// Get certificate paths from environment
	caCertPath := os.Getenv(prefix + "_CA_CERT_PATH")
	clientCertPath := os.Getenv(prefix + "_CLIENT_CERT_PATH")
	clientKeyPath := os.Getenv(prefix + "_CLIENT_KEY_PATH")
	serverName := os.Getenv(prefix + "_SERVER_NAME")

	// If no CA cert path is configured, TLS is not enabled for this module
	if caCertPath == "" {
		return nil, nil
	}

	// All paths must be configured for mTLS
	if clientCertPath == "" || clientKeyPath == "" {
		return nil, fmt.Errorf("incomplete TLS configuration for module %s: CA path set but client cert/key missing", moduleID)
	}

	// Load CA certificate
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert from %s: %w", caCertPath, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertPath)
	}

	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert/key from %s, %s: %w", clientCertPath, clientKeyPath, err)
	}

	// Use server name from env or default to the module service name
	if serverName == "" {
		serverName = moduleID + "-service"
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}

	t.log.Infof("Loaded TLS credentials for module %s: CA=%s, Cert=%s, ServerName=%s",
		moduleID, caCertPath, clientCertPath, serverName)

	return credentials.NewTLS(tlsConfig), nil
}

// writeError writes an error response
func (t *Transcoder) writeError(w http.ResponseWriter, code int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	t.log.Warnf("Transcoder error: %s", msg)

	httpErr := HTTPError{
		Code:    code,
		Message: msg,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	jsonBytes, err := json.Marshal(httpErr)
	if err != nil {
		t.log.Warnf("Failed to marshal HTTP error: %v", err)
		return
	}
	if _, err := w.Write(jsonBytes); err != nil {
		t.log.Warnf("Failed to write HTTP error response: %v", err)
	}
}

// ListModules returns a list of all registered modules
func (t *Transcoder) ListModules() []string {
	var modules []string
	t.connections.Range(func(key, value interface{}) bool {
		modules = append(modules, key.(string))
		return true
	})
	return modules
}

// GetModuleServices returns the services provided by a module
func (t *Transcoder) GetModuleServices(moduleID string) ([]string, error) {
	moduleConn, ok := t.GetModuleConnection(moduleID)
	if !ok {
		return nil, fmt.Errorf("module not found: %s", moduleID)
	}
	return moduleConn.Descriptor.ListServices(), nil
}

// GetModuleMethods returns all methods for a module
func (t *Transcoder) GetModuleMethods(moduleID string) ([]*MethodInfo, error) {
	moduleConn, ok := t.GetModuleConnection(moduleID)
	if !ok {
		return nil, fmt.Errorf("module not found: %s", moduleID)
	}
	return moduleConn.Descriptor.ListMethods(), nil
}

// Healthcheck checks if a module's gRPC connection is healthy
func (t *Transcoder) Healthcheck(ctx context.Context, moduleID string) error {
	moduleConn, ok := t.GetModuleConnection(moduleID)
	if !ok {
		return fmt.Errorf("module not found: %s", moduleID)
	}

	state := moduleConn.Conn.GetState()
	if state.String() == "TRANSIENT_FAILURE" || state.String() == "SHUTDOWN" {
		return fmt.Errorf("connection in unhealthy state: %s", state)
	}

	return nil
}

// Close closes all module connections
func (t *Transcoder) Close() error {
	var errs []error
	t.connections.Range(func(key, value interface{}) bool {
		moduleConn := value.(*ModuleConnection)
		if moduleConn.Conn != nil {
			if err := moduleConn.Conn.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close connection for %s: %w", key.(string), err))
			}
		}
		return true
	})

	if len(errs) > 0 {
		return fmt.Errorf("errors closing connections: %v", errs)
	}
	return nil
}

// RouteInfo contains information about a registered route
type RouteInfo struct {
	ModuleID    string
	ServiceName string
	MethodName  string
	HTTPMethod  string
	Pattern     string
	FullMethod  string
}

// ListRoutes returns all registered routes across all modules
func (t *Transcoder) ListRoutes() []RouteInfo {
	var routes []RouteInfo
	t.connections.Range(func(key, value interface{}) bool {
		moduleID := key.(string)
		moduleConn := value.(*ModuleConnection)

		for _, method := range moduleConn.Descriptor.ListMethods() {
			for _, rule := range method.HTTPRules {
				routes = append(routes, RouteInfo{
					ModuleID:    moduleID,
					ServiceName: method.ServiceName,
					MethodName:  method.MethodName,
					HTTPMethod:  rule.Method,
					Pattern:     rule.Pattern,
					FullMethod:  method.FullName,
				})
			}
		}
		return true
	})
	return routes
}

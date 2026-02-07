package service

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"gopkg.in/yaml.v3"
)

// OpenAPIParser parses OpenAPI specs and extracts menus and API resources.
type OpenAPIParser struct {
	log *log.Helper
}

// ParsedMenu represents a menu item extracted from OpenAPI x-menus extension.
type ParsedMenu struct {
	ID          string   `json:"id" yaml:"id"`
	ParentID    string   `json:"parent_id" yaml:"parent_id"`
	Type        string   `json:"type" yaml:"type"`                 // CATALOG, MENU, BUTTON
	Name        string   `json:"name" yaml:"name"`                 // i18n key or display name
	Path        string   `json:"path" yaml:"path"`                 // Route path
	Component   string   `json:"component" yaml:"component"`       // Vue component path
	Icon        string   `json:"icon" yaml:"icon"`                 // Icon identifier
	Order       int32    `json:"order" yaml:"order"`               // Sort order
	Authority   []string `json:"authority" yaml:"authority"`       // Required roles
	Hidden      bool     `json:"hidden" yaml:"hidden"`             // Whether menu is hidden
	AlwaysShow  bool     `json:"always_show" yaml:"always_show"`   // Always show in menu
	Redirect    string   `json:"redirect" yaml:"redirect"`         // Redirect path
	KeepAlive   bool     `json:"keep_alive" yaml:"keep_alive"`     // Keep component alive
	External    bool     `json:"external" yaml:"external"`         // External link
	Description string   `json:"description" yaml:"description"`   // Menu description
}

// ParsedAPI represents an API resource extracted from OpenAPI paths.
type ParsedAPI struct {
	Path          string   // HTTP path
	Method        string   // HTTP method (GET, POST, etc.)
	OperationID   string   // Operation ID from spec
	Summary       string   // API summary
	Description   string   // API description
	Tags          []string // OpenAPI tags
	MenuRef       string   // Reference to menu (x-menu-ref)
	Permissions   []string // Required permissions
	Authenticated bool     // Whether authentication is required
}

// ParsedSpec represents the parsed result of an OpenAPI spec.
type ParsedSpec struct {
	ModuleID    string        // From info.x-module-id
	ModuleName  string        // From info.x-module-name
	ModuleIcon  string        // From info.x-module-icon
	Version     string        // From info.version
	Description string        // From info.description
	Menus       []*ParsedMenu // From x-menus extension
	APIs        []*ParsedAPI  // From paths
	RouteCount  int32         // Number of routes
}

// NewOpenAPIParser creates a new OpenAPIParser.
func NewOpenAPIParser(ctx *bootstrap.Context) *OpenAPIParser {
	return &OpenAPIParser{
		log: ctx.NewLoggerHelper("openapi-parser/admin-service"),
	}
}

// Parse parses an OpenAPI spec and extracts menus and API resources.
func (p *OpenAPIParser) Parse(specData []byte) (*ParsedSpec, error) {
	if len(specData) == 0 {
		return nil, fmt.Errorf("empty OpenAPI spec")
	}

	// Load the OpenAPI document
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(specData)
	if err != nil {
		p.log.Errorf("Failed to parse OpenAPI spec: %v", err)
		return nil, fmt.Errorf("failed to parse OpenAPI spec: %w", err)
	}

	// Create the parsed spec
	result := &ParsedSpec{
		Menus: make([]*ParsedMenu, 0),
		APIs:  make([]*ParsedAPI, 0),
	}

	// Extract module info from info section
	if doc.Info != nil {
		result.Version = doc.Info.Version
		result.Description = doc.Info.Description

		// Extract custom extensions from info
		if doc.Info.Extensions != nil {
			if moduleID, ok := p.getExtensionString(doc.Info.Extensions, "x-module-id"); ok {
				result.ModuleID = moduleID
			}
			if moduleName, ok := p.getExtensionString(doc.Info.Extensions, "x-module-name"); ok {
				result.ModuleName = moduleName
			}
			if moduleIcon, ok := p.getExtensionString(doc.Info.Extensions, "x-module-icon"); ok {
				result.ModuleIcon = moduleIcon
			}
		}
	}

	// Extract menus from top-level x-menus extension
	menus, err := p.extractMenus(doc.Extensions)
	if err != nil {
		p.log.Warnf("Failed to extract menus: %v", err)
	} else {
		result.Menus = menus
	}

	// Extract APIs from paths
	apis, routeCount := p.extractAPIs(doc)
	result.APIs = apis
	result.RouteCount = routeCount

	p.log.Infof("Parsed OpenAPI spec: module=%s, menus=%d, apis=%d, routes=%d",
		result.ModuleID, len(result.Menus), len(result.APIs), result.RouteCount)

	return result, nil
}

// extractMenus extracts menu definitions from the x-menus extension.
func (p *OpenAPIParser) extractMenus(extensions map[string]interface{}) ([]*ParsedMenu, error) {
	menus := make([]*ParsedMenu, 0)

	menusExt, ok := extensions["x-menus"]
	if !ok {
		return menus, nil
	}

	// The extension could be a json.RawMessage or already parsed
	var menuList []interface{}

	switch v := menusExt.(type) {
	case json.RawMessage:
		if err := json.Unmarshal(v, &menuList); err != nil {
			return nil, fmt.Errorf("failed to unmarshal x-menus: %w", err)
		}
	case []interface{}:
		menuList = v
	default:
		return nil, fmt.Errorf("unexpected type for x-menus: %T", menusExt)
	}

	for _, item := range menuList {
		menu, err := p.parseMenuItem(item)
		if err != nil {
			p.log.Warnf("Failed to parse menu item: %v", err)
			continue
		}
		menus = append(menus, menu)
	}

	return menus, nil
}

// parseMenuItem parses a single menu item from the extension data.
func (p *OpenAPIParser) parseMenuItem(item interface{}) (*ParsedMenu, error) {
	menu := &ParsedMenu{}

	// Convert to JSON and back to struct for consistent handling
	jsonBytes, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal menu item: %w", err)
	}

	if err := json.Unmarshal(jsonBytes, menu); err != nil {
		return nil, fmt.Errorf("failed to unmarshal menu item: %w", err)
	}

	// Validate required fields
	if menu.ID == "" {
		return nil, fmt.Errorf("menu item missing required field: id")
	}

	return menu, nil
}

// extractAPIs extracts API resources from OpenAPI paths.
func (p *OpenAPIParser) extractAPIs(doc *openapi3.T) ([]*ParsedAPI, int32) {
	apis := make([]*ParsedAPI, 0)
	routeCount := int32(0)

	if doc.Paths == nil {
		return apis, routeCount
	}

	// Iterate through all paths
	for path, pathItem := range doc.Paths.Map() {
		if pathItem == nil {
			continue
		}

		// Process each HTTP method
		operations := map[string]*openapi3.Operation{
			"GET":     pathItem.Get,
			"POST":    pathItem.Post,
			"PUT":     pathItem.Put,
			"DELETE":  pathItem.Delete,
			"PATCH":   pathItem.Patch,
			"HEAD":    pathItem.Head,
			"OPTIONS": pathItem.Options,
		}

		for method, op := range operations {
			if op == nil {
				continue
			}

			routeCount++

			api := &ParsedAPI{
				Path:        path,
				Method:      method,
				OperationID: op.OperationID,
				Summary:     op.Summary,
				Description: op.Description,
				Tags:        op.Tags,
			}

			// Extract custom extensions
			if op.Extensions != nil {
				if menuRef, ok := p.getExtensionString(op.Extensions, "x-menu-ref"); ok {
					api.MenuRef = menuRef
				}
				if perms, ok := p.getExtensionStringSlice(op.Extensions, "x-permissions"); ok {
					api.Permissions = perms
				}
				if auth, ok := p.getExtensionBool(op.Extensions, "x-authenticated"); ok {
					api.Authenticated = auth
				} else {
					// Default to authenticated
					api.Authenticated = true
				}
			}

			apis = append(apis, api)
		}
	}

	return apis, routeCount
}

// getExtensionString extracts a string value from extensions.
func (p *OpenAPIParser) getExtensionString(extensions map[string]interface{}, key string) (string, bool) {
	if val, ok := extensions[key]; ok {
		switch v := val.(type) {
		case string:
			return v, true
		case json.RawMessage:
			var s string
			if err := json.Unmarshal(v, &s); err == nil {
				return s, true
			}
		}
	}
	return "", false
}

// getExtensionStringSlice extracts a string slice from extensions.
func (p *OpenAPIParser) getExtensionStringSlice(extensions map[string]interface{}, key string) ([]string, bool) {
	if val, ok := extensions[key]; ok {
		switch v := val.(type) {
		case []string:
			return v, true
		case []interface{}:
			result := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			return result, len(result) > 0
		case json.RawMessage:
			var arr []string
			if err := json.Unmarshal(v, &arr); err == nil {
				return arr, true
			}
		}
	}
	return nil, false
}

// getExtensionBool extracts a boolean value from extensions.
func (p *OpenAPIParser) getExtensionBool(extensions map[string]interface{}, key string) (bool, bool) {
	if val, ok := extensions[key]; ok {
		switch v := val.(type) {
		case bool:
			return v, true
		case json.RawMessage:
			var b bool
			if err := json.Unmarshal(v, &b); err == nil {
				return b, true
			}
		}
	}
	return false, false
}

// ParseMenuType converts a menu type string to the database integer value.
func ParseMenuType(typeStr string) int32 {
	switch strings.ToUpper(typeStr) {
	case "CATALOG":
		return 1
	case "MENU":
		return 2
	case "BUTTON":
		return 3
	default:
		return 2 // Default to MENU
	}
}

// ParseFromYAML is a convenience function to parse YAML OpenAPI specs.
func (p *OpenAPIParser) ParseFromYAML(yamlData []byte) (*ParsedSpec, error) {
	// kin-openapi handles YAML automatically, but we can pre-process if needed
	return p.Parse(yamlData)
}

// ValidateSpec validates that a parsed spec has the minimum required information.
func (p *OpenAPIParser) ValidateSpec(spec *ParsedSpec) error {
	if spec.ModuleID == "" {
		return fmt.Errorf("OpenAPI spec missing x-module-id in info section")
	}
	if spec.ModuleName == "" {
		return fmt.Errorf("OpenAPI spec missing x-module-name in info section")
	}
	return nil
}

// Helper to convert YAML to JSON for consistent processing
func yamlToJSON(yamlData []byte) ([]byte, error) {
	var data interface{}
	if err := yaml.Unmarshal(yamlData, &data); err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

package service

import (
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"gopkg.in/yaml.v3"
)

// MenuParser parses menus.yaml files from modules.
type MenuParser struct {
	log *log.Helper
}

// MenusFile represents the structure of a menus.yaml file.
// This now includes roles, permission_groups, and dashboard_widgets for unified module definition.
type MenusFile struct {
	Module           ModuleInfo               `yaml:"module"`
	Menus            []*ParsedMenu            `yaml:"menus"`
	Roles            []*ParsedRole            `yaml:"roles"`
	PermissionGroups []*ParsedPermissionGroup `yaml:"permission_groups"`
	DashboardWidgets []*ParsedWidget          `yaml:"dashboard_widgets"`
}

// ParsedWidget represents a dashboard widget defined in a module's YAML file.
type ParsedWidget struct {
	ID          string            `yaml:"id"`          // e.g. "lcm.cert_status_pie"
	Name        string            `yaml:"name"`        // Display name
	Description string            `yaml:"description"` // Widget description
	Icon        string            `yaml:"icon"`        // Icon identifier
	WidgetType  string            `yaml:"widget_type"` // stat_card|pie_chart|bar_chart|line_chart|gauge|table|list
	DataSource  WidgetDataSource  `yaml:"data_source"` // How to fetch data
	DataMapping map[string]string `yaml:"data_mapping"`
	DefaultSize WidgetSize        `yaml:"default_size"` // Default grid size
	Tags        []string          `yaml:"tags"`          // Categorization tags
	Authority   []string          `yaml:"authority"`     // Required roles
}

// WidgetDataSource defines how a widget fetches its data.
type WidgetDataSource struct {
	Endpoint string            `yaml:"endpoint"` // Gateway HTTP path, e.g. "/admin/v1/modules/lcm/v1/statistics"
	Method   string            `yaml:"method"`   // GET or POST
	Params   map[string]string `yaml:"params"`   // Default query parameters
}

// WidgetSize defines the default grid dimensions for a widget.
type WidgetSize struct {
	Width  int32 `yaml:"width"`  // 1-12 grid columns
	Height int32 `yaml:"height"` // Grid rows
}

// ModuleInfo contains module metadata from menus.yaml.
type ModuleInfo struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// ParsedRole represents a role defined in a module's YAML file.
type ParsedRole struct {
	Name        string   `yaml:"name"`
	Code        string   `yaml:"code"`
	Description string   `yaml:"description"`
	IsSystem    bool     `yaml:"is_system"`
	Permissions []string `yaml:"permissions"` // Permission codes
}

// ParsedPermissionGroup represents a permission group defined in a module's YAML file.
type ParsedPermissionGroup struct {
	Name        string              `yaml:"name"`
	Module      string              `yaml:"module"`
	Description string              `yaml:"description"`
	Permissions []*ParsedPermission `yaml:"permissions"`
}

// ParsedPermission represents a permission defined within a permission group.
type ParsedPermission struct {
	Name        string `yaml:"name"`
	Code        string `yaml:"code"`
	Description string `yaml:"description"`
}

// NewMenuParser creates a new MenuParser.
func NewMenuParser(ctx *bootstrap.Context) *MenuParser {
	return &MenuParser{
		log: ctx.NewLoggerHelper("menu-parser/admin-service"),
	}
}

// Parse parses a menus.yaml file and extracts menu definitions.
func (p *MenuParser) Parse(yamlData []byte) (*MenusFile, error) {
	if len(yamlData) == 0 {
		return nil, fmt.Errorf("empty menus.yaml data")
	}

	var menusFile MenusFile
	if err := yaml.Unmarshal(yamlData, &menusFile); err != nil {
		p.log.Errorf("Failed to parse menus.yaml: %v", err)
		return nil, fmt.Errorf("failed to parse menus.yaml: %w", err)
	}

	// Validate the parsed data
	if err := p.validate(&menusFile); err != nil {
		return nil, err
	}

	p.log.Infof("Parsed menus.yaml: module=%s, menus=%d, roles=%d, permission_groups=%d, dashboard_widgets=%d",
		menusFile.Module.ID, len(menusFile.Menus), len(menusFile.Roles), len(menusFile.PermissionGroups), len(menusFile.DashboardWidgets))

	return &menusFile, nil
}

// validate validates the parsed menus file.
func (p *MenuParser) validate(menusFile *MenusFile) error {
	if menusFile.Module.ID == "" {
		return fmt.Errorf("menus.yaml missing module.id")
	}

	// Validate each menu entry
	for i, menu := range menusFile.Menus {
		if menu.ID == "" {
			return fmt.Errorf("menu at index %d missing required field: id", i)
		}
		if menu.Type == "" {
			// Default to MENU if not specified
			menusFile.Menus[i].Type = "MENU"
		}
	}

	// Validate each role entry
	for i, role := range menusFile.Roles {
		if role.Code == "" {
			return fmt.Errorf("role at index %d missing required field: code", i)
		}
		if role.Name == "" {
			return fmt.Errorf("role at index %d missing required field: name", i)
		}
	}

	// Validate each dashboard widget entry
	validWidgetTypes := map[string]bool{
		"stat_card": true, "pie_chart": true, "bar_chart": true,
		"line_chart": true, "gauge": true, "table": true, "list": true,
	}
	for i, widget := range menusFile.DashboardWidgets {
		if widget.ID == "" {
			return fmt.Errorf("dashboard_widget at index %d missing required field: id", i)
		}
		if widget.WidgetType == "" {
			return fmt.Errorf("dashboard_widget '%s' missing required field: widget_type", widget.ID)
		}
		if !validWidgetTypes[widget.WidgetType] {
			return fmt.Errorf("dashboard_widget '%s' has invalid widget_type: %s", widget.ID, widget.WidgetType)
		}
		if widget.DataSource.Endpoint == "" {
			return fmt.Errorf("dashboard_widget '%s' missing required field: data_source.endpoint", widget.ID)
		}
		if widget.DefaultSize.Width < 1 || widget.DefaultSize.Width > 12 {
			return fmt.Errorf("dashboard_widget '%s' default_size.width must be between 1 and 12, got %d", widget.ID, widget.DefaultSize.Width)
		}
		if widget.DefaultSize.Height < 1 {
			return fmt.Errorf("dashboard_widget '%s' default_size.height must be at least 1, got %d", widget.ID, widget.DefaultSize.Height)
		}
		// Default method to GET
		if widget.DataSource.Method == "" {
			menusFile.DashboardWidgets[i].DataSource.Method = "GET"
		}
	}

	// Validate each permission group entry
	for i, group := range menusFile.PermissionGroups {
		if group.Name == "" {
			return fmt.Errorf("permission_group at index %d missing required field: name", i)
		}
		// Validate permissions within each group
		for j, perm := range group.Permissions {
			if perm.Code == "" {
				return fmt.Errorf("permission at index %d in group '%s' missing required field: code", j, group.Name)
			}
			if perm.Name == "" {
				return fmt.Errorf("permission at index %d in group '%s' missing required field: name", j, group.Name)
			}
		}
	}

	return nil
}

// ParseMenus is a convenience method that returns just the menus slice.
func (p *MenuParser) ParseMenus(yamlData []byte) ([]*ParsedMenu, error) {
	menusFile, err := p.Parse(yamlData)
	if err != nil {
		return nil, err
	}
	return menusFile.Menus, nil
}

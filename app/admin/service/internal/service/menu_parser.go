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
// This now includes roles and permission_groups for unified module definition.
type MenusFile struct {
	Module           ModuleInfo               `yaml:"module"`
	Menus            []*ParsedMenu            `yaml:"menus"`
	Roles            []*ParsedRole            `yaml:"roles"`
	PermissionGroups []*ParsedPermissionGroup `yaml:"permission_groups"`
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

	p.log.Infof("Parsed menus.yaml: module=%s, menus=%d, roles=%d, permission_groups=%d",
		menusFile.Module.ID, len(menusFile.Menus), len(menusFile.Roles), len(menusFile.PermissionGroups))

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

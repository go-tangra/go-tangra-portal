package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	paginationV1 "github.com/tx7do/go-crud/api/gen/go/pagination/v1"
	"github.com/tx7do/go-utils/trans"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
	permissionV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/permission/service/v1"
	userV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/user/service/v1"

	"github.com/go-tangra/go-tangra-portal/pkg/middleware/auth"
	"github.com/go-tangra/go-tangra-portal/pkg/utils/slice"
)

type AdminPortalService struct {
	adminV1.AdminPortalServiceHTTPServer

	log *log.Helper

	menuRepo       *data.MenuRepo
	roleRepo       *data.RoleRepo
	userRepo       data.UserRepo
	moduleRegistry *ModuleRegistry
}

func NewAdminPortalService(
	ctx *bootstrap.Context,
	menuRepo *data.MenuRepo,
	roleRepo *data.RoleRepo,
	userRepo data.UserRepo,
	moduleRegistry *ModuleRegistry,
) *AdminPortalService {
	return &AdminPortalService{
		log:            ctx.NewLoggerHelper("admin-portal/service/admin-service"),
		menuRepo:       menuRepo,
		roleRepo:       roleRepo,
		userRepo:       userRepo,
		moduleRegistry: moduleRegistry,
	}
}

func (s *AdminPortalService) menuListToQueryString(menus []uint32, onlyButton bool) string {
	var ids []string
	for _, menu := range menus {
		ids = append(ids, fmt.Sprintf("\"%d\"", menu))
	}
	idsStr := fmt.Sprintf("[%s]", strings.Join(ids, ", "))
	query := map[string]string{"id__in": idsStr}

	if onlyButton {
		query["type"] = permissionV1.Menu_BUTTON.String()
	} else {
		query["type__not"] = permissionV1.Menu_BUTTON.String()
	}

	query["status"] = "ON"

	queryStr, err := json.Marshal(query)
	if err != nil {
		return ""
	}

	return string(queryStr)
}

// queryMultipleRolesMenusByRoleCodes 使用RoleCodes查询菜单，即多个角色的菜单
func (s *AdminPortalService) queryMultipleRolesMenusByRoleCodes(ctx context.Context, roleCodes []string) ([]uint32, error) {
	roleIDs, err := s.roleRepo.ListRoleIDsByRoleCodes(ctx, roleCodes)
	if err != nil {
		return nil, adminV1.ErrorInternalServerError("query roles failed")
	}

	var menus []uint32

	menus, err = s.roleRepo.GetRolesPermissionMenuIDs(ctx, roleIDs)
	if err != nil {
		return nil, adminV1.ErrorInternalServerError("query roles menus failed")
	}

	menus = slice.Unique(menus)

	return menus, nil
}

// queryMultipleRolesMenusByRoleIds 使用RoleIDs查询菜单，即多个角色的菜单
func (s *AdminPortalService) queryMultipleRolesMenusByRoleIds(ctx context.Context, roleIDs []uint32) ([]uint32, error) {
	menus, err := s.roleRepo.GetRolesPermissionMenuIDs(ctx, roleIDs)
	if err != nil {
		return nil, adminV1.ErrorInternalServerError("query roles menus failed")
	}

	menus = slice.Unique(menus)

	return menus, nil
}

func (s *AdminPortalService) GetMyPermissionCode(ctx context.Context, _ *emptypb.Empty) (*adminV1.ListPermissionCodeResponse, error) {
	// 获取操作人信息
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.Get(ctx, &userV1.GetUserRequest{
		QueryBy: &userV1.GetUserRequest_Id{
			Id: operator.UserId,
		},
	})
	if err != nil {
		s.log.Errorf("query user failed[%s]", err.Error())
		return nil, adminV1.ErrorInternalServerError("query user failed")
	}

	// 多角色的菜单
	roleMenus, err := s.queryMultipleRolesMenusByRoleIds(ctx, user.GetRoleIds())
	if err != nil {
		return nil, err
	}

	menus, err := s.menuRepo.List(ctx, &paginationV1.PagingRequest{
		NoPaging: trans.Ptr(true),
		FilteringType: &paginationV1.PagingRequest_Query{
			Query: s.menuListToQueryString(roleMenus, true),
		},
		FieldMask: &fieldmaskpb.FieldMask{
			Paths: []string{"id", "meta"},
		},
	}, false)
	if err != nil {
		s.log.Errorf("list permission code failed [%s]", err.Error())
		return nil, adminV1.ErrorInternalServerError("list permission code failed")
	}

	var codes []string
	for menu := range menus.Items {
		if menus.Items[menu].GetMeta() == nil {
			continue
		}
		if len(menus.Items[menu].GetMeta().GetAuthority()) == 0 {
			continue
		}

		codes = append(codes, menus.Items[menu].GetMeta().GetAuthority()...)
	}

	return &adminV1.ListPermissionCodeResponse{
		Codes: codes,
	}, nil
}

func (s *AdminPortalService) fillRouteItem(menus []*permissionV1.Menu) []*permissionV1.MenuRouteItem {
	if len(menus) == 0 {
		return nil
	}

	var routers []*permissionV1.MenuRouteItem

	for _, v := range menus {
		if v.GetStatus() != permissionV1.Menu_ON {
			continue
		}
		if v.GetType() == permissionV1.Menu_BUTTON {
			continue
		}

		item := &permissionV1.MenuRouteItem{
			Path:      v.Path,
			Component: v.Component,
			Name:      v.Name,
			Redirect:  v.Redirect,
			Alias:     v.Alias,
			Meta:      v.Meta,
		}

		if len(v.Children) > 0 {
			item.Children = s.fillRouteItem(v.Children)
		}

		routers = append(routers, item)
	}

	return routers
}

func (s *AdminPortalService) GetNavigation(ctx context.Context, _ *emptypb.Empty) (*adminV1.ListRouteResponse, error) {
	// 获取操作人信息
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.Get(ctx, &userV1.GetUserRequest{
		QueryBy: &userV1.GetUserRequest_Id{
			Id: operator.UserId,
		},
	})
	if err != nil {
		s.log.Errorf("query user failed[%s]", err.Error())
		return nil, adminV1.ErrorInternalServerError("query user failed")
	}

	// 多角色的菜单 (使用角色ID而非角色代码，因为User.Roles字段未被填充)
	roleMenus, err := s.queryMultipleRolesMenusByRoleIds(ctx, user.GetRoleIds())
	if err != nil {
		return nil, err
	}

	menuList, err := s.menuRepo.List(ctx, &paginationV1.PagingRequest{
		NoPaging: trans.Ptr(true),
		FilteringType: &paginationV1.PagingRequest_Query{
			Query: s.menuListToQueryString(roleMenus, false),
		},
	}, true)
	if err != nil {
		s.log.Errorf("list route failed [%s]", err.Error())
		return nil, adminV1.ErrorInternalServerError("list route failed")
	}

	// Convert database menus to route items
	routes := s.fillRouteItem(menuList.Items)

	// Get user's permission codes for filtering dynamic menus
	userPermCodes := s.getUserPermissionCodes(user)

	// Append dynamic menus from registered modules
	dynamicMenus := s.moduleRegistry.GetAllDynamicMenus()
	dynamicRoutes := s.convertDynamicMenusToRoutes(dynamicMenus, userPermCodes)
	routes = append(routes, dynamicRoutes...)

	resp := &adminV1.ListRouteResponse{Items: routes}

	return resp, nil
}

// getUserPermissionCodes extracts permission codes from user's roles
func (s *AdminPortalService) getUserPermissionCodes(user *userV1.User) []string {
	// Map role IDs to permission codes
	// Role 1 = platform admin, Role 2 = tenant admin template
	var codes []string
	for _, roleID := range user.GetRoleIds() {
		if roleID == 1 {
			codes = append(codes, "platform:admin")
		}
		// Tenant manager roles (derived from template)
		if roleID >= 2 {
			codes = append(codes, "tenant:manager")
		}
	}
	return codes
}

// convertDynamicMenusToRoutes converts parsed menus to route items, filtering by user permissions
func (s *AdminPortalService) convertDynamicMenusToRoutes(menus []*ParsedMenu, userPermCodes []string) []*permissionV1.MenuRouteItem {
	if len(menus) == 0 {
		return nil
	}

	// Build a map for quick lookup and parent-child relationships
	menuMap := make(map[string]*ParsedMenu)
	for _, m := range menus {
		menuMap[m.ID] = m
	}

	// Find root menus (no parent or parent not in this module)
	var rootMenus []*ParsedMenu
	for _, m := range menus {
		if m.ParentID == "" || menuMap[m.ParentID] == nil {
			// Check if user has permission to see this menu
			if s.hasMenuPermission(m, userPermCodes) {
				rootMenus = append(rootMenus, m)
			}
		}
	}

	// Sort root menus by Order field
	sort.Slice(rootMenus, func(i, j int) bool {
		return rootMenus[i].Order < rootMenus[j].Order
	})

	// Convert root menus and their children
	var routes []*permissionV1.MenuRouteItem
	for _, root := range rootMenus {
		route := s.parsedMenuToRoute(root, menuMap, userPermCodes)
		if route != nil {
			routes = append(routes, route)
		}
	}

	return routes
}

// hasMenuPermission checks if user has permission to see a menu
func (s *AdminPortalService) hasMenuPermission(menu *ParsedMenu, userPermCodes []string) bool {
	if len(menu.Authority) == 0 {
		// No authority restriction - everyone can see
		return true
	}
	for _, required := range menu.Authority {
		for _, userCode := range userPermCodes {
			if required == userCode {
				return true
			}
		}
	}
	return false
}

// parsedMenuToRoute converts a ParsedMenu to a MenuRouteItem
func (s *AdminPortalService) parsedMenuToRoute(menu *ParsedMenu, menuMap map[string]*ParsedMenu, userPermCodes []string) *permissionV1.MenuRouteItem {
	if menu.Hidden {
		return nil
	}

	// Determine component: use BasicLayout for parent menus (CATALOG type) without a component
	component := menu.Component
	if component == "" && menu.Type == "CATALOG" {
		component = "BasicLayout"
	}

	route := &permissionV1.MenuRouteItem{
		Path:      trans.Ptr(menu.Path),
		Component: trans.Ptr(component),
		Name:      trans.Ptr(menu.ID), // Use ID as the route name
		Meta: &permissionV1.MenuMeta{
			Title:     trans.Ptr(menu.Name), // Name contains the i18n key or display name
			Icon:      trans.Ptr(menu.Icon),
			Authority: menu.Authority,
		},
	}

	if menu.Order > 0 {
		route.Meta.Order = trans.Ptr(menu.Order)
	}
	if menu.KeepAlive {
		route.Meta.KeepAlive = trans.Ptr(true)
	}
	if menu.Redirect != "" {
		route.Redirect = trans.Ptr(menu.Redirect)
	}

	// Find children menus
	var childMenus []*ParsedMenu
	for _, m := range menuMap {
		if m.ParentID == menu.ID && s.hasMenuPermission(m, userPermCodes) {
			childMenus = append(childMenus, m)
		}
	}

	// Sort children by Order field
	sort.Slice(childMenus, func(i, j int) bool {
		return childMenus[i].Order < childMenus[j].Order
	})

	// Convert children to routes
	for _, child := range childMenus {
		childRoute := s.parsedMenuToRoute(child, menuMap, userPermCodes)
		if childRoute != nil {
			route.Children = append(route.Children, childRoute)
		}
	}

	return route
}

package constants

import (
	dictV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/dict/service/v1"

	"github.com/tx7do/go-utils/trans"

	authenticationV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/authentication/service/v1"
	permissionV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/permission/service/v1"
	userV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/user/service/v1"
)

const (
	// DefaultAdminUserName 系统初始化默认管理员用户名
	DefaultAdminUserName = "admin"
	// DefaultAdminPassword 系统初始化默认管理员用户密码
	DefaultAdminPassword = "admin"

	// DefaultUserPassword 系统初始化默认普通用户密码
	DefaultUserPassword = "12345678"

	// PlatformTenantID 平台管理员租户ID
	PlatformTenantID = uint32(0)
)

// DefaultPermissionGroups 系统初始化默认权限组数据
var DefaultPermissionGroups = []*permissionV1.PermissionGroup{
	{
		//Id:        trans.Ptr(uint32(1)),
		Name:      trans.Ptr("System management"),
		Path:      trans.Ptr("/"),
		Module:    trans.Ptr(SystemPermissionModule),
		SortOrder: trans.Ptr(uint32(1)),
		Status:    trans.Ptr(permissionV1.PermissionGroup_ON),
	},
	{
		//Id:        trans.Ptr(uint32(2)),
		ParentId:  trans.Ptr(uint32(1)),
		Name:      trans.Ptr("System permissions"),
		Path:      trans.Ptr("/1/2/"),
		Module:    trans.Ptr(SystemPermissionModule),
		SortOrder: trans.Ptr(uint32(1)),
		Status:    trans.Ptr(permissionV1.PermissionGroup_ON),
	},
	{
		//Id:        trans.Ptr(uint32(3)),
		ParentId:  trans.Ptr(uint32(1)),
		Name:      trans.Ptr("Tenant management"),
		Path:      trans.Ptr("/1/3/"),
		Module:    trans.Ptr(SystemPermissionModule),
		SortOrder: trans.Ptr(uint32(2)),
		Status:    trans.Ptr(permissionV1.PermissionGroup_ON),
	},
	{
		//Id:        trans.Ptr(uint32(4)),
		ParentId:  trans.Ptr(uint32(1)),
		Name:      trans.Ptr("Audit management"),
		Path:      trans.Ptr("/1/4/"),
		Module:    trans.Ptr(SystemPermissionModule),
		SortOrder: trans.Ptr(uint32(3)),
		Status:    trans.Ptr(permissionV1.PermissionGroup_ON),
	},
	{
		//Id:        trans.Ptr(uint32(5)),
		ParentId:  trans.Ptr(uint32(1)),
		Name:      trans.Ptr("Security policy"),
		Path:      trans.Ptr("/1/5/"),
		Module:    trans.Ptr(SystemPermissionModule),
		SortOrder: trans.Ptr(uint32(4)),
		Status:    trans.Ptr(permissionV1.PermissionGroup_ON),
	},
}

// DefaultPermissions 系统初始化默认权限数据
var DefaultPermissions = []*permissionV1.Permission{
	{
		//Id:          trans.Ptr(uint32(1)),
		GroupId:     trans.Ptr(uint32(2)),
		Name:        trans.Ptr("Visit backend"),
		Description: trans.Ptr("Allow users to access the system backend management interface"),
		Code:        trans.Ptr(SystemAccessBackendPermissionCode),
		Status:      trans.Ptr(permissionV1.Permission_ON),
	},
	{
		//Id:          trans.Ptr(uint32(2)),
		GroupId:     trans.Ptr(uint32(2)),
		Name:        trans.Ptr("Platform administrator permissions"),
		Description: trans.Ptr("Have operational permissions for all functions of the system, and can manage tenants, users, roles, and all resources"),
		Code:        trans.Ptr(SystemPlatformAdminPermissionCode),
		Status:      trans.Ptr(permissionV1.Permission_ON),
		MenuIds: []uint32{
			1, 2,
			10, 11,
			20, 21, 22, 23, 24,
			30, 31, 32, 33, 34,
			40, 41, 42,
			50, 51, 52,
			60, 61, 62, 63, 64,
			// NOTE: LCM, Deployer, Warden, IPAM menus are dynamically registered by their services
		},
		ApiIds: []uint32{
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
			20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
			30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
			40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
			50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
			60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
			70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
			80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
			90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
			100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
			110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
			120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
			130, 131, 132, 133, 134, 135, 136,
		},
	},
	{
		//Id:          trans.Ptr(uint32(3)),
		GroupId:     trans.Ptr(uint32(3)),
		Name:        trans.Ptr("Tenant administrator rights"),
		Description: trans.Ptr("Have operational permissions for all functions within the tenant, and can manage users, roles, and all resources within the tenant"),
		Code:        trans.Ptr(SystemTenantManagerPermissionCode),
		Status:      trans.Ptr(permissionV1.Permission_ON),
		MenuIds: []uint32{
			1, 2,
			20, 21, 22, 23, 24,
			30, 32,
			40, 41,
			50, 51,
			60, 61, 62, 63, 64,
			// NOTE: LCM, Deployer, Warden, IPAM menus are dynamically registered by their services
		},
		ApiIds: []uint32{
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
			20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
			30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
			40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
			50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
			60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
			70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
			80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
			90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
			100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
			110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
			120, 121, 122, 123, 124, 125, 126, 127, 128,
		},
	},

	{
		//Id:          trans.Ptr(uint32(4)),
		GroupId:     trans.Ptr(uint32(3)),
		Name:        trans.Ptr("Manage tenants"),
		Description: trans.Ptr("Allow creating/modifying/deleting tenants"),
		Code:        trans.Ptr(SystemManageTenantsPermissionCode),
		Status:      trans.Ptr(permissionV1.Permission_ON),
	},
	{
		//Id:          trans.Ptr(uint32(5)),
		GroupId:     trans.Ptr(uint32(4)),
		Name:        trans.Ptr("View audit logs"),
		Description: trans.Ptr("Allow viewing system operation logs"),
		Code:        trans.Ptr(SystemAuditLogsPermissionCode),
		Status:      trans.Ptr(permissionV1.Permission_ON),
	},
}

// DefaultRoles 系统初始化默认角色数据
var DefaultRoles = []*userV1.Role{
	{
		//Id:          trans.Ptr(uint32(1)),
		Name:        trans.Ptr(DefaultPlatformAdminRoleName),
		Code:        trans.Ptr(PlatformAdminRoleCode),
		Status:      trans.Ptr(userV1.Role_ON),
		Description: trans.Ptr("Have operational permissions for all functions of the system, and can manage tenants, users, roles, and all resources"),
		IsProtected: trans.Ptr(true),
		IsSystem:    trans.Ptr(true),
		SortOrder:   trans.Ptr(uint32(1)),
		Permissions: []uint32{1, 2, 4},
	},
	{
		//Id:          trans.Ptr(uint32(2)),
		Name:        trans.Ptr(DefaultTenantManagerRoleName + "template"),
		Code:        trans.Ptr(TenantAdminTemplateRoleCode),
		Status:      trans.Ptr(userV1.Role_ON),
		Description: trans.Ptr("Tenant administrator role, have operational permissions for all functions within the tenant, and can manage users, roles, and all resources within the tenant"),
		IsProtected: trans.Ptr(true),
		IsSystem:    trans.Ptr(true),
		SortOrder:   trans.Ptr(uint32(2)),
		Permissions: []uint32{1, 3},
	},
}

// DefaultRoleMetadata 系统初始化默认角色元数据
var DefaultRoleMetadata = []*userV1.RoleMetadata{
	{
		//Id:              trans.Ptr(uint32(1)),
		RoleId:          trans.Ptr(uint32(1)),
		IsTemplate:      trans.Ptr(false),
		TemplateVersion: trans.Ptr(int32(1)),
		Scope:           userV1.RoleMetadata_PLATFORM.Enum(),
		SyncPolicy:      userV1.RoleMetadata_AUTO.Enum(),
	},
	{
		//Id:              trans.Ptr(uint32(2)),
		RoleId:          trans.Ptr(uint32(2)),
		IsTemplate:      trans.Ptr(true),
		TemplateFor:     trans.Ptr(TenantAdminRoleCode),
		TemplateVersion: trans.Ptr(int32(1)),
		Scope:           userV1.RoleMetadata_TENANT.Enum(),
		SyncPolicy:      userV1.RoleMetadata_AUTO.Enum(),
	},
}

// DefaultUsers 系统初始化默认用户数据
var DefaultUsers = []*userV1.User{
	{
		//Id:       trans.Ptr(uint32(1)),
		TenantId: trans.Ptr(uint32(0)),
		Username: trans.Ptr(DefaultAdminUserName),
		Realname: trans.Ptr("Sko"),
		Nickname: trans.Ptr("Sko"),
		Region:   trans.Ptr("EU"),
		Email:    trans.Ptr("admin@gmail.com"),
	},
}

// DefaultUserCredentials 系统初始化默认用户凭证数据
var DefaultUserCredentials = []*authenticationV1.UserCredential{
	{
		UserId:         trans.Ptr(uint32(1)),
		TenantId:       trans.Ptr(uint32(0)),
		IdentityType:   authenticationV1.UserCredential_USERNAME.Enum(),
		Identifier:     trans.Ptr(DefaultAdminUserName),
		CredentialType: authenticationV1.UserCredential_PASSWORD_HASH.Enum(),
		Credential:     trans.Ptr(DefaultAdminPassword),
		IsPrimary:      trans.Ptr(true),
		Status:         authenticationV1.UserCredential_ENABLED.Enum(),
	},
}

// DefaultUserRoles 系统初始化默认用户角色关系数据
var DefaultUserRoles = []*userV1.UserRole{
	{
		UserId:    trans.Ptr(uint32(1)),
		TenantId:  trans.Ptr(uint32(0)),
		RoleId:    trans.Ptr(uint32(1)),
		IsPrimary: trans.Ptr(true),
		Status:    userV1.UserRole_ACTIVE.Enum(),
	},
}

// DefaultMemberships 系统初始化默认用户成员关系数据
var DefaultMemberships = []*userV1.Membership{
	{
		UserId:    trans.Ptr(uint32(1)),
		TenantId:  trans.Ptr(uint32(0)),
		Status:    userV1.Membership_ACTIVE.Enum(),
		IsPrimary: trans.Ptr(true),
		RoleIds:   []uint32{1},
	},
}

// DefaultLanguages 系统初始化默认语言数据
var DefaultLanguages = []*dictV1.Language{
	{LanguageCode: trans.Ptr("zh-CN"), LanguageName: trans.Ptr("中文（简体）"), NativeName: trans.Ptr("简体中文"), IsDefault: trans.Ptr(true), IsEnabled: trans.Ptr(true)},
	{LanguageCode: trans.Ptr("zh-TW"), LanguageName: trans.Ptr("中文（繁体）"), NativeName: trans.Ptr("繁體中文"), IsDefault: trans.Ptr(false), IsEnabled: trans.Ptr(true)},
	{LanguageCode: trans.Ptr("en-US"), LanguageName: trans.Ptr("英语"), NativeName: trans.Ptr("English"), IsDefault: trans.Ptr(false), IsEnabled: trans.Ptr(true)},
	{LanguageCode: trans.Ptr("ja-JP"), LanguageName: trans.Ptr("日语"), NativeName: trans.Ptr("日本語"), IsDefault: trans.Ptr(false), IsEnabled: trans.Ptr(true)},
	{LanguageCode: trans.Ptr("ko-KR"), LanguageName: trans.Ptr("韩语"), NativeName: trans.Ptr("한국어"), IsDefault: trans.Ptr(false), IsEnabled: trans.Ptr(true)},
	{LanguageCode: trans.Ptr("es-ES"), LanguageName: trans.Ptr("西班牙语"), NativeName: trans.Ptr("Español"), IsDefault: trans.Ptr(false), IsEnabled: trans.Ptr(true)},
	{LanguageCode: trans.Ptr("fr-FR"), LanguageName: trans.Ptr("法语"), NativeName: trans.Ptr("Français"), IsDefault: trans.Ptr(false), IsEnabled: trans.Ptr(true)},
}

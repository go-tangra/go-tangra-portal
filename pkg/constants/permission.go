package constants

const (
	// SystemPermissionCodePrefix 系统权限代码前缀
	SystemPermissionCodePrefix = "sys:"

	// SystemAccessBackendPermissionCode 系统访问后台权限代码
	SystemAccessBackendPermissionCode = SystemPermissionCodePrefix + "access_backend"

	// SystemManageTenantsPermissionCode 系统管理租户权限代码
	SystemManageTenantsPermissionCode = SystemPermissionCodePrefix + "manage_tenants"

	// SystemAuditLogsPermissionCode 系统审计日志权限代码
	SystemAuditLogsPermissionCode = SystemPermissionCodePrefix + "audit_logs"

	// SystemPlatformAdminPermissionCode 系统平台管理员权限代码
	SystemPlatformAdminPermissionCode = SystemPermissionCodePrefix + "platform_admin"
	// SystemTenantManagerPermissionCode 系统租户管理员权限代码
	SystemTenantManagerPermissionCode = SystemPermissionCodePrefix + "tenant_manager"
	// SystemSelfServicePermissionCode 自助服务权限代码（所有认证用户需要的基本API）
	SystemSelfServicePermissionCode = SystemPermissionCodePrefix + "self_service"

	// ModuleUserRoleCode 模块用户基础角色代码
	ModuleUserRoleCode = "module.user"

	// SystemPermissionModule 系统权限模块标识
	SystemPermissionModule = "sys"

	// DefaultBizPermissionModule 业务权限模块标识
	DefaultBizPermissionModule = "biz"

	// UncategorizedPermissionGroup 未分类权限组标识
	UncategorizedPermissionGroup = "uncategorized"
)

// SelfServiceAPIEndpoint represents a path/method pair for self-service APIs.
type SelfServiceAPIEndpoint struct {
	Path   string
	Method string
}

// SelfServiceAPIEndpoints defines the API endpoints that the sys:self_service permission grants.
// These are the endpoints every authenticated user needs access to.
var SelfServiceAPIEndpoints = []SelfServiceAPIEndpoint{
	// User profile
	{"/admin/v1/me", "GET"},
	{"/admin/v1/me", "PUT"},
	{"/admin/v1/me/avatar", "POST"},
	{"/admin/v1/me/avatar", "DELETE"},
	{"/admin/v1/me/password", "POST"},
	{"/admin/v1/me/contact", "POST"},
	{"/admin/v1/me/contact/verify", "POST"},
	// Navigation and permissions
	{"/admin/v1/routes", "GET"},
	{"/admin/v1/perm-codes", "GET"},
	{"/admin/v1/initial-context", "GET"},
	// MFA self-service
	{"/admin/v1/me/mfa/status", "GET"},
	{"/admin/v1/me/mfa/methods", "GET"},
	{"/admin/v1/me/mfa/enroll", "POST"},
	{"/admin/v1/me/mfa/enroll/confirm", "POST"},
	{"/admin/v1/me/mfa/disable", "POST"},
	{"/admin/v1/me/mfa/backup-codes", "GET"},
	{"/admin/v1/me/mfa/backup-codes", "POST"},
	{"/admin/v1/me/mfa/devices/{credential_id}", "DELETE"},
	// Module registration (list registered modules for frontend)
	{"/admin/v1/registration/modules", "GET"},
	// Internal messages inbox
	{"/admin/v1/internal-message/inbox", "GET"},
}

// ProtectedPermissionCodes 受保护的权限代码列表，禁止删除
var ProtectedPermissionCodes = []string{
	SystemAccessBackendPermissionCode,
	SystemManageTenantsPermissionCode,
	SystemAuditLogsPermissionCode,
	SystemPlatformAdminPermissionCode,
	SystemTenantManagerPermissionCode,
}

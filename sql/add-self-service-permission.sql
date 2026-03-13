-- Add sys:self_service permission and module.user role
-- This migration is idempotent and safe to run multiple times.
-- It resolves API IDs by path/method instead of hardcoding them.

BEGIN;

-- 1. Create the sys:self_service permission if it doesn't exist
INSERT INTO sys_permissions (code, name, description, status, group_id, created_by)
SELECT 'sys:self_service',
       'Self Service',
       'Basic self-service endpoints: profile, navigation, permissions, MFA, modules, inbox',
       'ON',
       (SELECT id FROM sys_permission_groups WHERE name = 'System management' AND parent_id IS NULL LIMIT 1),
       1
WHERE NOT EXISTS (SELECT 1 FROM sys_permissions WHERE code = 'sys:self_service');

-- 2. Link self-service APIs to the permission (by path/method)
-- These are the endpoints every authenticated user needs
INSERT INTO sys_permission_apis (permission_id, api_id)
SELECT p.id, a.id
FROM sys_permissions p, sys_apis a
WHERE p.code = 'sys:self_service'
  AND (a.path, a.method) IN (
    -- User profile
    ('/admin/v1/me', 'GET'),
    ('/admin/v1/me', 'PUT'),
    ('/admin/v1/me/avatar', 'POST'),
    ('/admin/v1/me/avatar', 'DELETE'),
    ('/admin/v1/me/password', 'POST'),
    ('/admin/v1/me/contact', 'POST'),
    ('/admin/v1/me/contact/verify', 'POST'),
    -- Navigation and permissions
    ('/admin/v1/routes', 'GET'),
    ('/admin/v1/perm-codes', 'GET'),
    ('/admin/v1/initial-context', 'GET'),
    -- MFA self-service
    ('/admin/v1/me/mfa/status', 'GET'),
    ('/admin/v1/me/mfa/methods', 'GET'),
    ('/admin/v1/me/mfa/enroll', 'POST'),
    ('/admin/v1/me/mfa/enroll/confirm', 'POST'),
    ('/admin/v1/me/mfa/disable', 'POST'),
    ('/admin/v1/me/mfa/backup-codes', 'GET'),
    ('/admin/v1/me/mfa/backup-codes', 'POST'),
    ('/admin/v1/me/mfa/devices/{credential_id}', 'DELETE'),
    -- Module registration (list registered modules for frontend)
    ('/admin/v1/registration/modules', 'GET'),
    -- Internal messages inbox
    ('/admin/v1/internal-message/inbox', 'GET')
  )
  AND NOT EXISTS (
    SELECT 1 FROM sys_permission_apis pa
    WHERE pa.permission_id = p.id AND pa.api_id = a.id
  );

-- 3. Create the module.user role if it doesn't exist
INSERT INTO sys_roles (code, name, description, status, is_protected, is_system, sort_order, created_by)
SELECT 'module.user',
       'Module User',
       'Base role for module users with self-service access (profile, navigation, MFA, inbox)',
       'ON',
       true,
       true,
       100,
       1
WHERE NOT EXISTS (SELECT 1 FROM sys_roles WHERE code = 'module.user');

-- 4. Link permissions to the module.user role
-- sys:access_backend (login gate)
INSERT INTO sys_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM sys_roles r, sys_permissions p
WHERE r.code = 'module.user' AND p.code = 'sys:access_backend'
  AND NOT EXISTS (
    SELECT 1 FROM sys_role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
  );

-- sys:self_service
INSERT INTO sys_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM sys_roles r, sys_permissions p
WHERE r.code = 'module.user' AND p.code = 'sys:self_service'
  AND NOT EXISTS (
    SELECT 1 FROM sys_role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
  );

COMMIT;

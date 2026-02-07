-- Cleanup script to remove old static module menus
-- Run this after deploying the dynamic module registration system
-- This removes menus that are now managed dynamically by LCM, Deployer, Warden, and IPAM modules

BEGIN;

-- Remove old permission-menu associations for module menus
DELETE FROM public.sys_permission_menus
WHERE menu_id IN (70, 71, 72, 73, 74, 75, 76, 77,  -- LCM
                  80, 81, 82, 83,                   -- Deployer
                  90, 91, 92,                       -- Warden
                  100, 101, 102, 103, 104, 105, 106); -- IPAM

-- Remove old static module menus (children first, then parents due to foreign key)
-- IPAM child menus
DELETE FROM public.sys_menus WHERE id IN (101, 102, 103, 104, 105, 106);
-- IPAM parent
DELETE FROM public.sys_menus WHERE id = 100;

-- Warden child menus
DELETE FROM public.sys_menus WHERE id IN (91, 92);
-- Warden parent
DELETE FROM public.sys_menus WHERE id = 90;

-- Deployer child menus
DELETE FROM public.sys_menus WHERE id IN (81, 82, 83);
-- Deployer parent
DELETE FROM public.sys_menus WHERE id = 80;

-- LCM child menus
DELETE FROM public.sys_menus WHERE id IN (71, 72, 73, 74, 75, 76, 77);
-- LCM parent
DELETE FROM public.sys_menus WHERE id = 70;

-- Also remove any dynamically created menus from previous module registrations
-- These have names like 'module_id:menu_id'
DELETE FROM public.sys_menus WHERE name LIKE 'lcm:%';
DELETE FROM public.sys_menus WHERE name LIKE 'deployer:%';
DELETE FROM public.sys_menus WHERE name LIKE 'warden:%';
DELETE FROM public.sys_menus WHERE name LIKE 'ipam:%';

-- Remove any dynamically created APIs from previous module registrations
DELETE FROM public.sys_apis WHERE name LIKE 'lcm:%';
DELETE FROM public.sys_apis WHERE name LIKE 'deployer:%';
DELETE FROM public.sys_apis WHERE name LIKE 'warden:%';
DELETE FROM public.sys_apis WHERE name LIKE 'ipam:%';

COMMIT;

-- Verify cleanup
SELECT 'Remaining module menus:' as info;
SELECT id, name, path FROM public.sys_menus
WHERE id >= 70 OR name LIKE '%:%'
ORDER BY id;

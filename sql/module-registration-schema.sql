-- Dynamic Module Registration Schema
-- Description: Tables for dynamic module registration system

BEGIN;

-- Module registration table
-- Stores registered modules and their metadata
CREATE TABLE IF NOT EXISTS sys_modules (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id VARCHAR(64) UNIQUE NOT NULL,
    module_name VARCHAR(255) NOT NULL,
    version VARCHAR(32) NOT NULL,
    description TEXT,
    grpc_endpoint VARCHAR(255) NOT NULL,
    status INTEGER DEFAULT 1,           -- 1=active, 2=inactive, 3=error
    health INTEGER DEFAULT 1,           -- 1=healthy, 2=degraded, 3=unhealthy
    openapi_spec BYTEA,                 -- Stored OpenAPI spec for reconstruction
    proto_descriptor BYTEA,             -- Stored proto descriptor for reconstruction
    registration_id VARCHAR(36),        -- UUID for this registration instance
    registered_at TIMESTAMP DEFAULT NOW(),
    last_heartbeat TIMESTAMP,
    menu_count INTEGER DEFAULT 0,
    api_count INTEGER DEFAULT 0,
    route_count INTEGER DEFAULT 0,
    created_by VARCHAR(64),
    updated_at TIMESTAMP
);

-- Track which menus belong to which module (for cleanup on unregister)
CREATE TABLE IF NOT EXISTS sys_module_menus (
    id SERIAL PRIMARY KEY,
    module_id VARCHAR(64) NOT NULL,
    menu_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT fk_module_menus_module FOREIGN KEY (module_id)
        REFERENCES sys_modules(module_id) ON DELETE CASCADE,
    CONSTRAINT fk_module_menus_menu FOREIGN KEY (menu_id)
        REFERENCES sys_menus(id) ON DELETE CASCADE,
    CONSTRAINT uq_module_menu UNIQUE (module_id, menu_id)
);

-- Track which APIs belong to which module (for cleanup on unregister)
CREATE TABLE IF NOT EXISTS sys_module_apis (
    id SERIAL PRIMARY KEY,
    module_id VARCHAR(64) NOT NULL,
    api_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT fk_module_apis_module FOREIGN KEY (module_id)
        REFERENCES sys_modules(module_id) ON DELETE CASCADE,
    CONSTRAINT fk_module_apis_api FOREIGN KEY (api_id)
        REFERENCES sys_apis(id) ON DELETE CASCADE,
    CONSTRAINT uq_module_api UNIQUE (module_id, api_id)
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_modules_status ON sys_modules(status);
CREATE INDEX IF NOT EXISTS idx_modules_health ON sys_modules(health);
CREATE INDEX IF NOT EXISTS idx_modules_status_health ON sys_modules(status, health);
CREATE INDEX IF NOT EXISTS idx_modules_last_heartbeat ON sys_modules(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_module_menus_module_id ON sys_module_menus(module_id);
CREATE INDEX IF NOT EXISTS idx_module_apis_module_id ON sys_module_apis(module_id);

-- Comments
COMMENT ON TABLE sys_modules IS 'Registered dynamic modules';
COMMENT ON TABLE sys_module_menus IS 'Mapping of modules to their registered menus';
COMMENT ON TABLE sys_module_apis IS 'Mapping of modules to their registered API resources';

COMMENT ON COLUMN sys_modules.status IS '1=active, 2=inactive, 3=error';
COMMENT ON COLUMN sys_modules.health IS '1=healthy, 2=degraded, 3=unhealthy';
COMMENT ON COLUMN sys_modules.openapi_spec IS 'OpenAPI 3.0 spec with x-menu extensions';
COMMENT ON COLUMN sys_modules.proto_descriptor IS 'Compiled FileDescriptorSet for gRPC transcoding';

COMMIT;

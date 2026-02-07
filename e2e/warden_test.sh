#!/bin/sh
# Warden Service E2E Tests
# Usage: ./warden_test.sh [host:port]

set -e

WARDEN_ADDR="${1:-localhost:9300}"
TEST_PASSED=0
TEST_FAILED=0

# Generate unique test suffix based on timestamp
TEST_SUFFIX="$(date +%s)"
FOLDER_NAME="e2e-folder-${TEST_SUFFIX}"
SUBFOLDER_NAME="e2e-subfolder-${TEST_SUFFIX}"
SECRET_NAME="e2e-secret-${TEST_SUFFIX}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_test() {
    echo "${YELLOW}[TEST]${NC} $1"
}

log_pass() {
    echo "${GREEN}[PASS]${NC} $1"
    TEST_PASSED=$((TEST_PASSED + 1))
}

log_fail() {
    echo "${RED}[FAIL]${NC} $1"
    TEST_FAILED=$((TEST_FAILED + 1))
}

log_info() {
    echo "[INFO] $1"
}

# ============================================
# Health Check Tests
# ============================================

log_test "Health Check - gRPC Health"
if grpcurl -plaintext "$WARDEN_ADDR" grpc.health.v1.Health/Check > /dev/null 2>&1; then
    log_pass "gRPC Health check passed"
else
    log_fail "gRPC Health check failed"
fi

log_test "System Health Check"
RESULT=$(grpcurl -plaintext "$WARDEN_ADDR" warden.service.v1.WardenSystemService/Health 2>&1)
if echo "$RESULT" | grep -q "HEALTHY" || echo "$RESULT" | grep -q "healthy"; then
    log_pass "System health check passed"
else
    log_fail "System health check failed: $RESULT"
fi

log_test "Check Vault Connection"
RESULT=$(grpcurl -plaintext "$WARDEN_ADDR" warden.service.v1.WardenSystemService/CheckVault 2>&1)
if echo "$RESULT" | grep -q "connected.*true"; then
    log_pass "Vault connection check passed"
else
    log_fail "Vault connection check failed: $RESULT"
fi

# ============================================
# Folder Tests
# ============================================

log_test "Create Root Folder"
FOLDER_RESULT=$(grpcurl -plaintext -d '{
    "name": "'"$FOLDER_NAME"'",
    "description": "E2E test folder"
}' "$WARDEN_ADDR" warden.service.v1.WardenFolderService/CreateFolder 2>&1)

if echo "$FOLDER_RESULT" | grep -q '"id"'; then
    FOLDER_ID=$(echo "$FOLDER_RESULT" | grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
    log_pass "Created folder with ID: $FOLDER_ID"
else
    log_fail "Failed to create folder: $FOLDER_RESULT"
    FOLDER_ID=""
fi

if [ -n "$FOLDER_ID" ]; then
    log_test "Get Folder by ID"
    GET_RESULT=$(grpcurl -plaintext -d '{
        "id": "'"$FOLDER_ID"'"
    }' "$WARDEN_ADDR" warden.service.v1.WardenFolderService/GetFolder 2>&1)

    if echo "$GET_RESULT" | grep -q "$FOLDER_NAME"; then
        log_pass "Get folder passed"
    else
        log_fail "Get folder failed: $GET_RESULT"
    fi

    log_test "List Folders"
    LIST_RESULT=$(grpcurl -plaintext -d '{}' "$WARDEN_ADDR" warden.service.v1.WardenFolderService/ListFolders 2>&1)

    if echo "$LIST_RESULT" | grep -q "$FOLDER_NAME"; then
        log_pass "List folders passed"
    else
        log_fail "List folders failed: $LIST_RESULT"
    fi

    log_test "Create Subfolder"
    SUBFOLDER_RESULT=$(grpcurl -plaintext -d '{
        "parent_id": "'"$FOLDER_ID"'",
        "name": "'"$SUBFOLDER_NAME"'",
        "description": "E2E test subfolder"
    }' "$WARDEN_ADDR" warden.service.v1.WardenFolderService/CreateFolder 2>&1)

    if echo "$SUBFOLDER_RESULT" | grep -q '"id"'; then
        SUBFOLDER_ID=$(echo "$SUBFOLDER_RESULT" | grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
        log_pass "Created subfolder with ID: $SUBFOLDER_ID"
    else
        log_fail "Failed to create subfolder: $SUBFOLDER_RESULT"
        SUBFOLDER_ID=""
    fi

    log_test "Get Folder Tree"
    TREE_RESULT=$(grpcurl -plaintext -d '{}' "$WARDEN_ADDR" warden.service.v1.WardenFolderService/GetFolderTree 2>&1)

    if echo "$TREE_RESULT" | grep -q "$FOLDER_NAME"; then
        log_pass "Get folder tree passed"
    else
        log_fail "Get folder tree failed: $TREE_RESULT"
    fi

    log_test "Update Folder"
    UPDATED_FOLDER_NAME="${FOLDER_NAME}-updated"
    UPDATE_RESULT=$(grpcurl -plaintext -d '{
        "id": "'"$FOLDER_ID"'",
        "name": "'"$UPDATED_FOLDER_NAME"'",
        "description": "Updated description"
    }' "$WARDEN_ADDR" warden.service.v1.WardenFolderService/UpdateFolder 2>&1)

    if echo "$UPDATE_RESULT" | grep -q "$UPDATED_FOLDER_NAME"; then
        log_pass "Update folder passed"
    else
        log_fail "Update folder failed: $UPDATE_RESULT"
    fi
fi

# ============================================
# Secret Tests
# ============================================

if [ -n "$FOLDER_ID" ]; then
    log_test "Create Secret"
    SECRET_RESULT=$(grpcurl -plaintext -d '{
        "folder_id": "'"$FOLDER_ID"'",
        "name": "'"$SECRET_NAME"'",
        "username": "testuser",
        "password": "SuperSecretP@ss123!",
        "host_url": "https://example.com",
        "description": "E2E test secret"
    }' "$WARDEN_ADDR" warden.service.v1.WardenSecretService/CreateSecret 2>&1)

    if echo "$SECRET_RESULT" | grep -q '"id"'; then
        SECRET_ID=$(echo "$SECRET_RESULT" | grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
        log_pass "Created secret with ID: $SECRET_ID"
    else
        log_fail "Failed to create secret: $SECRET_RESULT"
        SECRET_ID=""
    fi

    if [ -n "$SECRET_ID" ]; then
        log_test "Get Secret (metadata only)"
        GET_SECRET_RESULT=$(grpcurl -plaintext -d '{
            "id": "'"$SECRET_ID"'"
        }' "$WARDEN_ADDR" warden.service.v1.WardenSecretService/GetSecret 2>&1)

        if echo "$GET_SECRET_RESULT" | grep -q "$SECRET_NAME"; then
            log_pass "Get secret passed"
        else
            log_fail "Get secret failed: $GET_SECRET_RESULT"
        fi

        log_test "Get Secret Password"
        GET_PASSWORD_RESULT=$(grpcurl -plaintext -d '{
            "id": "'"$SECRET_ID"'"
        }' "$WARDEN_ADDR" warden.service.v1.WardenSecretService/GetSecretPassword 2>&1)

        if echo "$GET_PASSWORD_RESULT" | grep -q "SuperSecretP@ss123!"; then
            log_pass "Get secret password passed"
        else
            log_fail "Get secret password failed: $GET_PASSWORD_RESULT"
        fi

        log_test "List Secrets in Folder"
        LIST_SECRETS_RESULT=$(grpcurl -plaintext -d '{
            "folder_id": "'"$FOLDER_ID"'"
        }' "$WARDEN_ADDR" warden.service.v1.WardenSecretService/ListSecrets 2>&1)

        if echo "$LIST_SECRETS_RESULT" | grep -q "$SECRET_NAME"; then
            log_pass "List secrets passed"
        else
            log_fail "List secrets failed: $LIST_SECRETS_RESULT"
        fi

        log_test "Update Secret Password (creates new version)"
        UPDATE_PASSWORD_RESULT=$(grpcurl -plaintext -d '{
            "id": "'"$SECRET_ID"'",
            "password": "NewSuperSecretP@ss456!",
            "comment": "Password rotation"
        }' "$WARDEN_ADDR" warden.service.v1.WardenSecretService/UpdateSecretPassword 2>&1)

        if echo "$UPDATE_PASSWORD_RESULT" | grep -q '"currentVersion"'; then
            log_pass "Update secret password passed"
        else
            log_fail "Update secret password failed: $UPDATE_PASSWORD_RESULT"
        fi

        log_test "List Secret Versions"
        LIST_VERSIONS_RESULT=$(grpcurl -plaintext -d '{
            "secret_id": "'"$SECRET_ID"'"
        }' "$WARDEN_ADDR" warden.service.v1.WardenSecretService/ListVersions 2>&1)

        if echo "$LIST_VERSIONS_RESULT" | grep -q "versions"; then
            log_pass "List versions passed"
        else
            log_fail "List versions failed: $LIST_VERSIONS_RESULT"
        fi

        log_test "Search Secrets"
        SEARCH_RESULT=$(grpcurl -plaintext -d '{
            "query": "e2e"
        }' "$WARDEN_ADDR" warden.service.v1.WardenSecretService/SearchSecrets 2>&1)

        if echo "$SEARCH_RESULT" | grep -q "$SECRET_NAME"; then
            log_pass "Search secrets passed"
        else
            log_fail "Search secrets failed: $SEARCH_RESULT"
        fi

        log_test "Update Secret Metadata"
        UPDATED_SECRET_NAME="${SECRET_NAME}-updated"
        UPDATE_SECRET_RESULT=$(grpcurl -plaintext -d '{
            "id": "'"$SECRET_ID"'",
            "name": "'"$UPDATED_SECRET_NAME"'",
            "description": "Updated secret description"
        }' "$WARDEN_ADDR" warden.service.v1.WardenSecretService/UpdateSecret 2>&1)

        if echo "$UPDATE_SECRET_RESULT" | grep -q "$UPDATED_SECRET_NAME"; then
            log_pass "Update secret metadata passed"
        else
            log_fail "Update secret metadata failed: $UPDATE_SECRET_RESULT"
        fi

        # Move secret to subfolder if it exists
        if [ -n "$SUBFOLDER_ID" ]; then
            log_test "Move Secret to Subfolder"
            MOVE_SECRET_RESULT=$(grpcurl -plaintext -d '{
                "id": "'"$SECRET_ID"'",
                "new_folder_id": "'"$SUBFOLDER_ID"'"
            }' "$WARDEN_ADDR" warden.service.v1.WardenSecretService/MoveSecret 2>&1)

            if echo "$MOVE_SECRET_RESULT" | grep -q '"secret"'; then
                log_pass "Move secret passed"
            else
                log_fail "Move secret failed: $MOVE_SECRET_RESULT"
            fi
        fi
    fi
fi

# ============================================
# Permission Tests
# ============================================

if [ -n "$FOLDER_ID" ]; then
    log_test "Grant Access to Folder"
    GRANT_RESULT=$(grpcurl -plaintext -d '{
        "resource_type": "RESOURCE_TYPE_FOLDER",
        "resource_id": "'"$FOLDER_ID"'",
        "relation": "RELATION_VIEWER",
        "subject_type": "SUBJECT_TYPE_USER",
        "subject_id": "user-123"
    }' "$WARDEN_ADDR" warden.service.v1.WardenPermissionService/GrantAccess 2>&1)

    if echo "$GRANT_RESULT" | grep -q "permission" || echo "$GRANT_RESULT" | grep -q "id"; then
        log_pass "Grant access passed"
    else
        log_fail "Grant access failed: $GRANT_RESULT"
    fi

    log_test "Check Access"
    CHECK_RESULT=$(grpcurl -plaintext -d '{
        "user_id": "user-123",
        "resource_type": "RESOURCE_TYPE_FOLDER",
        "resource_id": "'"$FOLDER_ID"'",
        "permission": "PERMISSION_READ"
    }' "$WARDEN_ADDR" warden.service.v1.WardenPermissionService/CheckAccess 2>&1)

    if echo "$CHECK_RESULT" | grep -q "allowed"; then
        log_pass "Check access passed"
    else
        log_fail "Check access failed: $CHECK_RESULT"
    fi

    log_test "List Permissions"
    LIST_PERMS_RESULT=$(grpcurl -plaintext -d '{
        "resource_type": "RESOURCE_TYPE_FOLDER",
        "resource_id": "'"$FOLDER_ID"'"
    }' "$WARDEN_ADDR" warden.service.v1.WardenPermissionService/ListPermissions 2>&1)

    if echo "$LIST_PERMS_RESULT" | grep -q "user-123" || echo "$LIST_PERMS_RESULT" | grep -q "permissions"; then
        log_pass "List permissions passed"
    else
        log_fail "List permissions failed: $LIST_PERMS_RESULT"
    fi

    log_test "Revoke Access"
    REVOKE_RESULT=$(grpcurl -plaintext -d '{
        "resource_type": "RESOURCE_TYPE_FOLDER",
        "resource_id": "'"$FOLDER_ID"'",
        "relation": "RELATION_VIEWER",
        "subject_type": "SUBJECT_TYPE_USER",
        "subject_id": "user-123"
    }' "$WARDEN_ADDR" warden.service.v1.WardenPermissionService/RevokeAccess 2>&1)

    # RevokeAccess returns empty on success
    if [ -z "$REVOKE_RESULT" ] || echo "$REVOKE_RESULT" | grep -q "{}"; then
        log_pass "Revoke access passed"
    else
        log_fail "Revoke access failed: $REVOKE_RESULT"
    fi
fi

# ============================================
# Cleanup Tests
# ============================================

if [ -n "$SECRET_ID" ]; then
    log_test "Delete Secret"
    DELETE_SECRET_RESULT=$(grpcurl -plaintext -d '{
        "id": "'"$SECRET_ID"'"
    }' "$WARDEN_ADDR" warden.service.v1.WardenSecretService/DeleteSecret 2>&1)

    if [ -z "$DELETE_SECRET_RESULT" ] || echo "$DELETE_SECRET_RESULT" | grep -q "{}"; then
        log_pass "Delete secret passed"
    else
        log_fail "Delete secret failed: $DELETE_SECRET_RESULT"
    fi
fi

if [ -n "$SUBFOLDER_ID" ]; then
    log_test "Delete Subfolder"
    DELETE_SUBFOLDER_RESULT=$(grpcurl -plaintext -d '{
        "id": "'"$SUBFOLDER_ID"'"
    }' "$WARDEN_ADDR" warden.service.v1.WardenFolderService/DeleteFolder 2>&1)

    if [ -z "$DELETE_SUBFOLDER_RESULT" ] || echo "$DELETE_SUBFOLDER_RESULT" | grep -q "{}"; then
        log_pass "Delete subfolder passed"
    else
        log_fail "Delete subfolder failed: $DELETE_SUBFOLDER_RESULT"
    fi
fi

if [ -n "$FOLDER_ID" ]; then
    log_test "Delete Root Folder"
    DELETE_FOLDER_RESULT=$(grpcurl -plaintext -d '{
        "id": "'"$FOLDER_ID"'"
    }' "$WARDEN_ADDR" warden.service.v1.WardenFolderService/DeleteFolder 2>&1)

    if [ -z "$DELETE_FOLDER_RESULT" ] || echo "$DELETE_FOLDER_RESULT" | grep -q "{}"; then
        log_pass "Delete folder passed"
    else
        log_fail "Delete folder failed: $DELETE_FOLDER_RESULT"
    fi
fi

# ============================================
# Summary
# ============================================

echo ""
echo "============================================"
echo "E2E Test Summary"
echo "============================================"
echo "${GREEN}Passed: $TEST_PASSED${NC}"
echo "${RED}Failed: $TEST_FAILED${NC}"
echo "============================================"

if [ $TEST_FAILED -gt 0 ]; then
    exit 1
fi

exit 0

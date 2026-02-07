package authz

// Relation represents a permission level in the Zanzibar-like authorization system
type Relation string

const (
	// RelationOwner grants full control: read, write, share, delete
	RelationOwner Relation = "RELATION_OWNER"
	// RelationEditor grants modify access: read, write
	RelationEditor Relation = "RELATION_EDITOR"
	// RelationViewer grants read-only access: read
	RelationViewer Relation = "RELATION_VIEWER"
	// RelationSharer grants share access: read, share
	RelationSharer Relation = "RELATION_SHARER"
)

// Permission represents an action that can be performed on a resource
type Permission string

const (
	// PermissionRead allows viewing the resource
	PermissionRead Permission = "PERMISSION_READ"
	// PermissionWrite allows modifying the resource
	PermissionWrite Permission = "PERMISSION_WRITE"
	// PermissionDelete allows deleting the resource
	PermissionDelete Permission = "PERMISSION_DELETE"
	// PermissionShare allows sharing the resource with others
	PermissionShare Permission = "PERMISSION_SHARE"
)

// ResourceType represents the type of resource being protected
type ResourceType string

const (
	// ResourceTypeFolder represents a folder resource
	ResourceTypeFolder ResourceType = "RESOURCE_TYPE_FOLDER"
	// ResourceTypeSecret represents a secret resource
	ResourceTypeSecret ResourceType = "RESOURCE_TYPE_SECRET"
)

// SubjectType represents the type of entity being granted access
type SubjectType string

const (
	// SubjectTypeUser represents a user subject
	SubjectTypeUser SubjectType = "SUBJECT_TYPE_USER"
	// SubjectTypeRole represents a role subject
	SubjectTypeRole SubjectType = "SUBJECT_TYPE_ROLE"
	// SubjectTypeTenant represents a tenant-wide subject
	SubjectTypeTenant SubjectType = "SUBJECT_TYPE_TENANT"
)

// relationPermissions defines which permissions each relation grants
var relationPermissions = map[Relation][]Permission{
	RelationOwner:  {PermissionRead, PermissionWrite, PermissionDelete, PermissionShare},
	RelationEditor: {PermissionRead, PermissionWrite},
	RelationViewer: {PermissionRead},
	RelationSharer: {PermissionRead, PermissionShare},
}

// RelationGrantsPermission checks if a relation grants a specific permission
func RelationGrantsPermission(relation Relation, permission Permission) bool {
	permissions, ok := relationPermissions[relation]
	if !ok {
		return false
	}
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// GetPermissionsForRelation returns all permissions granted by a relation
func GetPermissionsForRelation(relation Relation) []Permission {
	permissions, ok := relationPermissions[relation]
	if !ok {
		return nil
	}
	result := make([]Permission, len(permissions))
	copy(result, permissions)
	return result
}

// CompareRelations compares two relations and returns:
// -1 if r1 has fewer permissions than r2
//
//	0 if they have the same permissions
//	1 if r1 has more permissions than r2
func CompareRelations(r1, r2 Relation) int {
	p1 := len(relationPermissions[r1])
	p2 := len(relationPermissions[r2])
	if p1 < p2 {
		return -1
	}
	if p1 > p2 {
		return 1
	}
	return 0
}

// GetHighestRelation returns the relation with the most permissions from a list
func GetHighestRelation(relations []Relation) Relation {
	if len(relations) == 0 {
		return ""
	}
	highest := relations[0]
	for _, r := range relations[1:] {
		if CompareRelations(r, highest) > 0 {
			highest = r
		}
	}
	return highest
}

// RelationHierarchy defines inheritance order (higher = more permissions)
var RelationHierarchy = map[Relation]int{
	RelationOwner:  4,
	RelationEditor: 3,
	RelationSharer: 2,
	RelationViewer: 1,
}

// IsRelationAtLeast checks if r1 has at least as many permissions as r2
func IsRelationAtLeast(r1, r2 Relation) bool {
	return RelationHierarchy[r1] >= RelationHierarchy[r2]
}

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/tx7do/go-crud/entgo/mixin"
)

// Permission holds the schema definition for the Permission entity.
// Implements Zanzibar-like permission tuples for fine-grained access control.
type Permission struct {
	ent.Schema
}

// Annotations of the Permission.
func (Permission) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "warden_permissions"},
		entsql.WithComments(true),
	}
}

// Fields of the Permission.
func (Permission) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("resource_type").
			Values("RESOURCE_TYPE_UNSPECIFIED", "RESOURCE_TYPE_FOLDER", "RESOURCE_TYPE_SECRET").
			Comment("Type of resource (folder or secret)"),

		field.String("resource_id").
			NotEmpty().
			MaxLen(36).
			Comment("ID of the folder or secret"),

		field.Enum("relation").
			Values("RELATION_UNSPECIFIED", "RELATION_OWNER", "RELATION_EDITOR", "RELATION_VIEWER", "RELATION_SHARER").
			Comment("Permission level (owner, editor, viewer, sharer)"),

		field.Enum("subject_type").
			Values("SUBJECT_TYPE_UNSPECIFIED", "SUBJECT_TYPE_USER", "SUBJECT_TYPE_ROLE", "SUBJECT_TYPE_TENANT").
			Comment("Type of subject (user, role, or tenant)"),

		field.String("subject_id").
			NotEmpty().
			MaxLen(36).
			Comment("ID of the user, role, or tenant"),

		field.Uint32("granted_by").
			Optional().
			Nillable().
			Comment("User ID who granted this permission"),

		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("Optional expiration time for temporary access"),
	}
}

// Edges of the Permission.
func (Permission) Edges() []ent.Edge {
	return []ent.Edge{
		// Reference to folder (if resource_type is FOLDER)
		edge.From("folder", Folder.Type).
			Ref("permissions").
			Unique().
			Comment("Referenced folder"),

		// Reference to secret (if resource_type is SECRET)
		edge.From("secret", Secret.Type).
			Ref("permissions").
			Unique().
			Comment("Referenced secret"),
	}
}

// Mixin of the Permission.
func (Permission) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the Permission.
func (Permission) Indexes() []ent.Index {
	return []ent.Index{
		// Unique constraint for a permission tuple
		index.Fields("tenant_id", "resource_type", "resource_id", "relation", "subject_type", "subject_id").Unique(),
		// For looking up permissions on a resource
		index.Fields("tenant_id", "resource_type", "resource_id"),
		// For looking up permissions for a subject
		index.Fields("subject_type", "subject_id"),
		// For looking up by tenant
		index.Fields("tenant_id"),
		// For checking expiration
		index.Fields("expires_at"),
	}
}

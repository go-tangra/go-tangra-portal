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

// DocumentPermission holds the schema definition for the DocumentPermission entity.
// Implements Zanzibar-like permission tuples for fine-grained access control.
type DocumentPermission struct {
	ent.Schema
}

// Annotations of the DocumentPermission.
func (DocumentPermission) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "paperless_permissions"},
		entsql.WithComments(true),
	}
}

// Fields of the DocumentPermission.
func (DocumentPermission) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("resource_type").
			Values("RESOURCE_TYPE_UNSPECIFIED", "RESOURCE_TYPE_CATEGORY", "RESOURCE_TYPE_DOCUMENT").
			Comment("Type of resource (category or document)"),

		field.String("resource_id").
			NotEmpty().
			MaxLen(36).
			Comment("ID of the category or document"),

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

// Edges of the DocumentPermission.
func (DocumentPermission) Edges() []ent.Edge {
	return []ent.Edge{
		// Reference to category (if resource_type is CATEGORY)
		edge.From("category", Category.Type).
			Ref("permissions").
			Unique().
			Comment("Referenced category"),

		// Reference to document (if resource_type is DOCUMENT)
		edge.From("document", Document.Type).
			Ref("permissions").
			Unique().
			Comment("Referenced document"),
	}
}

// Mixin of the DocumentPermission.
func (DocumentPermission) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the DocumentPermission.
func (DocumentPermission) Indexes() []ent.Index {
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

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

// Folder holds the schema definition for the Folder entity.
// Folders organize secrets in a hierarchical file-system-like structure.
type Folder struct {
	ent.Schema
}

// Annotations of the Folder.
func (Folder) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "warden_folders"},
		entsql.WithComments(true),
	}
}

// Fields of the Folder.
func (Folder) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("UUID primary key"),

		field.String("parent_id").
			Optional().
			Nillable().
			Comment("Parent folder ID (null for root-level folders)"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Folder name"),

		field.String("path").
			NotEmpty().
			MaxLen(4096).
			Comment("Materialized path (e.g., /root/sub/current)"),

		field.String("description").
			Optional().
			MaxLen(1024).
			Comment("Optional description"),

		field.Int32("depth").
			Default(0).
			Comment("Nesting depth level (0 for root folders)"),
	}
}

// Edges of the Folder.
func (Folder) Edges() []ent.Edge {
	return []ent.Edge{
		// Self-referential edge for parent folder
		edge.To("children", Folder.Type).
			From("parent").
			Field("parent_id").
			Unique().
			Comment("Parent folder"),

		// Secrets contained in this folder
		edge.To("secrets", Secret.Type).
			Comment("Secrets in this folder"),

		// Permissions on this folder
		edge.To("permissions", Permission.Type).
			Comment("Permissions on this folder"),
	}
}

// Mixin of the Folder.
func (Folder) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the Folder.
func (Folder) Indexes() []ent.Index {
	return []ent.Index{
		// Unique constraint on tenant + parent + name
		index.Fields("tenant_id", "parent_id", "name").Unique(),
		// Unique constraint on tenant + path
		index.Fields("tenant_id", "path").Unique(),
		// For listing folders by tenant
		index.Fields("tenant_id"),
		// For finding child folders
		index.Fields("parent_id"),
		// For path-based queries
		index.Fields("path"),
	}
}

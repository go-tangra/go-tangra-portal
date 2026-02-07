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

// Category holds the schema definition for the Category entity.
// Categories organize documents in a hierarchical structure.
type Category struct {
	ent.Schema
}

// Annotations of the Category.
func (Category) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "paperless_categories"},
		entsql.WithComments(true),
	}
}

// Fields of the Category.
func (Category) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("UUID primary key"),

		field.String("parent_id").
			Optional().
			Nillable().
			Comment("Parent category ID (null for root-level categories)"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Category name"),

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
			Comment("Nesting depth level (0 for root categories)"),

		field.Int32("sort_order").
			Default(0).
			Comment("Sort order within parent (lower numbers appear first)"),
	}
}

// Edges of the Category.
func (Category) Edges() []ent.Edge {
	return []ent.Edge{
		// Self-referential edge for parent category
		edge.To("children", Category.Type).
			From("parent").
			Field("parent_id").
			Unique().
			Comment("Parent category"),

		// Documents contained in this category
		edge.To("documents", Document.Type).
			Comment("Documents in this category"),

		// Permissions on this category
		edge.To("permissions", DocumentPermission.Type).
			Comment("Permissions on this category"),
	}
}

// Mixin of the Category.
func (Category) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the Category.
func (Category) Indexes() []ent.Index {
	return []ent.Index{
		// Unique constraint on tenant + parent + name
		index.Fields("tenant_id", "parent_id", "name").Unique(),
		// Unique constraint on tenant + path
		index.Fields("tenant_id", "path").Unique(),
		// For listing categories by tenant
		index.Fields("tenant_id"),
		// For finding child categories
		index.Fields("parent_id"),
		// For path-based queries
		index.Fields("path"),
		// For sorting
		index.Fields("tenant_id", "sort_order"),
	}
}

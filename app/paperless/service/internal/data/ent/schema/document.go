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

// Document holds the schema definition for the Document entity.
// Documents are stored in RustFS/S3 and metadata is stored in the database.
type Document struct {
	ent.Schema
}

// Annotations of the Document.
func (Document) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "paperless_documents"},
		entsql.WithComments(true),
	}
}

// Fields of the Document.
func (Document) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("UUID primary key"),

		field.String("category_id").
			Optional().
			Nillable().
			Comment("Parent category ID (null for root-level documents)"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Document display name"),

		field.String("description").
			Optional().
			MaxLen(4096).
			Comment("Document description"),

		field.String("file_key").
			NotEmpty().
			MaxLen(512).
			Comment("Storage key in RustFS/S3"),

		field.String("file_name").
			NotEmpty().
			MaxLen(255).
			Comment("Original file name"),

		field.Int64("file_size").
			Default(0).
			Comment("File size in bytes"),

		field.String("mime_type").
			Optional().
			MaxLen(255).
			Comment("MIME type of the file"),

		field.String("checksum").
			Optional().
			MaxLen(64).
			Comment("SHA-256 checksum of the file"),

		field.JSON("tags", map[string]string{}).
			Optional().
			Comment("Custom tags (key-value pairs)"),

		field.Enum("status").
			Values("DOCUMENT_STATUS_UNSPECIFIED", "DOCUMENT_STATUS_ACTIVE", "DOCUMENT_STATUS_ARCHIVED", "DOCUMENT_STATUS_DELETED").
			Default("DOCUMENT_STATUS_ACTIVE").
			Comment("Document status"),

		field.Enum("source").
			Values("DOCUMENT_SOURCE_UNSPECIFIED", "DOCUMENT_SOURCE_UPLOAD", "DOCUMENT_SOURCE_EMAIL").
			Default("DOCUMENT_SOURCE_UPLOAD").
			Comment("Source of the document (upload, email, etc.)"),
	}
}

// Edges of the Document.
func (Document) Edges() []ent.Edge {
	return []ent.Edge{
		// Parent category
		edge.From("category", Category.Type).
			Ref("documents").
			Field("category_id").
			Unique().
			Comment("Parent category"),

		// Permissions on this document
		edge.To("permissions", DocumentPermission.Type).
			Comment("Permissions on this document"),
	}
}

// Mixin of the Document.
func (Document) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the Document.
func (Document) Indexes() []ent.Index {
	return []ent.Index{
		// Unique constraint on tenant + category + name
		index.Fields("tenant_id", "category_id", "name").Unique(),
		// For listing documents by tenant
		index.Fields("tenant_id"),
		// For finding documents in a category
		index.Fields("category_id"),
		// For searching by name
		index.Fields("tenant_id", "name"),
		// For filtering by status
		index.Fields("status"),
		// For storage key lookups
		index.Fields("file_key").Unique(),
		// For filtering by MIME type
		index.Fields("tenant_id", "mime_type"),
	}
}

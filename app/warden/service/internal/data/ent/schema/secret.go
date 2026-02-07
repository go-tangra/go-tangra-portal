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

// Secret holds the schema definition for the Secret entity.
// Secrets store credentials with references to HashiCorp Vault for actual password storage.
type Secret struct {
	ent.Schema
}

// Annotations of the Secret.
func (Secret) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "warden_secrets"},
		entsql.WithComments(true),
	}
}

// Fields of the Secret.
func (Secret) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("UUID primary key"),

		field.String("folder_id").
			Optional().
			Nillable().
			Comment("Parent folder ID (null for root-level secrets)"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Secret name"),

		field.String("username").
			Optional().
			MaxLen(255).
			Comment("Associated username"),

		field.String("host_url").
			Optional().
			MaxLen(2048).
			Comment("Host/URL associated with the secret"),

		field.String("vault_path").
			NotEmpty().
			Comment("Reference path to HashiCorp Vault"),

		field.Int32("current_version").
			Default(1).
			Comment("Current active version number"),

		field.JSON("metadata", map[string]any{}).
			Optional().
			Comment("Custom fields, notes, tags (JSON)"),

		field.String("description").
			Optional().
			MaxLen(4096).
			Comment("Description"),

		field.Enum("status").
			Values("SECRET_STATUS_UNSPECIFIED", "SECRET_STATUS_ACTIVE", "SECRET_STATUS_ARCHIVED", "SECRET_STATUS_DELETED").
			Default("SECRET_STATUS_ACTIVE").
			Comment("Secret status"),
	}
}

// Edges of the Secret.
func (Secret) Edges() []ent.Edge {
	return []ent.Edge{
		// Parent folder
		edge.From("folder", Folder.Type).
			Ref("secrets").
			Field("folder_id").
			Unique().
			Comment("Parent folder"),

		// Versions of this secret
		edge.To("versions", SecretVersion.Type).
			Comment("Secret versions"),

		// Permissions on this secret
		edge.To("permissions", Permission.Type).
			Comment("Permissions on this secret"),
	}
}

// Mixin of the Secret.
func (Secret) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the Secret.
func (Secret) Indexes() []ent.Index {
	return []ent.Index{
		// Unique constraint on tenant + folder + name
		index.Fields("tenant_id", "folder_id", "name").Unique(),
		// For listing secrets by tenant
		index.Fields("tenant_id"),
		// For finding secrets in a folder
		index.Fields("folder_id"),
		// For searching by name
		index.Fields("tenant_id", "name"),
		// For searching by username
		index.Fields("tenant_id", "username"),
		// For filtering by status
		index.Fields("status"),
		// For Vault path lookups
		index.Fields("vault_path").Unique(),
	}
}

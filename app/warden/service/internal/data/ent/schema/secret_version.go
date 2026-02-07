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

// SecretVersion holds the schema definition for the SecretVersion entity.
// Each version represents a password change, enabling version history and rollback.
type SecretVersion struct {
	ent.Schema
}

// Annotations of the SecretVersion.
func (SecretVersion) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "warden_secret_versions"},
		entsql.WithComments(true),
	}
}

// Fields of the SecretVersion.
func (SecretVersion) Fields() []ent.Field {
	return []ent.Field{
		field.String("secret_id").
			NotEmpty().
			Comment("Parent secret ID"),

		field.Int32("version_number").
			Positive().
			Comment("Version number (1, 2, 3...)"),

		field.String("vault_path").
			NotEmpty().
			Comment("Vault path for this version"),

		field.String("comment").
			Optional().
			MaxLen(1024).
			Comment("Version comment describing the change"),

		field.String("checksum").
			NotEmpty().
			MaxLen(64).
			Comment("SHA-256 checksum of the password"),
	}
}

// Edges of the SecretVersion.
func (SecretVersion) Edges() []ent.Edge {
	return []ent.Edge{
		// Parent secret
		edge.From("secret", Secret.Type).
			Ref("versions").
			Field("secret_id").
			Required().
			Unique().
			Comment("Parent secret"),
	}
}

// Mixin of the SecretVersion.
func (SecretVersion) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.Time{},
	}
}

// Indexes of the SecretVersion.
func (SecretVersion) Indexes() []ent.Index {
	return []ent.Index{
		// Unique constraint on secret + version number
		index.Fields("secret_id", "version_number").Unique(),
		// For listing versions of a secret
		index.Fields("secret_id"),
		// For Vault path lookups
		index.Fields("vault_path").Unique(),
	}
}

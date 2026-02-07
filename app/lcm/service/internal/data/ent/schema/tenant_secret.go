package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/tx7do/go-crud/entgo/mixin"
)

// TenantSecret holds the schema definition for the TenantSecret entity.
// This maps shared secrets to tenants for client registration.
type TenantSecret struct {
	ent.Schema
}

// Annotations of the TenantSecret.
func (TenantSecret) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lcm_tenant_secrets"},
		entsql.WithComments(true),
	}
}

// Fields of the TenantSecret.
func (TenantSecret) Fields() []ent.Field {
	return []ent.Field{
		field.Uint32("tenant_id").
			Comment("Tenant ID this secret belongs to"),

		field.String("secret_hash").
			NotEmpty().
			Comment("SHA-256 hash of the shared secret"),

		field.String("description").
			Optional().
			Comment("Description of this secret"),

		field.Enum("status").
			Values("TENANT_SECRET_STATUS_UNSPECIFIED", "TENANT_SECRET_STATUS_ACTIVE", "TENANT_SECRET_STATUS_DISABLED").
			Default("TENANT_SECRET_STATUS_ACTIVE").
			Comment("Secret status"),

		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("Expiration time for this secret"),
	}
}

// Edges of the TenantSecret.
func (TenantSecret) Edges() []ent.Edge {
	return nil
}

// Mixin of the TenantSecret.
func (TenantSecret) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
	}
}

// Indexes of the TenantSecret.
func (TenantSecret) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("secret_hash").Unique(),
		index.Fields("status"),
	}
}

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

// Issuer holds the schema definition for the Issuer entity.
// This is the base table that holds common issuer information.
type Issuer struct {
	ent.Schema
}

// Annotations of the Issuer.
func (Issuer) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "issuers"},
		entsql.WithComments(true),
	}
}

// Fields of the Issuer.
func (Issuer) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			NotEmpty().
			Comment("issuer name/identifier"),

		field.Enum("type").
			Values("self-signed", "acme").
			Comment("Issuer type"),

		field.String("description").
			Optional().
			Comment("Human-readable description"),

		field.JSON("config", map[string]string{}).
			Optional().
			Comment("General issuer configuration"),

		field.String("client_id").
			Optional().
			Comment("Legacy client ID field (deprecated - use lcm_client relationship)"),

		field.Enum("status").
			Optional().
			Nillable().
			Default("ISSUER_STATUS_UNSPECIFIED").
			Values(
				"ISSUER_STATUS_UNSPECIFIED",
				"ISSUER_STATUS_ACTIVE",
				"ISSUER_STATUS_DISABLED",
				"ISSUER_STATUS_ERROR",
			),
	}
}

// Edges of the Issuer.
func (Issuer) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("self_signed_configs", SelfSignedIssuer.Type).
			Comment("Self-signed issuer configurations"),
		edge.To("acme_configs", AcmeIssuer.Type).
			Comment("ACME issuer configurations"),
		edge.From("certificate_requests", CertificateRequest.Type).
			Ref("issuer").
			Comment("Certificate requests using this issuer"),
		edge.From("client_associations", ClientIssuer.Type).
			Ref("issuer").
			Comment("Client associations with this issuer"),
		edge.From("lcm_client", LcmClient.Type).
			Ref("owned_issuers").
			Unique().
			Comment("LCM client that owns this issuer"),
	}
}

// Mixin of the Issuer.
func (Issuer) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the Issuer.
func (Issuer) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("name"),
		index.Fields("type"),
		index.Fields("client_id"),
		// Unique constraint: each tenant can have only one issuer with a given name
		index.Fields("tenant_id", "name").
			Unique(),
	}
}

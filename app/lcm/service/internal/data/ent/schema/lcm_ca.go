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

// LcmClient holds the schema definition for the LcmClient entity.
// This represents a logical client that can have multiple mTLS certificates.
type LcmCa struct {
	ent.Schema
}

// Annotations of the LcmClient.
func (LcmCa) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lcm_ca"},
		entsql.WithComments(true),
	}
}

// Fields of the LcmClient.
func (LcmCa) Fields() []ent.Field {
	return []ent.Field{
		field.String("key_pem").
			NotEmpty().
			Comment("PEM encoded private key"),
		field.String("certificate_pem").
			Optional().
			Comment("PEM encoded certificate"),

		field.String("fingerprint").
			Optional().
			Comment("Certificate fingerprint"),

		field.String("subject").
			Optional().
			Comment("Subject of the certificate"),
		field.String("serial").
			Optional().
			Comment("Serial number of the certificate"),

		field.Time("not_before").
			Comment("Not before time").
			Optional().
			Nillable(),
		field.Time("not_after").
			Comment("Not after time").
			Optional().
			Nillable(),
	}
}

// Edges of the LcmClient.
func (LcmCa) Edges() []ent.Edge {
	return []ent.Edge{
		// One-to-One relationship with LcmClient
		edge.From("lcm_client", LcmClient.Type).
			Ref("lcm_ca").
			Unique().
			Comment("Client that owns this CA"),
	}
}

// Mixin of the LcmCa.
func (LcmCa) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the LcmCa.
func (LcmCa) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
	}
}

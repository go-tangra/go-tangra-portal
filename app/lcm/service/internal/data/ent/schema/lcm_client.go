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
type LcmClient struct {
	ent.Schema
}

// Annotations of the LcmClient.
func (LcmClient) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lcm_clients"},
		entsql.WithComments(true),
	}
}

// Fields of the LcmClient.
func (LcmClient) Fields() []ent.Field {
	return []ent.Field{
		field.String("client_id").
			NotEmpty().
			Comment("Client identifier (unique per tenant)"),
		field.String("description").
			Optional().
			Comment("Client description"),

		field.String("organization").
			Optional().
			Comment("Client organization"),

		field.String("contact_email").
			Optional().
			Comment("Contact email for this client"),

		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("Additional client metadata"),

		field.Enum("status").
			Values("LCM_CLIENT_UNSPECIFIED", "LCM_CLIENT_ACTIVE", "LCM_CLIENT_DISABLED", "LCM_CLIENT_SUSPENDED").
			Optional().
			Nillable().
			Default("LCM_CLIENT_ACTIVE").
			Comment("Client status"),
	}
}

// Edges of the LcmClient.
func (LcmClient) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("mtls_certificates", MtlsCertificate.Type).
			Comment("mTLS certificates associated with this client"),
		edge.To("mtls_certificate_requests", MtlsCertificateRequest.Type).
			Comment("mTLS certificate requests associated with this client"),
		edge.To("owned_issuers", Issuer.Type).
			Comment("Issuers owned by this client"),

		edge.To("certificate_requests", CertificateRequest.Type).
			Comment("Certificate requests made by this client"),

		edge.To("issued_certificates", IssuedCertificate.Type).
			Comment("Certificates issued to this client"),

		edge.From("client_issuer_associations", ClientIssuer.Type).
			Ref("lcm_client").
			Comment("Issuer associations for this client"),

		// One-to-One relationship with LcmCa
		edge.To("lcm_ca", LcmCa.Type).
			Unique().
			Comment("CA associated with this client"),

		edge.From("certificate_grants", CertificatePermission.Type).
			Ref("grantee").
			Comment("Certificate permissions granted to this client"),
	}
}

// Mixin of the LcmClient.
func (LcmClient) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the LcmClient.
func (LcmClient) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "client_id").Unique(),
		index.Fields("tenant_id"),
		index.Fields("status"),
		index.Fields("organization"),
	}
}

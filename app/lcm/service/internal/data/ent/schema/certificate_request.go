package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// CertificateRequest holds the schema definition for the CertificateRequest entity.
type CertificateRequest struct {
	ent.Schema
}

// Annotations of the CertificateRequest.
func (CertificateRequest) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "certificate_requests"},
		entsql.WithComments(true),
	}
}

// Fields of the CertificateRequest.
func (CertificateRequest) Fields() []ent.Field {
	return []ent.Field{
		field.String("request_id").
			Unique().
			NotEmpty().
			Comment("Unique request identifier"),

		field.String("client_id").
			Optional().
			Comment("Legacy client identifier (deprecated - use lcm_client relationship)"),

		field.String("issuer_name").
			Optional().
			Comment("Issuer to use for this certificate (if not specified, use default)"),

		field.String("hostname").
			NotEmpty().
			Comment("Client hostname"),

		field.Text("public_key").
			NotEmpty().
			Comment("Client's public key in PEM format"),

		field.JSON("dns_names", []string{}).
			Optional().
			Comment("Additional DNS names for the certificate"),

		field.JSON("ip_addresses", []string{}).
			Optional().
			Comment("IP addresses for the certificate"),

		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("Client metadata (OS, architecture, etc.)"),

		field.Enum("status").
			Values("unknown", "issued", "pending", "revoked").
			Default("pending").
			Comment("Certificate status"),

		field.Text("certificate").
			Optional().
			Comment("Generated certificate in PEM format"),

		field.Time("expires_at").
			Optional().
			Comment("Certificate expiration time"),

		field.Time("revoked_at").
			Optional().
			Comment("Certificate revocation time"),

		field.String("revoked_by").
			Optional().
			Comment("User who revoked the certificate"),

		field.String("revoked_reason").
			Optional().
			Comment("Reason for revocation"),

		field.String("approved_by").
			Optional().
			Comment("User who approved the certificate"),

		field.Time("approved_at").
			Optional().
			Comment("Certificate approval time"),

		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Creation time"),

		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Update time"),
	}
}

// Edges of the CertificateRequest.
func (CertificateRequest) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("issuer", Issuer.Type).
			Unique().
			Comment("The issuer used for this certificate"),
		edge.From("lcm_client", LcmClient.Type).
			Ref("certificate_requests").
			Unique().
			Comment("The LCM client that made this request"),
	}
}

// Indexes of the CertificateRequest.
func (CertificateRequest) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("request_id"),
		index.Fields("client_id"),
		index.Fields("status"),
		index.Fields("created_at"),
	}
}

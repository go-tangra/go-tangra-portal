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

// SelfSignedIssuer holds the schema definition for the SelfSignedIssuer entity.
// This table stores configuration specific to self-signed certificate issuers.
type SelfSignedIssuer struct {
	ent.Schema
}

// Annotations of the SelfSignedIssuer.
func (SelfSignedIssuer) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "self_signed_issuers"},
		entsql.WithComments(true),
	}
}

// Fields of the SelfSignedIssuer.
func (SelfSignedIssuer) Fields() []ent.Field {
	return []ent.Field{
		// Certificate fields
		field.String("common_name").
			NotEmpty().
			Comment("Common name for self-signed certificates"),

		field.JSON("dns_names", []string{}).
			Optional().
			Comment("DNS names for self-signed certificates"),

		field.JSON("ip_addresses", []string{}).
			Optional().
			Comment("IP addresses for self-signed certificates"),

		// CA certificate configuration
		field.String("ca_common_name").
			NotEmpty().
			Comment("CA certificate common name"),

		field.String("ca_organization").
			Optional().
			Comment("CA certificate organization"),

		field.String("ca_organizational_unit").
			Optional().
			Comment("CA certificate organizational unit"),

		field.String("ca_country").
			Optional().
			Comment("CA certificate country code (2 letters)"),

		field.String("ca_province").
			Optional().
			Comment("CA certificate province/state"),

		field.String("ca_locality").
			Optional().
			Comment("CA certificate locality/city"),

		field.Int32("ca_validity_days").
			Default(365).
			Comment("CA certificate validity in days"),

		// CA certificate storage (PEM encoded)
		field.Text("ca_certificate_pem").
			Optional().
			Comment("CA certificate in PEM format"),

		// CA private key storage (PEM encoded, encrypted)
		field.Text("ca_private_key_pem").
			Optional().
			Comment("CA private key in PEM format (server-side only, never exposed)"),

		// CA certificate metadata
		field.String("ca_certificate_fingerprint").
			Optional().
			Comment("CA certificate fingerprint for identification"),

		field.Time("ca_expires_at").
			Optional().
			Comment("CA certificate expiration time"),

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

// Edges of the SelfSignedIssuer.
func (SelfSignedIssuer) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("issuer", Issuer.Type).
			Ref("self_signed_configs").
			Unique().
			Required().
			Comment("Parent issuer"),
	}
}

// Indexes of the SelfSignedIssuer.
func (SelfSignedIssuer) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("common_name"),
		index.Fields("ca_common_name"),
		index.Fields("created_at"),
	}
}

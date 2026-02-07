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

// AcmeIssuer holds the schema definition for the AcmeIssuer entity.
// This table stores configuration specific to ACME certificate issuers.
type AcmeIssuer struct {
	ent.Schema
}

// Annotations of the AcmeIssuer.
func (AcmeIssuer) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "acme_issuers"},
		entsql.WithComments(true),
	}
}

// Fields of the AcmeIssuer.
func (AcmeIssuer) Fields() []ent.Field {
	return []ent.Field{
		// ACME account configuration
		field.String("email").
			NotEmpty().
			Comment("ACME account email address"),

		field.String("endpoint").
			NotEmpty().
			Comment("ACME server endpoint URL"),

		// Key configuration
		field.Enum("key_type").
			Values("rsa", "ec").
			Default("rsa").
			Comment("Key type (RSA or EC)"),

		field.Int32("key_size").
			Default(2048).
			Comment("Key size in bits (e.g., 2048, 3072, 4096 for RSA; 256, 384 for EC)"),

		field.Text("key_pem").
			Optional().
			Sensitive().
			Comment("ACME account private key in PEM format"),

		// Retry configuration
		field.Int32("max_retries").
			Default(3).
			Comment("Maximum number of retry attempts"),

		field.String("base_delay").
			Default("2s").
			Comment("Base delay between retries (e.g., '2s', '5m', '1h')"),

		// Challenge configuration
		field.Enum("challenge_type").
			Values("HTTP", "DNS").
			Default("HTTP").
			Comment("Challenge type for domain verification"),

		field.String("provider_name").
			Optional().
			Comment("DNS provider name for DNS challenges (e.g., 'cloudflare', 'route53')"),

		field.JSON("provider_config", map[string]string{}).
			Optional().
			Comment("Provider-specific configuration for challenges"),

		// External Account Binding (EAB) for ACME providers that require it
		field.String("eab_kid").
			Optional().
			Comment("EAB Key Identifier for providers like ZeroSSL, Google Trust Services"),

		field.String("eab_hmac_key").
			Optional().
			Sensitive().
			Comment("EAB HMAC Key (base64 encoded) - sensitive, never exposed"),

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

// Edges of the AcmeIssuer.
func (AcmeIssuer) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("issuer", Issuer.Type).
			Ref("acme_configs").
			Unique().
			Required().
			Comment("Parent issuer"),
	}
}

// Indexes of the AcmeIssuer.
func (AcmeIssuer) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email"),
		index.Fields("endpoint"),
		index.Fields("challenge_type"),
		index.Fields("eab_kid"),
		index.Fields("created_at"),
	}
}

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

// ClientIssuer holds the schema definition for the ClientIssuer entity.
// This is a junction table to manage which issuers a client can use.
type ClientIssuer struct {
	ent.Schema
}

// Annotations of the ClientIssuer.
func (ClientIssuer) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "client_issuers"},
		entsql.WithComments(true),
	}
}

// Fields of the ClientIssuer.
func (ClientIssuer) Fields() []ent.Field {
	return []ent.Field{
		field.String("client_id").
			Optional().
			Comment("Legacy client identifier (deprecated - use lcm_client relationship)"),
		
		field.String("issuer_name").
			NotEmpty().
			Comment("Issuer name"),
		
		field.Bool("is_default").
			Default(false).
			Comment("Whether this is the default issuer for this client"),
		
		field.Int("priority").
			Default(0).
			Comment("Priority order for issuer selection (higher = preferred)"),
		
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

// Edges of the ClientIssuer.
func (ClientIssuer) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("issuer", Issuer.Type).
			Required().
			Unique().
			Comment("Reference to the issuer"),
		edge.To("lcm_client", LcmClient.Type).
			Unique().
			Comment("Reference to the LCM client"),
	}
}

// Indexes of the ClientIssuer.
func (ClientIssuer) Indexes() []ent.Index {
	return []ent.Index{
		// Composite primary key
		index.Fields("client_id", "issuer_name").Unique(),
		// Index for finding client's issuers
		index.Fields("client_id"),
		// Index for finding clients of an issuer
		index.Fields("issuer_name"),
		// Index for default issuer lookup
		index.Fields("client_id", "is_default"),
		// Index for priority ordering
		index.Fields("client_id", "priority"),
		index.Fields("created_at"),
	}
}
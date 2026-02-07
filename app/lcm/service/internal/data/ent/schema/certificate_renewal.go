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

// CertificateRenewal holds the schema definition for tracking certificate renewals.
// This table persists renewal job state across server restarts.
type CertificateRenewal struct {
	ent.Schema
}

// Annotations of the CertificateRenewal.
func (CertificateRenewal) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "certificate_renewals"},
		entsql.WithComments(true),
	}
}

// Fields of the CertificateRenewal.
func (CertificateRenewal) Fields() []ent.Field {
	return []ent.Field{
		field.String("certificate_id").
			NotEmpty().
			Comment("ID of the certificate to be renewed"),
		
		field.String("client_id").
			NotEmpty().
			Comment("Client who owns the certificate"),
		
		field.Enum("status").
			Values("pending", "processing", "completed", "failed", "cancelled").
			Default("pending").
			Comment("Current renewal status"),
		
		field.Time("scheduled_at").
			Comment("When the renewal is scheduled to run"),
		
		field.Time("started_at").
			Optional().
			Comment("When the renewal process actually started"),
		
		field.Time("completed_at").
			Optional().
			Comment("When the renewal process completed"),
		
		field.Int32("attempt_number").
			Default(1).
			Comment("Current attempt number (for retries)"),
		
		field.Int32("max_attempts").
			Default(3).
			Comment("Maximum number of attempts allowed"),
		
		field.String("error_message").
			Optional().
			Comment("Error message if renewal failed"),
		
		field.String("worker_id").
			Optional().
			Comment("ID of the worker processing this renewal"),
		
		field.Time("locked_at").
			Optional().
			Comment("When this renewal was locked by a worker"),
		
		field.Time("lock_expires_at").
			Optional().
			Comment("When the worker lock expires"),
		
		field.JSON("renewal_config", map[string]interface{}{}).
			Optional().
			Comment("Renewal configuration snapshot"),
		
		field.String("issuer_name").
			NotEmpty().
			Comment("Issuer to use for renewal"),
		
		field.JSON("domains", []string{}).
			Comment("Domains to renew certificate for"),
		
		field.Time("original_expires_at").
			Comment("Original certificate expiration time"),
		
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("When the renewal was scheduled"),
		
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Last update time"),
	}
}

// Edges of the CertificateRenewal.
func (CertificateRenewal) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("issued_certificate", IssuedCertificate.Type).
			Unique().
			Required().
			Field("certificate_id").
			Comment("The certificate being renewed"),
	}
}

// Indexes of the CertificateRenewal.
func (CertificateRenewal) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("certificate_id"),
		index.Fields("client_id"),
		index.Fields("status"),
		index.Fields("scheduled_at"),
		index.Fields("status", "scheduled_at"),
		index.Fields("worker_id"),
		index.Fields("locked_at"),
		index.Fields("lock_expires_at"),
		// For finding renewals that need processing
		index.Fields("status", "scheduled_at", "attempt_number"),
		// For worker cleanup of expired locks
		index.Fields("status", "lock_expires_at"),
	}
}
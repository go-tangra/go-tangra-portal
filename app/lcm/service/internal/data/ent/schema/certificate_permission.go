package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/tx7do/go-crud/entgo/mixin"
)

// CertificatePermission holds the schema definition for granting certificate access to other clients.
// This is a junction table to manage which clients can access certificates they don't own.
type CertificatePermission struct {
	ent.Schema
}

// Annotations of the CertificatePermission.
func (CertificatePermission) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "certificate_permissions"},
		entsql.WithComments(true),
	}
}

// Fields of the CertificatePermission.
func (CertificatePermission) Fields() []ent.Field {
	return []ent.Field{
		field.String("certificate_id").
			NotEmpty().
			Comment("ID of the issued certificate being shared"),

		field.Uint32("grantee_id").
			Comment("ID of the LCM client receiving access"),

		field.Enum("permission_type").
			Values("READ", "DOWNLOAD", "FULL").
			Default("READ").
			Comment("Type of permission: READ (view metadata), DOWNLOAD (download cert+key), FULL (all including revoke)"),

		field.String("granted_by").
			NotEmpty().
			Comment("Client ID of the owner who granted permission"),

		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("Optional expiration time for the permission"),

		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Permission creation time"),

		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Last update time"),
	}
}

// Edges of the CertificatePermission.
func (CertificatePermission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("issued_certificate", IssuedCertificate.Type).
			Required().
			Unique().
			Field("certificate_id").
			Comment("Reference to the issued certificate being shared"),

		edge.To("grantee", LcmClient.Type).
			Required().
			Unique().
			Field("grantee_id").
			Comment("Reference to the LCM client receiving access"),
	}
}

// Mixin of the CertificatePermission.
func (CertificatePermission) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the CertificatePermission.
func (CertificatePermission) Indexes() []ent.Index {
	return []ent.Index{
		// Unique: prevent duplicate grants for same certificate + grantee
		index.Fields("certificate_id", "grantee_id").Unique(),
		// Index for listing permissions per certificate
		index.Fields("certificate_id"),
		// Index for listing certificates accessible to a client
		index.Fields("grantee_id"),
		// Index for tenant isolation
		index.Fields("tenant_id"),
		// Index for finding expired permissions
		index.Fields("expires_at"),
		// Index for listing who granted permissions
		index.Fields("granted_by"),
	}
}

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

// MtlsCertificateRequest holds the schema definition for the MtlsCertificateRequest entity.
// This represents an mTLS certificate request submitted by a client.
type MtlsCertificateRequest struct {
	ent.Schema
}

// Annotations of the MtlsCertificateRequest.
func (MtlsCertificateRequest) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "mtls_certificate_requests"},
		entsql.WithComments(true),
	}
}

// Fields of the MtlsCertificateRequest.
func (MtlsCertificateRequest) Fields() []ent.Field {
	return []ent.Field{
		field.String("request_id").
			NotEmpty().
			Unique().
			Comment("UUID for tracking the request"),

		field.String("client_id").
			NotEmpty().
			Comment("Requesting client ID"),

		field.String("common_name").
			Optional().
			Comment("Common Name (CN) for the certificate"),

		field.Text("csr_pem").
			Optional().
			Comment("PEM-encoded Certificate Signing Request"),

		field.Text("public_key").
			Optional().
			Comment("Public key from CSR in PEM format"),

		field.JSON("dns_names", []string{}).
			Optional().
			Comment("Subject Alternative Names - DNS"),

		field.JSON("ip_addresses", []string{}).
			Optional().
			Comment("Subject Alternative Names - IPs"),

		field.String("issuer_name").
			Optional().
			Comment("Issuer to use for signing"),

		field.Enum("cert_type").
			Values("MTLS_CERT_TYPE_UNSPECIFIED", "MTLS_CERT_TYPE_CLIENT", "MTLS_CERT_TYPE_INTERNAL").
			Optional().
			Nillable().
			Default("MTLS_CERT_TYPE_CLIENT").
			Comment("Certificate type"),

		field.Enum("status").
			Values(
				"MTLS_CERTIFICATE_REQUEST_STATUS_UNSPECIFIED",
				"MTLS_CERTIFICATE_REQUEST_STATUS_PENDING",
				"MTLS_CERTIFICATE_REQUEST_STATUS_APPROVED",
				"MTLS_CERTIFICATE_REQUEST_STATUS_REJECTED",
				"MTLS_CERTIFICATE_REQUEST_STATUS_ISSUED",
				"MTLS_CERTIFICATE_REQUEST_STATUS_CANCELLED",
			).
			Optional().
			Nillable().
			Default("MTLS_CERTIFICATE_REQUEST_STATUS_PENDING").
			Comment("Certificate request status"),

		field.Int32("validity_days").
			Optional().
			Nillable().
			Comment("Requested validity period in days"),

		field.String("reject_reason").
			Optional().
			Comment("Reason for rejection"),

		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("Custom metadata"),

		field.Text("notes").
			Optional().
			Comment("Admin notes"),

		field.Uint32("approved_by").
			Optional().
			Nillable().
			Comment("User ID who approved the request"),

		field.Uint32("rejected_by").
			Optional().
			Nillable().
			Comment("User ID who rejected the request"),

		field.Time("approved_at").
			Optional().
			Nillable().
			Comment("Approval timestamp"),

		field.Time("rejected_at").
			Optional().
			Nillable().
			Comment("Rejection timestamp"),

		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("Request expiration timestamp"),

		field.Int64("certificate_serial").
			Optional().
			Nillable().
			Comment("Issued certificate serial number (if approved)"),
	}
}

// Edges of the MtlsCertificateRequest.
func (MtlsCertificateRequest) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lcm_client", LcmClient.Type).
			Ref("mtls_certificate_requests").
			Unique().
			Comment("The LCM client this certificate request belongs to"),
	}
}

// Mixin of the MtlsCertificateRequest.
func (MtlsCertificateRequest) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the MtlsCertificateRequest.
func (MtlsCertificateRequest) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("tenant_id", "request_id").Unique(),
		index.Fields("request_id"),
		index.Fields("tenant_id", "client_id"),
		index.Fields("client_id"),
		index.Fields("common_name"),
		index.Fields("status"),
		index.Fields("issuer_name"),
		index.Fields("expires_at"),
		index.Fields("certificate_serial"),
	}
}

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

// MtlsCertificate holds the schema definition for the MtlsCertificate entity.
// This represents an issued mTLS certificate used for authentication.
type MtlsCertificate struct {
	ent.Schema
}

// Annotations of the MtlsCertificate.
func (MtlsCertificate) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "mtls_certificates"},
		entsql.WithComments(true),
	}
}

// Fields of the MtlsCertificate.
func (MtlsCertificate) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("serial_number").
			Unique().
			Comment("Unique certificate serial number (bigint)"),

		field.String("client_id").
			Optional().
			Comment("Owner client ID"),

		field.String("common_name").
			Optional().
			Comment("Subject Common Name (CN)"),

		field.String("subject_dn").
			Optional().
			Comment("Full subject distinguished name"),

		field.String("issuer_dn").
			Optional().
			Comment("Issuer distinguished name"),

		field.String("issuer_name").
			Optional().
			Comment("Issuer name/identifier"),

		field.String("fingerprint_sha256").
			Optional().
			Unique().
			Comment("SHA-256 fingerprint"),

		field.String("fingerprint_sha1").
			Optional().
			Comment("SHA-1 fingerprint (for compatibility)"),

		field.String("public_key_algorithm").
			Optional().
			Comment("Public key algorithm (e.g., RSA, ECDSA)"),

		field.Int32("public_key_size").
			Optional().
			Nillable().
			Comment("Key size in bits"),

		field.String("signature_algorithm").
			Optional().
			Comment("Signature algorithm (e.g., SHA256WithRSA)"),

		field.Text("certificate_pem").
			Optional().
			Comment("PEM-encoded certificate"),

		field.Text("public_key_pem").
			Optional().
			Comment("PEM-encoded public key"),

		field.JSON("dns_names", []string{}).
			Optional().
			Comment("Subject Alternative Names - DNS"),

		field.JSON("ip_addresses", []string{}).
			Optional().
			Comment("Subject Alternative Names - IPs"),

		field.JSON("email_addresses", []string{}).
			Optional().
			Comment("Subject Alternative Names - Email"),

		field.JSON("uris", []string{}).
			Optional().
			Comment("Subject Alternative Names - URIs"),

		field.Enum("cert_type").
			Values("MTLS_CERT_TYPE_UNSPECIFIED", "MTLS_CERT_TYPE_CLIENT", "MTLS_CERT_TYPE_INTERNAL").
			Optional().
			Nillable().
			Default("MTLS_CERT_TYPE_CLIENT").
			Comment("Certificate type"),

		field.Enum("status").
			Values(
				"MTLS_CERTIFICATE_STATUS_UNSPECIFIED",
				"MTLS_CERTIFICATE_STATUS_ACTIVE",
				"MTLS_CERTIFICATE_STATUS_EXPIRED",
				"MTLS_CERTIFICATE_STATUS_REVOKED",
				"MTLS_CERTIFICATE_STATUS_SUSPENDED",
			).
			Optional().
			Nillable().
			Default("MTLS_CERTIFICATE_STATUS_ACTIVE").
			Comment("Certificate status"),

		field.Bool("is_ca").
			Default(false).
			Comment("Is this a CA certificate"),

		field.Int32("path_len_constraint").
			Optional().
			Nillable().
			Comment("CA path length constraint"),

		field.JSON("key_usage", []string{}).
			Optional().
			Comment("Key usage extensions"),

		field.JSON("ext_key_usage", []string{}).
			Optional().
			Comment("Extended key usage"),

		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("Custom metadata"),

		field.Text("notes").
			Optional().
			Comment("Admin notes"),

		field.Uint32("request_id").
			Optional().
			Nillable().
			Comment("Link to certificate request ID"),

		field.Enum("revocation_reason").
			Values(
				"MTLS_CERT_REVOCATION_REASON_UNSPECIFIED",
				"MTLS_CERT_REVOCATION_REASON_KEY_COMPROMISE",
				"MTLS_CERT_REVOCATION_REASON_CA_COMPROMISE",
				"MTLS_CERT_REVOCATION_REASON_AFFILIATION_CHANGED",
				"MTLS_CERT_REVOCATION_REASON_SUPERSEDED",
				"MTLS_CERT_REVOCATION_REASON_CESSATION_OF_OPERATION",
				"MTLS_CERT_REVOCATION_REASON_CERTIFICATE_HOLD",
				"MTLS_CERT_REVOCATION_REASON_PRIVILEGE_WITHDRAWN",
				"MTLS_CERT_REVOCATION_REASON_AA_COMPROMISE",
			).
			Optional().
			Nillable().
			Comment("Revocation reason (RFC 5280)"),

		field.Text("revocation_notes").
			Optional().
			Comment("Notes about the revocation"),

		field.Uint32("issued_by").
			Optional().
			Nillable().
			Comment("User ID who issued the certificate"),

		field.Uint32("revoked_by").
			Optional().
			Nillable().
			Comment("User ID who revoked the certificate"),

		field.Time("not_before").
			Optional().
			Nillable().
			Comment("Certificate validity start time"),

		field.Time("not_after").
			Optional().
			Nillable().
			Comment("Certificate validity end time"),

		field.Time("issued_at").
			Optional().
			Nillable().
			Comment("Certificate issuance timestamp"),

		field.Time("revoked_at").
			Optional().
			Nillable().
			Comment("Certificate revocation timestamp"),

		field.Time("last_seen_at").
			Optional().
			Nillable().
			Comment("Last time this certificate was used for authentication"),
	}
}

// Edges of the MtlsCertificate.
func (MtlsCertificate) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lcm_client", LcmClient.Type).
			Ref("mtls_certificates").
			Unique().
			Comment("The LCM client this certificate belongs to"),
	}
}

// Mixin of the MtlsCertificate.
func (MtlsCertificate) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the MtlsCertificate.
func (MtlsCertificate) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("tenant_id", "serial_number"),
		index.Fields("serial_number"),
		index.Fields("tenant_id", "client_id"),
		index.Fields("client_id"),
		index.Fields("common_name"),
		index.Fields("fingerprint_sha256"),
		index.Fields("fingerprint_sha1"),
		index.Fields("issuer_name"),
		index.Fields("status"),
		index.Fields("not_after"),
		index.Fields("last_seen_at"),
		index.Fields("request_id"),
	}
}

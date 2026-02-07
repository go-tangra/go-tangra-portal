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

// CertificateDetails holds the schema definition for the CertificateDetails entity.
// This stores parsed certificate information for performance optimization.
type CertificateDetails struct {
	ent.Schema
}

// Annotations of the CertificateDetails.
func (CertificateDetails) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "certificate_details"},
		entsql.WithComments(true),
	}
}

// Fields of the CertificateDetails.
func (CertificateDetails) Fields() []ent.Field {
	return []ent.Field{
		field.String("certificate_id").
			NotEmpty().
			Unique().
			Comment("ID of the associated certificate"),

		field.String("serial_number").
			Optional().
			Comment("Certificate serial number"),

		field.JSON("ip_addresses", []string{}).
			Optional().
			Comment("IP addresses from certificate SAN"),

		field.String("subject_common_name").
			Optional().
			Comment("Subject common name"),

		field.String("subject_organization").
			Optional().
			Comment("Subject organization"),

		field.String("subject_organizational_unit").
			Optional().
			Comment("Subject organizational unit"),

		field.String("subject_country").
			Optional().
			Comment("Subject country"),

		field.String("subject_state").
			Optional().
			Comment("Subject state/province"),

		field.String("subject_locality").
			Optional().
			Comment("Subject locality/city"),

		field.String("issuer_common_name").
			Optional().
			Comment("Issuer common name"),

		field.String("issuer_organization").
			Optional().
			Comment("Issuer organization"),

		field.String("issuer_country").
			Optional().
			Comment("Issuer country"),

		field.String("issuer_type").
			Optional().
			Default("unknown").
			Comment("Type of issuer: self-signed, acme, unknown"),

		field.String("signature_algorithm").
			Optional().
			Comment("Certificate signature algorithm"),

		field.String("public_key_algorithm").
			Optional().
			Comment("Public key algorithm"),

		field.Int("key_size").
			Optional().
			Comment("Key size in bits"),

		field.JSON("dns_names", []string{}).
			Optional().
			Comment("DNS names from certificate SAN"),

		field.JSON("email_addresses", []string{}).
			Optional().
			Comment("Email addresses from certificate SAN"),

		field.Time("not_before").
			Optional().
			Comment("Certificate valid from"),

		field.Time("not_after").
			Optional().
			Comment("Certificate valid until"),

		field.Bool("is_ca").
			Default(false).
			Comment("Whether certificate is a CA certificate"),

		field.String("key_usage").
			Optional().
			Comment("Key usage extensions"),

		field.JSON("extended_key_usage", []string{}).
			Optional().
			Comment("Extended key usage extensions"),
	}
}

// Edges of the CertificateDetails.
func (CertificateDetails) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("issued_certificate", IssuedCertificate.Type).
			Ref("certificate_details").
			Field("certificate_id").
			Required().
			Unique().
			Comment("Associated issued certificate"),
	}
}

// Mixin of the CertificateDetails.
func (CertificateDetails) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
	}
}

// Indexes of the CertificateDetails.
func (CertificateDetails) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("certificate_id").Unique(),
		index.Fields("serial_number"),
		index.Fields("issuer_type"),
		index.Fields("subject_common_name"),
	}
}

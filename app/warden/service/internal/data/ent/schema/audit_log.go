package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/tx7do/go-crud/entgo/mixin"
)

// AuditLog holds the schema definition for the AuditLog entity.
// This stores audit logs for Warden operations with cryptographic integrity.
type AuditLog struct {
	ent.Schema
}

// Annotations of the AuditLog.
func (AuditLog) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "warden_audit_logs"},
		entsql.WithComments(true),
	}
}

// Fields of the AuditLog.
func (AuditLog) Fields() []ent.Field {
	return []ent.Field{
		field.String("audit_id").
			NotEmpty().
			Unique().
			Comment("Unique audit log identifier (UUID)"),
		field.String("request_id").
			Optional().
			Comment("Request ID from metadata"),
		field.String("operation").
			NotEmpty().
			Comment("gRPC operation path"),
		field.String("service_name").
			Default("warden-service").
			Comment("Service name"),
		field.String("client_id").
			Optional().
			Comment("Client ID from certificate CN"),
		field.String("client_common_name").
			Optional().
			Comment("Client certificate common name"),
		field.String("client_organization").
			Optional().
			Comment("Client certificate organization"),
		field.String("client_serial_number").
			Optional().
			Comment("Client certificate serial number"),
		field.Bool("is_authenticated").
			Default(false).
			Comment("Whether the client was authenticated via mTLS"),
		field.Bool("success").
			Default(true).
			Comment("Whether the operation succeeded"),
		field.Int32("error_code").
			Optional().
			Nillable().
			Comment("Error code if failed"),
		field.String("error_message").
			Optional().
			Comment("Error message if failed"),
		field.Int64("latency_ms").
			Default(0).
			Comment("Operation latency in milliseconds"),
		field.String("peer_address").
			Optional().
			Comment("Client IP address"),
		field.JSON("geo_location", map[string]string{}).
			Optional().
			Comment("Geographic location info"),
		field.String("log_hash").
			Optional().
			Comment("SHA-256 hash of the log content"),
		field.Bytes("signature").
			Optional().
			Comment("ECDSA signature for integrity verification"),
		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("Additional metadata"),
	}
}

// Edges of the AuditLog.
func (AuditLog) Edges() []ent.Edge {
	return nil
}

// Mixin of the AuditLog.
func (AuditLog) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

// Indexes of the AuditLog.
func (AuditLog) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id").StorageKey("warden_auditlog_tenant_id"),
		index.Fields("tenant_id", "client_id").StorageKey("warden_auditlog_tenant_client"),
		index.Fields("tenant_id", "operation").StorageKey("warden_auditlog_tenant_operation"),
		index.Fields("tenant_id", "success").StorageKey("warden_auditlog_tenant_success"),
		index.Fields("operation").StorageKey("warden_auditlog_operation"),
		index.Fields("client_id").StorageKey("warden_auditlog_client_id"),
		index.Fields("success").StorageKey("warden_auditlog_success"),
		index.Fields("peer_address").StorageKey("warden_auditlog_peer_address"),
	}
}

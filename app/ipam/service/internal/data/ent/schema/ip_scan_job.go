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

// IpScanJob represents a network scan job for discovering IP addresses
type IpScanJob struct {
	ent.Schema
}

func (IpScanJob) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_ip_scan_jobs"},
		entsql.WithComments(true),
	}
}

func (IpScanJob) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Unique identifier"),

		field.String("subnet_id").
			NotEmpty().
			Comment("Subnet ID to scan"),

		field.Enum("status").
			Values("PENDING", "SCANNING", "COMPLETED", "FAILED", "CANCELLED").
			Default("PENDING").
			Comment("Job status"),

		field.Int32("progress").
			Default(0).
			Comment("Progress percentage (0-100)"),

		field.String("status_message").
			Optional().
			Comment("Status message or error description"),

		field.Int64("total_addresses").
			Default(0).
			Comment("Total number of addresses to scan"),

		field.Int64("scanned_count").
			Default(0).
			Comment("Number of addresses scanned so far"),

		field.Int64("alive_count").
			Default(0).
			Comment("Number of addresses that responded"),

		field.Int64("new_count").
			Default(0).
			Comment("Number of newly discovered addresses"),

		field.Int64("updated_count").
			Default(0).
			Comment("Number of existing addresses updated"),

		field.Enum("triggered_by").
			Values("AUTO", "MANUAL").
			Default("MANUAL").
			Comment("How the scan was triggered"),

		field.Int32("retry_count").
			Default(0).
			Comment("Number of retry attempts"),

		field.Int32("max_retries").
			Default(3).
			Comment("Maximum number of retry attempts"),

		field.Time("next_retry_at").
			Optional().
			Nillable().
			Comment("Next retry timestamp"),

		// Scan configuration
		field.Int32("timeout_ms").
			Default(1000).
			Comment("TCP probe timeout in milliseconds"),

		field.Int32("concurrency").
			Default(50).
			Comment("Number of parallel probes"),

		field.Bool("skip_reverse_dns").
			Default(false).
			Comment("Skip reverse DNS lookup"),

		field.String("tcp_probe_ports").
			Default("22,80,443,3389,445").
			Comment("Comma-separated list of TCP ports to probe"),

		// Timing
		field.Time("started_at").
			Optional().
			Nillable().
			Comment("When the scan started"),

		field.Time("completed_at").
			Optional().
			Nillable().
			Comment("When the scan completed"),
	}
}

func (IpScanJob) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("subnet", Subnet.Type).
			Ref("scan_jobs").
			Field("subnet_id").
			Unique().
			Required(),
	}
}

func (IpScanJob) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (IpScanJob) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "subnet_id"),
		index.Fields("tenant_id", "status"),
		index.Fields("tenant_id"),
		index.Fields("subnet_id"),
		index.Fields("status"),
		index.Fields("status", "next_retry_at"),
	}
}

// Ensure time is imported
func init() {
	_ = time.Now()
}

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

// Subnet represents a network subnet (CIDR block)
type Subnet struct {
	ent.Schema
}

func (Subnet) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_subnets"},
		entsql.WithComments(true),
	}
}

func (Subnet) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Unique identifier"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Human-readable name"),

		field.String("cidr").
			NotEmpty().
			Comment("CIDR notation (e.g., 192.168.1.0/24)"),

		field.String("description").
			Optional().
			Comment("Optional description"),

		field.String("gateway").
			Optional().
			Comment("Gateway IP address"),

		field.String("dns_servers").
			Optional().
			Comment("DNS servers (comma-separated)"),

		field.String("vlan_id").
			Optional().
			Comment("Associated VLAN ID"),

		field.String("parent_id").
			Optional().
			Comment("Parent subnet ID (for hierarchical subnets)"),

		field.String("location_id").
			Optional().
			Comment("Location/site ID"),

		field.Int32("status").
			Default(1).
			Comment("Subnet status: 1=Active, 2=Reserved, 3=Deprecated, 4=Deleted"),

		field.Int32("ip_version").
			Default(4).
			Comment("IP version (4 or 6)"),

		field.String("network_address").
			Optional().
			Comment("Network address"),

		field.String("broadcast_address").
			Optional().
			Comment("Broadcast address"),

		field.String("mask").
			Optional().
			Comment("Subnet mask"),

		field.Int32("prefix_length").
			Optional().
			Comment("Prefix length"),

		field.Int64("total_addresses").
			Default(0).
			Comment("Total number of addresses"),

		field.Text("tags").
			Optional().
			Comment("Custom tags (JSON)"),

		field.Text("metadata").
			Optional().
			Comment("Custom metadata (JSON)"),
	}
}

func (Subnet) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("addresses", IpAddress.Type),
		edge.To("children", Subnet.Type).
			From("parent").
			Field("parent_id").
			Unique(),
		edge.To("vlan", Vlan.Type).
			Field("vlan_id").
			Unique(),
		edge.To("location", Location.Type).
			Field("location_id").
			Unique(),
		edge.To("scan_jobs", IpScanJob.Type),
	}
}

func (Subnet) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (Subnet) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "name").Unique(),
		index.Fields("tenant_id", "cidr"),
		index.Fields("tenant_id"),
		index.Fields("vlan_id"),
		index.Fields("parent_id"),
		index.Fields("location_id"),
		index.Fields("status"),
	}
}

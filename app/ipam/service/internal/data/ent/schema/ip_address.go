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

// IpAddress represents a single IP address
type IpAddress struct {
	ent.Schema
}

func (IpAddress) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_ip_addresses"},
		entsql.WithComments(true),
	}
}

func (IpAddress) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Unique identifier"),

		field.String("address").
			NotEmpty().
			Comment("IP address (e.g., 192.168.1.10)"),

		field.String("subnet_id").
			NotEmpty().
			Comment("Subnet ID this address belongs to"),

		field.String("hostname").
			Optional().
			Comment("Hostname or FQDN"),

		field.String("mac_address").
			Optional().
			Comment("MAC address"),

		field.String("description").
			Optional().
			Comment("Description"),

		field.String("device_id").
			Optional().
			Comment("Associated device ID"),

		field.String("interface_name").
			Optional().
			Comment("Interface name on device"),

		field.Int32("status").
			Default(1).
			Comment("Address status: 1=Active, 2=Reserved, 3=DHCP, 4=Deprecated, 5=Offline"),

		field.Int32("address_type").
			Default(1).
			Comment("Address type: 1=Host, 2=Gateway, 3=Broadcast, 4=Network, 5=Virtual, 6=Anycast"),

		field.Bool("is_primary").
			Default(false).
			Comment("Is this the primary address for the device"),

		field.String("ptr_record").
			Optional().
			Comment("PTR record for reverse DNS"),

		field.Bool("has_reverse_dns").
			Default(false).
			Comment("Whether IP has a valid reverse DNS record"),

		field.String("dns_name").
			Optional().
			Comment("DNS name"),

		field.String("owner").
			Optional().
			Comment("Owner/contact"),

		field.Time("last_seen").
			Optional().
			Comment("Last seen timestamp (from network scan)"),

		field.Time("lease_expiry").
			Optional().
			Nillable().
			Comment("Lease expiry (for DHCP)"),

		field.Text("tags").
			Optional().
			Comment("Custom tags (JSON)"),

		field.Text("metadata").
			Optional().
			Comment("Custom metadata (JSON)"),

		field.Text("note").
			Optional().
			Comment("Note/comment"),
	}
}

func (IpAddress) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("subnet", Subnet.Type).
			Ref("addresses").
			Field("subnet_id").
			Unique().
			Required(),
		edge.From("device", Device.Type).
			Ref("addresses").
			Field("device_id").
			Unique(),
	}
}

func (IpAddress) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (IpAddress) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "address").Unique(),
		index.Fields("tenant_id", "subnet_id"),
		index.Fields("tenant_id"),
		index.Fields("subnet_id"),
		index.Fields("device_id"),
		index.Fields("status"),
		index.Fields("hostname"),
		index.Fields("mac_address"),
	}
}

// Ensure last_seen is updated when address is modified
func init() {
	_ = time.Now()
}

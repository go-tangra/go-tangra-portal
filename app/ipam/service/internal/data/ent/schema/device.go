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

// Device represents a network device
type Device struct {
	ent.Schema
}

func (Device) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_devices"},
		entsql.WithComments(true),
	}
}

func (Device) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Unique identifier"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Device name/hostname"),

		field.Int32("device_type").
			Default(0).
			Comment("Device type: 1=Server, 2=VM, 3=Router, 4=Switch, 5=Firewall, etc."),

		field.String("description").
			Optional().
			Comment("Description"),

		field.String("manufacturer").
			Optional().
			Comment("Manufacturer/vendor"),

		field.String("model").
			Optional().
			Comment("Model number"),

		field.String("serial_number").
			Optional().
			Comment("Serial number"),

		field.String("asset_tag").
			Optional().
			Comment("Asset tag"),

		field.String("location_id").
			Optional().
			Comment("Location/site ID"),

		field.String("rack_id").
			Optional().
			Comment("Rack ID"),

		field.Int32("rack_position").
			Optional().
			Nillable().
			Comment("Rack position (U)"),

		field.Int32("device_height_u").
			Optional().
			Nillable().
			Default(1).
			Comment("Device height in rack units"),

		field.Int32("status").
			Default(1).
			Comment("Device status: 1=Active, 2=Planned, 3=Staged, 4=Decommissioned, 5=Offline, 6=Failed"),

		field.String("primary_ip").
			Optional().
			Comment("Primary IP address"),

		field.String("primary_ipv6").
			Optional().
			Comment("Primary IPv6 address"),

		field.String("management_ip").
			Optional().
			Comment("Management IP (if different)"),

		field.String("os_type").
			Optional().
			Comment("Operating system"),

		field.String("os_version").
			Optional().
			Comment("OS version"),

		field.String("firmware_version").
			Optional().
			Comment("Firmware version"),

		field.String("contact").
			Optional().
			Comment("Contact person"),

		field.Text("tags").
			Optional().
			Comment("Custom tags (JSON)"),

		field.Text("metadata").
			Optional().
			Comment("Custom metadata (JSON)"),

		field.Text("notes").
			Optional().
			Comment("Notes"),

		field.Time("last_seen").
			Optional().
			Nillable().
			Comment("Last discovered/seen"),
	}
}

func (Device) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("addresses", IpAddress.Type),
		edge.To("interfaces", DeviceInterface.Type),
		edge.To("location", Location.Type).
			Field("location_id").
			Unique(),
	}
}

func (Device) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (Device) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "name").Unique(),
		index.Fields("tenant_id"),
		index.Fields("location_id"),
		index.Fields("status"),
		index.Fields("device_type"),
		index.Fields("serial_number"),
	}
}

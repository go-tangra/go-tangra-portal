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

// DeviceInterface represents a network interface on a device
type DeviceInterface struct {
	ent.Schema
}

func (DeviceInterface) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_device_interfaces"},
		entsql.WithComments(true),
	}
}

func (DeviceInterface) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Unique identifier"),

		field.String("device_id").
			NotEmpty().
			Comment("Device ID"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Interface name (e.g., eth0, ens192)"),

		field.String("mac_address").
			Optional().
			Comment("MAC address"),

		field.String("interface_type").
			Optional().
			Comment("Interface type (e.g., ethernet, wifi, virtual)"),

		field.Bool("enabled").
			Default(true).
			Comment("Is interface enabled"),

		field.Int32("speed_mbps").
			Optional().
			Nillable().
			Comment("Speed in Mbps"),

		field.String("description").
			Optional().
			Comment("Description"),
	}
}

func (DeviceInterface) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("device", Device.Type).
			Ref("interfaces").
			Field("device_id").
			Unique().
			Required(),
	}
}

func (DeviceInterface) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}

func (DeviceInterface) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("device_id", "name").Unique(),
		index.Fields("device_id"),
		index.Fields("mac_address"),
	}
}

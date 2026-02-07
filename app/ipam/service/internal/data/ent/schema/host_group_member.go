package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// HostGroupMember represents a device member of a host group
type HostGroupMember struct {
	ent.Schema
}

func (HostGroupMember) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_host_group_members"},
		entsql.WithComments(true),
	}
}

func (HostGroupMember) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Unique identifier"),

		field.String("host_group_id").
			NotEmpty().
			Comment("Host Group ID"),

		field.String("device_id").
			NotEmpty().
			Comment("Device ID"),

		field.Int32("sequence").
			Default(0).
			Comment("Order/sequence in the group"),

		field.Time("create_time").
			Optional().
			Nillable().
			Comment("Creation timestamp"),

		field.Time("update_time").
			Optional().
			Nillable().
			Comment("Last update timestamp"),
	}
}

func (HostGroupMember) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("group", HostGroup.Type).
			Ref("members").
			Field("host_group_id").
			Unique().
			Required(),
		edge.To("device", Device.Type).
			Field("device_id").
			Unique().
			Required(),
	}
}

func (HostGroupMember) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("host_group_id", "device_id").Unique(),
		index.Fields("host_group_id"),
		index.Fields("device_id"),
	}
}

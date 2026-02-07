package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// IpGroupMember represents a member of an IP group
type IpGroupMember struct {
	ent.Schema
}

func (IpGroupMember) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_ip_group_members"},
		entsql.WithComments(true),
	}
}

func (IpGroupMember) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Unique identifier"),

		field.String("ip_group_id").
			NotEmpty().
			Comment("IP Group ID"),

		field.Int32("member_type").
			Default(1).
			Comment("Member type: 1=Address, 2=Range, 3=Subnet"),

		field.String("value").
			NotEmpty().
			Comment("Value based on type: IP address, range, or CIDR"),

		field.String("description").
			Optional().
			Comment("Optional description/label"),

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

func (IpGroupMember) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("group", IpGroup.Type).
			Ref("members").
			Field("ip_group_id").
			Unique().
			Required(),
	}
}

func (IpGroupMember) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("ip_group_id", "value").Unique(),
		index.Fields("ip_group_id"),
		index.Fields("member_type"),
	}
}

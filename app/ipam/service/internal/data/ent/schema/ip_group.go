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

// IpGroup represents a logical grouping of IP addresses, ranges, or subnets
type IpGroup struct {
	ent.Schema
}

func (IpGroup) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_ip_groups"},
		entsql.WithComments(true),
	}
}

func (IpGroup) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Unique identifier"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Human-readable name"),

		field.String("description").
			Optional().
			Comment("Optional description"),

		field.Int32("status").
			Default(1).
			Comment("Group status: 1=Active, 2=Inactive"),

		field.Text("tags").
			Optional().
			Comment("Custom tags (JSON)"),

		field.Text("metadata").
			Optional().
			Comment("Custom metadata (JSON)"),
	}
}

func (IpGroup) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("members", IpGroupMember.Type),
	}
}

func (IpGroup) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (IpGroup) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "name").Unique(),
		index.Fields("tenant_id"),
		index.Fields("status"),
	}
}

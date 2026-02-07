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

// HostGroup represents a logical grouping of devices by function or purpose
type HostGroup struct {
	ent.Schema
}

func (HostGroup) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_host_groups"},
		entsql.WithComments(true),
	}
}

func (HostGroup) Fields() []ent.Field {
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

func (HostGroup) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("members", HostGroupMember.Type),
	}
}

func (HostGroup) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (HostGroup) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "name").Unique(),
		index.Fields("tenant_id"),
		index.Fields("status"),
	}
}

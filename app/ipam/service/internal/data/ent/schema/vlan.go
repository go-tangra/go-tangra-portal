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

// Vlan represents a Virtual LAN
type Vlan struct {
	ent.Schema
}

func (Vlan) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_vlans"},
		entsql.WithComments(true),
	}
}

func (Vlan) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Unique identifier"),

		field.Int32("vlan_id").
			Comment("VLAN ID (1-4094)"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Human-readable name"),

		field.String("description").
			Optional().
			Comment("Description"),

		field.String("domain").
			Optional().
			Comment("Domain/VTP domain"),

		field.String("location_id").
			Optional().
			Comment("Location/site ID"),

		field.Int32("status").
			Default(1).
			Comment("VLAN status: 1=Active, 2=Reserved, 3=Deprecated"),

		field.Text("tags").
			Optional().
			Comment("Custom tags (JSON)"),

		field.Text("metadata").
			Optional().
			Comment("Custom metadata (JSON)"),
	}
}

func (Vlan) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("subnets", Subnet.Type).
			Ref("vlan"),
		edge.To("location", Location.Type).
			Field("location_id").
			Unique(),
	}
}

func (Vlan) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (Vlan) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "vlan_id").Unique(),
		index.Fields("tenant_id", "name").Unique(),
		index.Fields("tenant_id"),
		index.Fields("location_id"),
		index.Fields("status"),
	}
}

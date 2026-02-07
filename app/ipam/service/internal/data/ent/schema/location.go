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

// Location represents a physical site/datacenter/building
type Location struct {
	ent.Schema
}

func (Location) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_locations"},
		entsql.WithComments(true),
	}
}

func (Location) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Unique identifier"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Location name"),

		field.String("code").
			Optional().
			MaxLen(50).
			Comment("Location code (short identifier)"),

		field.Int32("location_type").
			Default(0).
			Comment("Location type: 1=Region, 2=Country, 3=City, 4=Datacenter, 5=Building, etc."),

		field.String("description").
			Optional().
			Comment("Description"),

		field.String("parent_id").
			Optional().
			Comment("Parent location ID (for hierarchy)"),

		field.String("path").
			Optional().
			Comment("Full path (e.g., Region/Country/City/DC)"),

		field.String("address").
			Optional().
			Comment("Physical address"),

		field.String("city").
			Optional().
			Comment("City"),

		field.String("state").
			Optional().
			Comment("State/Province"),

		field.String("country").
			Optional().
			Comment("Country"),

		field.String("postal_code").
			Optional().
			Comment("Postal code"),

		field.Float("latitude").
			Optional().
			Nillable().
			Comment("Latitude"),

		field.Float("longitude").
			Optional().
			Nillable().
			Comment("Longitude"),

		field.String("contact").
			Optional().
			Comment("Contact person"),

		field.String("phone").
			Optional().
			Comment("Contact phone"),

		field.String("email").
			Optional().
			Comment("Contact email"),

		field.Int32("status").
			Default(1).
			Comment("Location status: 1=Active, 2=Planned, 3=Decommissioned"),

		field.Text("tags").
			Optional().
			Comment("Custom tags (JSON)"),

		field.Text("metadata").
			Optional().
			Comment("Custom metadata (JSON)"),

		field.Int32("rack_size_u").
			Optional().
			Nillable().
			Comment("Rack size in U units (only for rack type locations)"),
	}
}

func (Location) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("children", Location.Type).
			From("parent").
			Field("parent_id").
			Unique(),
		edge.From("subnets", Subnet.Type).
			Ref("location"),
		edge.From("vlans", Vlan.Type).
			Ref("location"),
		edge.From("devices", Device.Type).
			Ref("location"),
	}
}

func (Location) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (Location) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "name").Unique(),
		index.Fields("tenant_id", "code").Unique(),
		index.Fields("tenant_id"),
		index.Fields("parent_id"),
		index.Fields("status"),
		index.Fields("location_type"),
		index.Fields("country"),
	}
}

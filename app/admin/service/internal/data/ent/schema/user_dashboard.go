package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"github.com/tx7do/go-crud/entgo/mixin"
)

// DashboardWidgetConfig represents a widget placed on a user's dashboard.
type DashboardWidgetConfig struct {
	WidgetID string         `json:"widget_id"`
	GridX    int32          `json:"grid_x"`
	GridY    int32          `json:"grid_y"`
	GridW    int32          `json:"grid_w"`
	GridH    int32          `json:"grid_h"`
	Config   map[string]any `json:"config,omitempty"`
}

// UserDashboard holds the schema definition for the UserDashboard entity.
type UserDashboard struct {
	ent.Schema
}

func (UserDashboard) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{
			Table:     "sys_user_dashboards",
			Charset:   "utf8mb4",
			Collation: "utf8mb4_bin",
		},
		entsql.WithComments(true),
		schema.Comment("User dashboard layout configuration"),
	}
}

// Fields of the UserDashboard.
func (UserDashboard) Fields() []ent.Field {
	return []ent.Field{
		field.Uint32("user_id").
			Comment("User who owns this dashboard"),

		field.Uint32("tenant_id").
			Comment("Tenant scope"),

		field.String("name").
			Comment("Dashboard name").
			Default("My Dashboard"),

		field.JSON("widgets", []DashboardWidgetConfig{}).
			Comment("Dashboard widget layout configuration").
			SchemaType(map[string]string{
				dialect.MySQL:    "json",
				dialect.Postgres: "jsonb",
			}).
			Optional(),

		field.Bool("is_default").
			Comment("Whether this is the user's default dashboard").
			Default(true),
	}
}

// Mixin of the UserDashboard.
func (UserDashboard) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.TimeAt{},
	}
}

// Indexes of the UserDashboard.
func (UserDashboard) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "tenant_id").
			StorageKey("idx_sys_user_dashboards_user_tenant"),

		index.Fields("user_id", "tenant_id", "is_default").
			StorageKey("idx_sys_user_dashboards_user_tenant_default"),
	}
}

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/tx7do/go-crud/entgo/mixin"
)

// Module holds the schema definition for the dynamically registered Module entity.
type Module struct {
	ent.Schema
}

func (Module) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{
			Table:     "sys_modules",
			Charset:   "utf8mb4",
			Collation: "utf8mb4_bin",
		},
		entsql.WithComments(true),
		schema.Comment("Dynamic module registration table"),
	}
}

// Fields of the Module.
func (Module) Fields() []ent.Field {
	return []ent.Field{
		field.String("module_id").
			Comment("Unique module identifier (e.g., 'echo', 'lcm', 'ipam')").
			NotEmpty().
			Unique(),

		field.String("module_name").
			Comment("Display name of the module").
			NotEmpty(),

		field.String("version").
			Comment("Module version (semver)").
			Default("1.0.0"),

		field.String("description").
			Comment("Module description").
			Optional().
			Nillable(),

		field.String("grpc_endpoint").
			Comment("gRPC endpoint address (e.g., 'echo-service:9500')").
			NotEmpty(),

		field.Int32("status").
			Comment("Module status: 1=active, 2=inactive, 3=error").
			Default(1),

		field.Int32("health").
			Comment("Module health: 1=healthy, 2=degraded, 3=unhealthy").
			Default(1),

		field.Bytes("openapi_spec").
			Comment("OpenAPI 3.0 spec with x-menu extensions").
			Optional().
			Nillable(),

		field.Bytes("proto_descriptor").
			Comment("Compiled FileDescriptorSet for gRPC transcoding").
			Optional().
			Nillable(),

		field.Bytes("menus_yaml").
			Comment("Raw menus.yaml bytes for menu recovery on restart").
			Optional().
			Nillable(),

		field.String("registration_id").
			Comment("UUID for this registration instance").
			Optional().
			Nillable(),

		field.Time("registered_at").
			Comment("When the module was registered").
			Optional().
			Nillable(),

		field.Time("last_heartbeat").
			Comment("Last heartbeat received from module").
			Optional().
			Nillable(),

		field.Int32("menu_count").
			Comment("Number of menus registered by this module").
			Default(0),

		field.Int32("api_count").
			Comment("Number of API resources registered by this module").
			Default(0),

		field.Int32("route_count").
			Comment("Number of HTTP routes registered by this module").
			Default(0),
	}
}

func (Module) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.TimeAt{},
		mixin.OperatorID{},
	}
}

// Indexes of the Module.
func (Module) Indexes() []ent.Index {
	return []ent.Index{
		// Status index for filtering active/inactive modules
		index.Fields("status").
			StorageKey("idx_sys_modules_status"),

		// Health index for monitoring queries
		index.Fields("health").
			StorageKey("idx_sys_modules_health"),

		// Combined status and health for dashboard queries
		index.Fields("status", "health").
			StorageKey("idx_sys_modules_status_health"),

		// Last heartbeat for health monitoring cleanup
		index.Fields("last_heartbeat").
			StorageKey("idx_sys_modules_last_heartbeat"),

		// Created at for listing
		index.Fields("created_at").
			StorageKey("idx_sys_modules_created_at"),
	}
}

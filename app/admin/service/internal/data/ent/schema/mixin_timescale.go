package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

// NotNullCreatedAt is a mixin that provides a NOT NULL created_at field.
// Use this instead of mixin.CreatedAt{} for tables that will be converted
// to TimescaleDB hypertables, because hypertable partition columns must be NOT NULL.
type NotNullCreatedAt struct{ mixin.Schema }

func (NotNullCreatedAt) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Comment("创建时间").
			Immutable().
			Default(time.Now),
	}
}

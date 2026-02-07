package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"github.com/tx7do/go-crud/entgo/mixin"
)

// DnsConfig holds DNS server configuration for reverse DNS lookups
type DnsConfig struct {
	ent.Schema
}

func (DnsConfig) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ipam_dns_configs"},
		entsql.WithComments(true),
	}
}

func (DnsConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Unique identifier"),

		field.JSON("dns_servers", []string{}).
			Optional().
			Comment("List of DNS server addresses"),

		field.Int32("timeout_ms").
			Default(5000).
			Comment("Timeout for DNS queries in milliseconds"),

		field.Bool("use_system_dns_fallback").
			Default(true).
			Comment("Whether to use system DNS as fallback"),

		field.Bool("reverse_dns_enabled").
			Default(true).
			Comment("Whether reverse DNS lookup is enabled"),
	}
}

func (DnsConfig) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.UpdateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (DnsConfig) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id").Unique(),
	}
}

package store

import (
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
)

// List definitions of the gateway operations tables
// (specs/032-server-side-tables in go-tangra). Sort fields map to constant
// expressions only.
var (
	// AuditList pages gateway_audit_events in SQL.
	AuditList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"ts":         {Expr: "ts", DefaultDir: listquery.Desc},
			"module":     {Expr: "module", Text: true},
			"event_type": {Expr: "event_type", Text: true},
		},
		Default: "ts", TieBreak: "id", DefaultSize: 50,
	}
	// AllowListList pages the (small) allow-list in memory.
	AllowListList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"spiffe_id":  {Expr: "spiffe_id", Text: true},
			"created_at": {Expr: "created_at", DefaultDir: listquery.Desc},
			"revoked_at": {Expr: "revoked_at", DefaultDir: listquery.Desc},
		},
		Default: "spiffe_id", TieBreak: "id",
	}
	// RegistrationList pages the in-memory registry.
	RegistrationList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"module":       {Expr: "module", Text: true},
			"state":        {Expr: "state", Text: true},
			"instances":    {Expr: "instances", DefaultDir: listquery.Desc},
			"last_renewal": {Expr: "last_renewal", DefaultDir: listquery.Desc},
		},
		Default: "module", TieBreak: "module",
	}
)

// AuditQuery filters an audit page.
type AuditQuery struct {
	Module, EventType string
	From, To          time.Time
}

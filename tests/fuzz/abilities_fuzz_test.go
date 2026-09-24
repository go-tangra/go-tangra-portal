package fuzz

import (
	"encoding/json"
	"testing"

	"github.com/go-tangra/go-tangra-portal/v4/internal/authz"
	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
)

func FuzzAbilityPack(f *testing.F) {
	f.Add("read,update", "Order,Line", `{"ownerId":{"$eq":"me"}}`, "a,b", "why", true)
	f.Add("read", "Order", ``, "", "", false)
	f.Fuzz(func(t *testing.T, actions, subjects, conditions, fields, reason string, inverted bool) {
		a := manifest.Ability{Action: splitNonEmpty(actions), Subject: splitNonEmpty(subjects), Fields: splitNonEmpty(fields), Reason: reason, Inverted: inverted, Requires: "x:y"}
		if len(a.Action) == 0 || len(a.Subject) == 0 || hasComma(a.Action) || hasComma(a.Subject) || hasComma(a.Fields) {
			return
		}
		if conditions != "" {
			var c map[string]any
			if json.Unmarshal([]byte(conditions), &c) != nil || manifest.ValidateConditions(c) != nil {
				return
			}
			a.Conditions = c
		}
		p := authz.Pack(a)
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("pack not serialisable: %v", err)
		}
		var back authz.PackedRule
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		u, err := authz.Unpack(back)
		if err != nil {
			t.Fatalf("unpack: %v (%s)", err, raw)
		}
		if len(u.Action) != len(a.Action) || len(u.Subject) != len(a.Subject) || u.Inverted != a.Inverted || u.Reason != a.Reason || len(u.Fields) != len(a.Fields) || u.Requires != "" {
			t.Fatalf("round trip: %+v → %s → %+v", a, raw, u)
		}
	})
}

func splitNonEmpty(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func hasComma(list []string) bool {
	for _, s := range list {
		for i := 0; i < len(s); i++ {
			if s[i] == ',' {
				return true
			}
		}
	}
	return false
}

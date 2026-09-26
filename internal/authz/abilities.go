package authz

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
)

// PackedRule is a CASL packed rule: [actions, subjects, conditions|0,
// inverted 1|0, fields|0, reason] with trailing falsy entries trimmed
// (@casl/ability/extra packRules).
type PackedRule []any

// Pack renders a manifest ability as a packed rule (requires is stripped).
func Pack(a manifest.Ability) PackedRule {
	r := PackedRule{strings.Join(a.Action, ","), strings.Join(a.Subject, ",")}
	if len(a.Conditions) > 0 {
		r = append(r, a.Conditions)
	} else {
		r = append(r, 0)
	}
	if a.Inverted {
		r = append(r, 1)
	} else {
		r = append(r, 0)
	}
	if len(a.Fields) > 0 {
		r = append(r, strings.Join(a.Fields, ","))
	} else {
		r = append(r, 0)
	}
	r = append(r, a.Reason)
	for len(r) > 2 && falsy(r[len(r)-1]) {
		r = r[:len(r)-1]
	}
	return r
}

// falsy mirrors JavaScript truthiness for the values Pack emits.
func falsy(v any) bool {
	switch x := v.(type) {
	case int:
		return x == 0
	case string:
		return x == ""
	}
	return false
}

// Unpack is the inverse of Pack (tests, contract checks).
func Unpack(r PackedRule) (manifest.Ability, error) {
	if len(r) < 2 {
		return manifest.Ability{}, fmt.Errorf("authz: packed rule needs actions and subjects")
	}
	actions, ok1 := r[0].(string)
	subjects, ok2 := r[1].(string)
	if !ok1 || !ok2 {
		return manifest.Ability{}, fmt.Errorf("authz: packed rule actions/subjects must be strings")
	}
	a := manifest.Ability{Action: strings.Split(actions, ","), Subject: strings.Split(subjects, ",")}
	if len(r) > 2 {
		if c, ok := r[2].(map[string]any); ok {
			a.Conditions = c
		}
	}
	if len(r) > 3 {
		switch v := r[3].(type) {
		case int:
			a.Inverted = v == 1
		case float64:
			a.Inverted = v == 1
		}
	}
	if len(r) > 4 {
		if f, ok := r[4].(string); ok && f != "" {
			a.Fields = strings.Split(f, ",")
		}
	}
	if len(r) > 5 {
		if s, ok := r[5].(string); ok {
			a.Reason = s
		}
	}
	return a, nil
}

// AbilitiesDoc is the GET /gateway/v1/me/abilities body.
type AbilitiesDoc struct {
	Tenant  string                  `json:"tenant"`
	User    string                  `json:"user"`
	Roles   []string                `json:"roles"`
	Version string                  `json:"version"`
	Modules map[string][]PackedRule `json:"modules"`
}

// Held decides a set of module permissions and returns the ones the user holds.
func (d *Decider) Held(ctx context.Context, tenant, user string, refs []Ref) (map[Ref]bool, error) {
	uniq := map[Ref]bool{}
	var list []Ref
	for _, r := range refs {
		if !uniq[r] {
			uniq[r] = true
			list = append(list, r)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].String() < list[j].String() })
	held := map[Ref]bool{}
	if len(list) == 0 {
		return held, nil
	}
	ds, err := d.Check(ctx, tenant, user, list)
	if err != nil {
		return nil, err
	}
	for i, r := range list {
		if ds[i].Allowed {
			held[r] = true
		}
	}
	return held, nil
}

// Abilities evaluates every module's rules for the caller: rules are kept
// only when the caller holds their `requires` permission of that module (a
// manifest's requires is bare and qualified with the registration's module);
// the version changes with the registry and with the tenant policy.
func (d *Decider) Abilities(ctx context.Context, regs []registry.Registration, tenant, user string, roles []string, registryVersion uint64) (AbilitiesDoc, error) {
	var refs []Ref
	for _, reg := range regs {
		for _, a := range reg.Manifest.Abilities {
			refs = append(refs, Ref{Module: reg.Module, Perm: a.Requires})
		}
	}
	held, err := d.Held(ctx, tenant, user, refs)
	if err != nil {
		return AbilitiesDoc{}, err
	}
	doc := AbilitiesDoc{Tenant: tenant, User: user, Roles: roles, Modules: map[string][]PackedRule{}}
	if doc.Roles == nil {
		doc.Roles = []string{}
	}
	for _, reg := range regs {
		var rules []PackedRule
		for _, a := range reg.Manifest.Abilities {
			if held[Ref{Module: reg.Module, Perm: a.Requires}] {
				rules = append(rules, Pack(a))
			}
		}
		if len(rules) > 0 {
			doc.Modules[reg.Module] = rules
		}
	}
	doc.Version = fmt.Sprintf("%d.%s", registryVersion, d.TenantVersion(tenant))
	return doc, nil
}

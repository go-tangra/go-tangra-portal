package manifest

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
)

// FromProto converts the wire manifest and validates it exactly like Parse.
func FromProto(p *gatewayv1.Manifest) (Manifest, error) {
	if p == nil {
		return Manifest{}, fmt.Errorf("%w: manifest required", ErrInvalid)
	}
	m := fromProtoNoValidate(p)
	// Round-trip through JSON so the wire form is held to the published
	// schema (structpb values are always marshalable).
	raw, _ := json.Marshal(m)
	return Parse(raw)
}

func fromProtoNoValidate(p *gatewayv1.Manifest) Manifest {
	m := Manifest{Module: p.GetModule(), DisplayName: p.GetDisplayName(), Version: p.GetVersion(), Prefixes: p.GetPrefixes(),
		Routes: []Route{}, Methods: []Method{}, Permissions: []Permission{}, Abilities: []Ability{}, Nav: []NavEntry{}}
	for _, r := range p.GetRoutes() {
		m.Routes = append(m.Routes, Route{Method: r.GetMethod(), Path: r.GetPath(), Permission: r.GetPermission(), Public: r.GetPublic(), MaxBodyBytes: int64(r.GetMaxBodyBytes()), Timeout: dur(r.GetTimeout().AsDuration()), ClientAddress: r.GetClientAddress()}) // #nosec G115 -- bounded by schema maximum
	}
	for _, mt := range p.GetMethods() {
		m.Methods = append(m.Methods, Method{FullMethod: mt.GetFullMethod(), Permission: mt.GetPermission(), Public: mt.GetPublic(), Streaming: mt.GetStreaming(), MaxStreamDuration: dur(mt.GetMaxStreamDuration().AsDuration())})
	}
	for _, pm := range p.GetPermissions() {
		m.Permissions = append(m.Permissions, Permission{Resource: pm.GetResource(), Action: pm.GetAction(), Description: pm.GetDescription()})
	}
	for _, a := range p.GetAbilities() {
		ab := Ability{Action: a.GetAction(), Subject: a.GetSubject(), Fields: a.GetFields(), Inverted: a.GetInverted(), Reason: a.GetReason(), Requires: a.GetRequires()}
		if a.GetConditions() != nil {
			ab.Conditions = a.GetConditions().AsMap()
		}
		m.Abilities = append(m.Abilities, ab)
	}
	if p.GetRemote() != nil {
		m.Remote = Remote{Entry: p.GetRemote().GetEntry(), Exposes: p.GetRemote().GetExposes(), Integrity: p.GetRemote().GetIntegrity()}
	}
	for _, n := range p.GetNav() {
		m.Nav = append(m.Nav, NavEntry{Title: n.GetTitle(), Path: n.GetPath(), Icon: n.GetIcon(), Order: int(n.GetOrder()), Requires: n.GetRequires()})
	}
	if m.Prefixes == nil {
		m.Prefixes = []string{}
	}
	for i, pf := range m.Prefixes {
		if n, ok := NormalizePrefix(pf); ok {
			m.Prefixes[i] = n
		}
	}
	if m.Remote.Exposes == nil {
		m.Remote.Exposes = []string{}
	}
	return m
}

// dur renders a duration in the schema grammar (^[0-9]+(ms|s|m)$).
func dur(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	case d%time.Second == 0:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	default:
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	}
}

package catalogue

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	fwcat "github.com/go-tangra/go-tangra/v4/catalogue"
)

var core = map[string]string{
	"TRUST_DOMAIN": "infra.example.org", "GATEWAY_ISSUER": "https://portal.example.org:8443",
	"LCM_ENROLL_URL": "https://portal.example.org:8443/api/lcm/v1/enroll", "AUTH_GRPC": "portal.example.org:9543",
	"GATEWAY_GRPC": "portal.example.org:9643", "LCM_GRPC": "portal.example.org:9945", "MESH_TENANT_ID": "00000000-0000-0000-0000-000000000001",
}

func joinEntry(t *testing.T, templates map[string]string, tlsHosts ...string) (fwcat.Entry, []byte) {
	t.Helper()
	fsys := fstest.MapFS{"compose.yaml": {Data: []byte("services: { db: { command: [\"sh\", \"-c\", \"exec \\\"$$@\\\"\"] } }\nimage: ${MODULE_IMAGE}:${MODULE_VERSION}\n"), Mode: 0o644},
		"README.md": {Data: []byte("# readme\n"), Mode: 0o644}}
	var names []string
	for name, body := range templates {
		fsys[name] = &fstest.MapFile{Data: []byte(body), Mode: 0o644}
		names = append(names, name)
	}
	bundle, err := fwcat.PackBundle(fsys)
	if err != nil {
		t.Fatal(err)
	}
	d := descriptor("sms-gw")
	d.Bundle.Templates = names
	d.Bundle.TLSHosts = tlsHosts
	d.HostInputs = []fwcat.HostInput{
		{Key: "MODULE_ADVERTISE_HOST", Label: "host", Pattern: `^[a-z0-9.-]+$`},
		{Key: "SMS_PUBLIC_PORT", Label: "port", Pattern: `^[0-9]+$`, Default: "9901"},
		{Key: "FREE_TEXT", Label: "anything", Pattern: `^.*$`, Default: "x"},
	}
	e, err := fwcat.BuildEntry(d, "4.3.0", "go-tangra/go-tangra-sms-gw", nil, bundle)
	if err != nil {
		t.Fatal(err)
	}
	return e, bundle
}

func TestCheckInputs(t *testing.T) {
	e, _ := joinEntry(t, map[string]string{"config.yaml": "x\n"})
	got, err := CheckInputs(e, map[string]string{"MODULE_ADVERTISE_HOST": "sms.example.org"})
	if err != nil || got["SMS_PUBLIC_PORT"] != "9901" || got["MODULE_ADVERTISE_HOST"] != "sms.example.org" {
		t.Fatalf("%v %v", got, err)
	}
	for name, tc := range map[string]struct {
		in  map[string]string
		key string
	}{
		"missing":       {map[string]string{}, "MODULE_ADVERTISE_HOST"},
		"extra":         {map[string]string{"MODULE_ADVERTISE_HOST": "a.b", "EVIL": "1"}, "EVIL"},
		"pattern":       {map[string]string{"MODULE_ADVERTISE_HOST": "A_B"}, "MODULE_ADVERTISE_HOST"},
		"newline":       {map[string]string{"MODULE_ADVERTISE_HOST": "a.b", "FREE_TEXT": "a\nGATEWAY_ISSUER=x"}, "FREE_TEXT"},
		"dollar":        {map[string]string{"MODULE_ADVERTISE_HOST": "a.b", "FREE_TEXT": "${TRUST_DOMAIN}"}, "FREE_TEXT"},
		"quote":         {map[string]string{"MODULE_ADVERTISE_HOST": "a.b", "FREE_TEXT": `a"b`}, "FREE_TEXT"},
		"backtick":      {map[string]string{"MODULE_ADVERTISE_HOST": "a.b", "FREE_TEXT": "`id`"}, "FREE_TEXT"},
		"backslash":     {map[string]string{"MODULE_ADVERTISE_HOST": "a.b", "FREE_TEXT": `a\b`}, "FREE_TEXT"},
		"reserved name": {map[string]string{"MODULE_ADVERTISE_HOST": "a.b", "GATEWAY_ISSUER": "https://evil"}, "GATEWAY_ISSUER"},
		"too long":      {map[string]string{"MODULE_ADVERTISE_HOST": "a.b", "FREE_TEXT": strings.Repeat("a", 1025)}, "FREE_TEXT"},
	} {
		_, err := CheckInputs(e, tc.in)
		var ie *InputError
		if !errors.As(err, &ie) || ie.Key != tc.key {
			t.Errorf("%s: %v (want input %s)", name, err, tc.key)
		}
	}
}

func unzip(t *testing.T, b []byte) map[string]*zip.File {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*zip.File{}
	for _, f := range r.File {
		out[f.Name] = f
	}
	return out
}

func read(t *testing.T, f *zip.File) string {
	t.Helper()
	if f == nil {
		t.Fatal("missing file")
	}
	rc, _ := f.Open()
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return string(b)
}

func TestRenderJoin(t *testing.T) {
	e, bundle := joinEntry(t, map[string]string{
		"config.yaml": "trust_domain: ${TRUST_DOMAIN}\nissuer: ${GATEWAY_ISSUER}\ndsn: postgres://app:${GEN_PASSWORD_2}@db/x\nkey: ${GEN_KEY_1}\nhost: ${MODULE_ADVERTISE_HOST}\n",
		"policy.yaml": "from: spiffe://${TRUST_DOMAIN}/svc/gateway\n",
	}, "sms-gw-db")
	inputs, _ := CheckInputs(e, map[string]string{"MODULE_ADVERTISE_HOST": "sms.example.org"})
	ca := []byte("-----BEGIN CERTIFICATE-----\nmesh\n-----END CERTIFICATE-----\n")
	out, err := RenderJoin(JoinRequest{Entry: e, Bundle: bundle, Core: core, Inputs: inputs, Token: "eyJ.join.token", MeshCA: ca, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	files := unzip(t, out)
	cfg := read(t, files["sms-gw/config.yaml"])
	if !strings.Contains(cfg, "trust_domain: infra.example.org") || !strings.Contains(cfg, "issuer: https://portal.example.org:8443") ||
		!strings.Contains(cfg, "host: sms.example.org") || strings.Contains(cfg, "${") {
		t.Fatalf("config not rendered:\n%s", cfg)
	}
	if read(t, files["sms-gw/policy.yaml"]) != "from: spiffe://infra.example.org/svc/gateway\n" {
		t.Fatal("policy not rendered")
	}
	// Non-template files are copied verbatim (compose keeps $$ and ${...} for docker compose).
	if c := read(t, files["sms-gw/compose.yaml"]); !strings.Contains(c, "$$@") || !strings.Contains(c, "${MODULE_IMAGE}") {
		t.Fatalf("compose altered:\n%s", c)
	}
	env := read(t, files["sms-gw/.env"])
	for k, v := range core {
		if !strings.Contains(env, k+`="`+v+`"`) {
			t.Fatalf(".env lacks %s:\n%s", k, env)
		}
	}
	for _, want := range []string{`MODULE_VERSION="4.3.0"`, `MODULE_IMAGE="ghcr.io/go-tangra/go-tangra-sms-gw"`, `SMS_PUBLIC_PORT="9901"`, `MODULE="sms-gw"`} {
		if !strings.Contains(env, want) {
			t.Fatalf(".env lacks %s", want)
		}
	}
	pw := regexp.MustCompile(`GEN_PASSWORD_(\d)="([0-9a-f]+)"`).FindAllStringSubmatch(env, -1)
	seen := map[string]bool{}
	for _, m := range pw {
		if len(m[2]) != 48 || seen[m[2]] {
			t.Fatalf("password %s weak or repeated", m[1])
		}
		seen[m[2]] = true
	}
	if len(pw) != 4 || !strings.Contains(cfg, "app:"+pw[1][2]+"@") {
		t.Fatalf("passwords %d; config uses GEN_PASSWORD_2", len(pw))
	}
	key := regexp.MustCompile(`GEN_KEY_1="([^"]+)"`).FindStringSubmatch(env)
	if raw, err := base64.StdEncoding.DecodeString(key[1]); err != nil || len(raw) != 32 {
		t.Fatalf("GEN_KEY_1 not 32 bytes base64: %v", err)
	}
	if read(t, files["sms-gw/private/enrollment.token"]) != "eyJ.join.token" || read(t, files["sms-gw/private/mesh-ca.pem"]) != string(ca) {
		t.Fatal("token or mesh CA missing")
	}
	// Local TLS: the server certificate verifies for its host against the bundle CA.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(read(t, files["sms-gw/private/tls/ca.pem"]))) {
		t.Fatal("ca.pem unreadable")
	}
	blk, _ := pem.Decode([]byte(read(t, files["sms-gw/private/tls/sms-gw-db.crt"])))
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "sms-gw-db"}); err != nil {
		t.Fatalf("server certificate does not verify: %v", err)
	}
	if !strings.Contains(read(t, files["sms-gw/private/tls/sms-gw-db.key"]), "PRIVATE KEY") {
		t.Fatal("server key missing")
	}
	if m := files["sms-gw/.env"].Mode().Perm(); m != 0o600 {
		t.Fatalf(".env mode %o", m)
	}
	if m := files["sms-gw/"].Mode().Perm(); m != 0o700 {
		t.Fatalf("bundle dir mode %o", m)
	}
	// Two renders never share secrets.
	again, _ := RenderJoin(JoinRequest{Entry: e, Bundle: bundle, Core: core, Inputs: inputs, Token: "eyJ.join.token", MeshCA: ca, Now: time.Now()})
	if read(t, unzip(t, again)["sms-gw/.env"]) == env {
		t.Fatal("two bundles share generated secrets")
	}
}

func TestRenderJoinRefusals(t *testing.T) {
	e, bundle := joinEntry(t, map[string]string{"config.yaml": "x: ${NOT_PROVIDED}\n"})
	inputs, _ := CheckInputs(e, map[string]string{"MODULE_ADVERTISE_HOST": "sms.example.org"})
	_, err := RenderJoin(JoinRequest{Entry: e, Bundle: bundle, Core: core, Inputs: inputs, Token: "tok", MeshCA: []byte("ca"), Now: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "NOT_PROVIDED") || strings.Contains(err.Error(), "tok") {
		t.Fatalf("unresolved placeholder: %v", err)
	}
	good, gb := joinEntry(t, map[string]string{"config.yaml": "x: ${TRUST_DOMAIN}\n"})
	if _, err := RenderJoin(JoinRequest{Entry: good, Bundle: append(gb, 0), Core: core, Inputs: inputs, Token: "tok", MeshCA: []byte("ca"), Now: time.Now()}); err == nil {
		t.Fatal("bundle not matching the entry rendered")
	}
	missingCore := map[string]string{}
	for k, v := range core {
		missingCore[k] = v
	}
	delete(missingCore, "GATEWAY_ISSUER")
	if _, err := RenderJoin(JoinRequest{Entry: good, Bundle: gb, Core: missingCore, Inputs: inputs, Token: "tok", MeshCA: []byte("ca"), Now: time.Now()}); err == nil {
		t.Fatal("rendered without a core value")
	}
	if _, err := RenderJoin(JoinRequest{Entry: good, Bundle: gb, Core: core, Inputs: inputs, Token: "", MeshCA: []byte("ca"), Now: time.Now()}); err == nil {
		t.Fatal("rendered without a token")
	}
}

func TestTokenJTI(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	tok := enc(`{"alg":"EdDSA"}`) + "." + enc(`{"jti":"0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55","exp":1}`) + ".sig"
	if j, err := TokenJTI(tok); err != nil || j != "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55" {
		t.Fatalf("%q %v", j, err)
	}
	for _, bad := range []string{"", "a.b", enc("{}") + "." + enc(`{"jti":"x"}`) + ".s", "a." + hex.EncodeToString([]byte("x")) + ".c"} {
		if _, err := TokenJTI(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

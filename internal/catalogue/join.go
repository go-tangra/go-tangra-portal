package catalogue

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"

	fwcat "github.com/go-tangra/go-tangra/v4/catalogue"
)

// CoreKeys are the core values every join bundle receives from the gateway.
var CoreKeys = []string{"TRUST_DOMAIN", "GATEWAY_ISSUER", "LCM_ENROLL_URL", "AUTH_GRPC", "GATEWAY_GRPC", "LCM_GRPC", "MESH_TENANT_ID"}

const (
	genPasswords   = 4
	genKeys        = 2
	maxInputLength = 1024
)

// ErrRender: a join bundle could not be made (the detail names a placeholder
// or file, never a secret).
var ErrRender = errors.New("catalogue: join bundle not rendered")

// InputError names the host input that was refused.
type InputError struct{ Key, Msg string }

func (e *InputError) Error() string { return e.Key + ": " + e.Msg }

// CheckInputs validates the operator's host inputs against the entry: every
// declared input present (or defaulted) and matching its pattern, nothing
// undeclared, and no character that could break out of .env or YAML.
func CheckInputs(e fwcat.Entry, in map[string]string) (map[string]string, error) {
	declared := map[string]fwcat.HostInput{}
	for _, h := range e.HostInputs {
		declared[h.Key] = h
	}
	for k := range in {
		if _, ok := declared[k]; !ok {
			return nil, &InputError{k, "not an input of this module"}
		}
	}
	out := map[string]string{}
	for _, h := range e.HostInputs {
		v, ok := in[h.Key]
		if !ok || v == "" {
			v = h.Default
		}
		switch {
		case v == "":
			return nil, &InputError{h.Key, "required"}
		case len(v) > maxInputLength:
			return nil, &InputError{h.Key, "too long"}
		case strings.ContainsAny(v, "\n\r\"'`$\\\x00"):
			return nil, &InputError{h.Key, "contains a character that is not allowed"}
		}
		re, err := regexp.Compile(h.Pattern)
		if err != nil || !re.MatchString(v) {
			return nil, &InputError{h.Key, "does not match " + h.Pattern}
		}
		out[h.Key] = v
	}
	return out, nil
}

// JoinRequest is everything a join bundle is rendered from.
type JoinRequest struct {
	Entry  fwcat.Entry
	Bundle []byte            // the verified bundle.zip the entry pins
	Core   map[string]string // CoreKeys from the gateway's configuration
	Inputs map[string]string // CheckInputs result
	Token  string            // single-use enrolment token
	MeshCA []byte            // PEM
	Now    time.Time
	Rand   io.Reader // default crypto/rand
}

var placeholderRE = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)\}`)

// RenderJoin makes the join bundle zip: the entry's bundle under <module>/,
// templates rendered, .env with every value, private/ with the token, the
// mesh CA and the bundle's own TLS material. Nothing is kept.
func RenderJoin(r JoinRequest) ([]byte, error) {
	if r.Token == "" || len(r.MeshCA) == 0 {
		return nil, fmt.Errorf("%w: token and mesh CA required", ErrRender)
	}
	if err := r.Entry.CheckBundle(r.Bundle); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRender, err)
	}
	files, err := fwcat.ReadBundle(r.Bundle)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRender, err)
	}
	rnd := r.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	values := map[string]string{"MODULE": r.Entry.Module, "MODULE_VERSION": r.Entry.Version, "MODULE_IMAGE": r.Entry.Image}
	for _, k := range CoreKeys {
		v := r.Core[k]
		if v == "" {
			return nil, fmt.Errorf("%w: core value %s not configured", ErrRender, k)
		}
		values[k] = v
	}
	for k, v := range r.Inputs {
		if fwcat.Reserved(k) {
			return nil, fmt.Errorf("%w: input %s is reserved", ErrRender, k)
		}
		values[k] = v
	}
	for i := 1; i <= genPasswords; i++ {
		b := make([]byte, 24)
		if _, err := io.ReadFull(rnd, b); err != nil {
			return nil, fmt.Errorf("%w: randomness", ErrRender)
		}
		values[fmt.Sprintf("GEN_PASSWORD_%d", i)] = hex.EncodeToString(b)
	}
	for i := 1; i <= genKeys; i++ {
		b := make([]byte, 32)
		if _, err := io.ReadFull(rnd, b); err != nil {
			return nil, fmt.Errorf("%w: randomness", ErrRender)
		}
		values[fmt.Sprintf("GEN_KEY_%d", i)] = base64.StdEncoding.EncodeToString(b)
	}
	templates := map[string]bool{}
	for _, t := range r.Entry.Bundle.Templates {
		templates[t] = true
	}
	root := r.Entry.Module + "/"
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	add := func(name string, mode fs.FileMode, data []byte) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: r.Now}
		h.SetMode(fs.FileMode(mode))
		w, err := z.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	dir := func(name string) error {
		h := &zip.FileHeader{Name: name, Modified: r.Now}
		h.SetMode(fs.ModeDir | 0o700)
		_, err := z.CreateHeader(h)
		return err
	}
	for _, d := range []string{root, root + "private/"} {
		if err := dir(d); err != nil {
			return nil, err
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		data := files[n]
		if templates[n] {
			var missing []string
			data = placeholderRE.ReplaceAllFunc(data, func(m []byte) []byte {
				k := string(placeholderRE.FindSubmatch(m)[1])
				v, ok := values[k]
				if !ok {
					missing = append(missing, k)
				}
				return []byte(v)
			})
			if len(missing) > 0 {
				return nil, fmt.Errorf("%w: %s uses unknown placeholders %s", ErrRender, n, strings.Join(uniq(missing), ", "))
			}
		}
		if err := add(root+n, 0o644, data); err != nil {
			return nil, err
		}
	}
	if err := add(root+".env", 0o600, envFile(values)); err != nil {
		return nil, err
	}
	if err := add(root+"private/enrollment.token", 0o644, []byte(r.Token)); err != nil {
		return nil, err
	}
	if err := add(root+"private/mesh-ca.pem", 0o644, r.MeshCA); err != nil {
		return nil, err
	}
	if len(r.Entry.Bundle.TLSHosts) > 0 {
		tlsFiles, err := localTLS(rnd, r.Now, r.Entry.Module, r.Entry.Bundle.TLSHosts)
		if err != nil {
			return nil, fmt.Errorf("%w: local TLS: %v", ErrRender, err)
		}
		if err := dir(root + "private/tls/"); err != nil {
			return nil, err
		}
		tnames := make([]string, 0, len(tlsFiles))
		for n := range tlsFiles {
			tnames = append(tnames, n)
		}
		sort.Strings(tnames)
		for _, n := range tnames {
			mode := fs.FileMode(0o644)
			if strings.HasSuffix(n, ".key") {
				mode = 0o600 // the database container copies it as root (see the module's compose)
			}
			if err := add(root+"private/tls/"+n, mode, tlsFiles[n]); err != nil {
				return nil, err
			}
		}
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// envFile writes every value quoted (CheckInputs keeps quotes, $ and
// newlines out of operator values; generated and core values have none).
func envFile(values map[string]string) []byte {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Written by the gateway's add-module wizard. Keep this file on this host only.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=\"%s\"\n", k, values[k])
	}
	return []byte(b.String())
}

// localTLS issues a CA and one server certificate per host for the bundle's
// own services (e.g. its database), ECDSA P-256.
func localTLS(rnd io.Reader, now time.Time, module string, hosts []string) (map[string][]byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rnd)
	if err != nil {
		return nil, err
	}
	serial := func() (*big.Int, error) { return rand.Int(rnd, new(big.Int).Lsh(big.NewInt(1), 120)) }
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	caTpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: module + " join bundle local CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rnd, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	out := map[string][]byte{"ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	for _, h := range hosts {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rnd)
		if err != nil {
			return nil, err
		}
		sn, err := serial()
		if err != nil {
			return nil, err
		}
		tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: h}, DNSNames: []string{h},
			NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rnd, tpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
		kb, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		out[h+".crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		out[h+".key"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
	}
	return out, nil
}

// TokenJTI reads the jti of an enrolment token the gateway just minted (its
// payload only: the token came from auth over the mesh and is not trusted
// for anything else here).
func TokenJTI(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("catalogue: not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("catalogue: token payload not base64url")
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || !uuidRE.MatchString(claims.JTI) {
		return "", errors.New("catalogue: token has no jti")
	}
	return claims.JTI, nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func uniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

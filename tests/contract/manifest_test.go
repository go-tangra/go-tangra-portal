package contract

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/go-tangra/go-tangra-portal/sdk/v4/api/schema"
	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
)

const specSchema = "../../specs/003-application-gateway/contracts/manifest.schema.json"

func TestManifestSchemaSelfValidatesAndMatchesContract(t *testing.T) {
	c := jsonschema.NewCompiler()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema.Manifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("manifest.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Compile("manifest.schema.json"); err != nil {
		t.Fatalf("embedded schema does not compile: %v", err)
	}
	if spec, err := os.ReadFile(specSchema); err == nil && !bytes.Equal(bytes.TrimSpace(spec), bytes.TrimSpace(schema.Manifest)) {
		t.Fatal("api/schema/manifest.schema.json drifted from the specification contract")
	}
	raw, err := os.ReadFile("../../internal/manifest/testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Parse(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Parse([]byte(`{"module":"x"}`)); !errors.Is(err, manifest.ErrInvalid) {
		t.Fatal("incomplete manifest accepted")
	}
}

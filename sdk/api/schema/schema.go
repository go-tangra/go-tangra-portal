// Package schema embeds the manifest JSON Schema every registration is validated against.
package schema

import _ "embed"

// Manifest is contracts/manifest.schema.json.
//
//go:embed manifest.schema.json
var Manifest []byte

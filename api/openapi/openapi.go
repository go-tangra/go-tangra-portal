// Package openapi embeds the gateway's shell/operations API contract.
package openapi

import _ "embed"

// Gateway is the OpenAPI 3.1 document for /gateway/v1 and /m/{module}.
//
//go:embed gateway.yaml
var Gateway []byte

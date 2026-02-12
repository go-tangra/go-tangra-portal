package service

import (
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"

	authenticationV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/authentication/service/v1"
)

// parseRegistrationResponse converts the proto WebAuthnAssertion (used for registration confirmation)
// into a go-webauthn CredentialCreationResponse by reconstructing the standard WebAuthn JSON structure
// and parsing it through the library's parser.
func parseRegistrationResponse(assertion *authenticationV1.WebAuthnAssertion) (*protocol.ParsedCredentialCreationData, error) {
	if assertion == nil {
		return nil, fmt.Errorf("webauthn assertion is nil")
	}

	// Reconstruct the standard CredentialCreationResponse JSON that go-webauthn expects.
	// The proto fields are base64url-encoded strings matching the WebAuthn spec.
	ccr := map[string]interface{}{
		"id":    assertion.GetId(),
		"rawId": assertion.GetId(),
		"type":  "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    assertion.GetClientDataJson(),
			"attestationObject": assertion.GetAuthenticatorData(), // registration uses attestationObject
		},
	}

	data, err := json.Marshal(ccr)
	if err != nil {
		return nil, fmt.Errorf("marshal registration response: %w", err)
	}

	return protocol.ParseCredentialCreationResponseBytes(data)
}

// parseLoginResponse converts the proto WebAuthnAssertion (used for login verification)
// into a go-webauthn CredentialAssertionResponse.
func parseLoginResponse(assertion *authenticationV1.WebAuthnAssertion) (*protocol.ParsedCredentialAssertionData, error) {
	if assertion == nil {
		return nil, fmt.Errorf("webauthn assertion is nil")
	}

	car := map[string]interface{}{
		"id":    assertion.GetId(),
		"rawId": assertion.GetId(),
		"type":  "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    assertion.GetClientDataJson(),
			"authenticatorData": assertion.GetAuthenticatorData(),
			"signature":         assertion.GetSignature(),
		},
	}

	if assertion.UserHandle != nil {
		car["response"].(map[string]interface{})["userHandle"] = *assertion.UserHandle
	}

	data, err := json.Marshal(car)
	if err != nil {
		return nil, fmt.Errorf("marshal login response: %w", err)
	}

	return protocol.ParseCredentialRequestResponseBytes(data)
}

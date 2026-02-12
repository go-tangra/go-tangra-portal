package data

import (
	"encoding/binary"

	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnUser implements the webauthn.User interface required by go-webauthn.
type WebAuthnUser struct {
	ID          uint32
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

var _ webauthn.User = (*WebAuthnUser)(nil)

// WebAuthnID returns a 4-byte big-endian encoding of the user ID.
func (u *WebAuthnUser) WebAuthnID() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, u.ID)
	return b
}

// WebAuthnName returns the username.
func (u *WebAuthnUser) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the display name.
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Name
}

// WebAuthnCredentials returns the stored credentials for this user.
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

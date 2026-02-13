package data

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/tx7do/go-utils/password"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/usercredential"

	authenticationV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/authentication/service/v1"
)

// MFARepo handles MFA credential operations (TOTP, backup codes) in sys_user_credentials.
type MFARepo struct {
	entClient      *entCrud.EntClient[*ent.Client]
	passwordCrypto password.Crypto
	log            *log.Helper
}

func NewMFARepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client], passwordCrypto password.Crypto) *MFARepo {
	return &MFARepo{
		entClient:      entClient,
		passwordCrypto: passwordCrypto,
		log:            ctx.NewLoggerHelper("mfa/repo/admin-service"),
	}
}

// ListEnabledMFACredentials returns all active MFA credentials (TOTP and HARDWARE_TOKEN) for a user.
func (r *MFARepo) ListEnabledMFACredentials(ctx context.Context, userID uint32) ([]*ent.UserCredential, error) {
	return r.entClient.Client().UserCredential.Query().
		Where(
			usercredential.UserIDEQ(userID),
			usercredential.StatusEQ(usercredential.StatusEnabled),
			usercredential.CredentialTypeIn(
				usercredential.CredentialTypeTOTP,
				usercredential.CredentialTypeHardwareToken,
			),
		).
		All(ctx)
}

// HasEnabledMFA checks if user has any enabled MFA credential.
func (r *MFARepo) HasEnabledMFA(ctx context.Context, userID uint32) (bool, error) {
	return r.entClient.Client().UserCredential.Query().
		Where(
			usercredential.UserIDEQ(userID),
			usercredential.StatusEQ(usercredential.StatusEnabled),
			usercredential.CredentialTypeIn(
				usercredential.CredentialTypeTOTP,
				usercredential.CredentialTypeHardwareToken,
			),
		).
		Exist(ctx)
}

// GetTOTPCredential returns the TOTP credential for a user (encrypted secret in Credential field).
func (r *MFARepo) GetTOTPCredential(ctx context.Context, userID uint32) (*ent.UserCredential, error) {
	return r.entClient.Client().UserCredential.Query().
		Where(
			usercredential.UserIDEQ(userID),
			usercredential.CredentialTypeEQ(usercredential.CredentialTypeTOTP),
			usercredential.StatusEQ(usercredential.StatusEnabled),
		).
		Only(ctx)
}

// CreateTOTPCredential stores a new TOTP credential.
// The secret should be stored as plaintext base32 (or AES-encrypted depending on policy).
func (r *MFARepo) CreateTOTPCredential(ctx context.Context, userID, tenantID uint32, secret string) (uint32, error) {
	identifier := fmt.Sprintf("mfa:totp:%d", userID)

	// Check if already enrolled
	exists, err := r.entClient.Client().UserCredential.Query().
		Where(
			usercredential.UserIDEQ(userID),
			usercredential.CredentialTypeEQ(usercredential.CredentialTypeTOTP),
			usercredential.StatusEQ(usercredential.StatusEnabled),
		).
		Exist(ctx)
	if err != nil {
		return 0, fmt.Errorf("check existing TOTP: %w", err)
	}
	if exists {
		return 0, authenticationV1.ErrorMfaAlreadyEnrolled("TOTP already enrolled")
	}

	cred, err := r.entClient.Client().UserCredential.Create().
		SetUserID(userID).
		SetTenantID(tenantID).
		SetIdentityType(usercredential.IdentityTypeUsername).
		SetIdentifier(identifier).
		SetCredentialType(usercredential.CredentialTypeTOTP).
		SetCredential(secret).
		SetIsPrimary(false).
		SetStatus(usercredential.StatusEnabled).
		SetCreatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return 0, fmt.Errorf("create TOTP credential: %w", err)
	}

	return cred.ID, nil
}

// CreateBackupCodes generates backup codes, stores bcrypt hashes, and returns plaintext codes.
func (r *MFARepo) CreateBackupCodes(ctx context.Context, userID, tenantID uint32, count int) ([]string, error) {
	if count <= 0 {
		count = 10
	}

	// Delete existing backup codes first
	if _, err := r.entClient.Client().UserCredential.Delete().
		Where(
			usercredential.UserIDEQ(userID),
			usercredential.CredentialTypeEQ(usercredential.CredentialTypeOTP),
			usercredential.IdentifierHasPrefix(fmt.Sprintf("mfa:backup:%d:", userID)),
		).
		Exec(ctx); err != nil {
		r.log.Warnf("failed to delete existing backup codes for user %d: %v", userID, err)
	}

	codes := make([]string, count)
	builders := make([]*ent.UserCredentialCreate, count)

	for i := 0; i < count; i++ {
		code := generateBackupCode()
		codes[i] = code

		hash, err := r.passwordCrypto.Encrypt(code)
		if err != nil {
			return nil, fmt.Errorf("hash backup code: %w", err)
		}

		identifier := fmt.Sprintf("mfa:backup:%d:%d", userID, i)
		builders[i] = r.entClient.Client().UserCredential.Create().
			SetUserID(userID).
			SetTenantID(tenantID).
			SetIdentityType(usercredential.IdentityTypeUsername).
			SetIdentifier(identifier).
			SetCredentialType(usercredential.CredentialTypeOTP).
			SetCredential(hash).
			SetIsPrimary(false).
			SetStatus(usercredential.StatusEnabled).
			SetCreatedAt(time.Now())
	}

	if err := r.entClient.Client().UserCredential.CreateBulk(builders...).Exec(ctx); err != nil {
		return nil, fmt.Errorf("bulk create backup codes: %w", err)
	}

	return codes, nil
}

// VerifyAndConsumeBackupCode checks a backup code against all remaining codes for the user.
// On match, disables that code and returns true.
func (r *MFARepo) VerifyAndConsumeBackupCode(ctx context.Context, userID uint32, plainCode string) (bool, error) {
	creds, err := r.entClient.Client().UserCredential.Query().
		Where(
			usercredential.UserIDEQ(userID),
			usercredential.CredentialTypeEQ(usercredential.CredentialTypeOTP),
			usercredential.IdentifierHasPrefix(fmt.Sprintf("mfa:backup:%d:", userID)),
			usercredential.StatusEQ(usercredential.StatusEnabled),
		).
		All(ctx)
	if err != nil {
		return false, fmt.Errorf("query backup codes: %w", err)
	}

	for _, cred := range creds {
		if cred.Credential == nil {
			continue
		}
		ok, _ := r.passwordCrypto.Verify(plainCode, *cred.Credential)
		if ok {
			// Mark as consumed
			if err = r.entClient.Client().UserCredential.UpdateOneID(cred.ID).
				SetStatus(usercredential.StatusDisabled).
				SetUpdatedAt(time.Now()).
				Exec(ctx); err != nil {
				r.log.Errorf("disable consumed backup code %d: %v", cred.ID, err)
			}
			return true, nil
		}
	}

	return false, nil
}

// CountRemainingBackupCodes returns the count of unused backup codes.
func (r *MFARepo) CountRemainingBackupCodes(ctx context.Context, userID uint32) (int, error) {
	return r.entClient.Client().UserCredential.Query().
		Where(
			usercredential.UserIDEQ(userID),
			usercredential.CredentialTypeEQ(usercredential.CredentialTypeOTP),
			usercredential.IdentifierHasPrefix(fmt.Sprintf("mfa:backup:%d:", userID)),
			usercredential.StatusEQ(usercredential.StatusEnabled),
		).
		Count(ctx)
}

// DisableMFACredentials disables all MFA credentials of the given type for a user.
func (r *MFARepo) DisableMFACredentials(ctx context.Context, userID uint32, credType usercredential.CredentialType) (int, error) {
	return r.entClient.Client().UserCredential.Update().
		Where(
			usercredential.UserIDEQ(userID),
			usercredential.CredentialTypeEQ(credType),
			usercredential.StatusEQ(usercredential.StatusEnabled),
		).
		SetStatus(usercredential.StatusDisabled).
		SetUpdatedAt(time.Now()).
		Save(ctx)
}

// DisableAllMFA disables all MFA credentials (TOTP + backup codes) for a user.
func (r *MFARepo) DisableAllMFA(ctx context.Context, userID uint32) error {
	_, err := r.entClient.Client().UserCredential.Update().
		Where(
			usercredential.UserIDEQ(userID),
			usercredential.StatusEQ(usercredential.StatusEnabled),
			usercredential.CredentialTypeIn(
				usercredential.CredentialTypeTOTP,
				usercredential.CredentialTypeOTP,
				usercredential.CredentialTypeHardwareToken,
			),
		).
		SetStatus(usercredential.StatusDisabled).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	return err
}

// DisableCredentialByID disables a specific credential by its ID.
func (r *MFARepo) DisableCredentialByID(ctx context.Context, credentialID uint32) error {
	return r.entClient.Client().UserCredential.UpdateOneID(credentialID).
		SetStatus(usercredential.StatusDisabled).
		SetUpdatedAt(time.Now()).
		Exec(ctx)
}

// GetCredentialByID returns a credential by its ID.
func (r *MFARepo) GetCredentialByID(ctx context.Context, credentialID uint32) (*ent.UserCredential, error) {
	return r.entClient.Client().UserCredential.Get(ctx, credentialID)
}

// generateBackupCode creates a random 8-character hex string.
func generateBackupCode() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand.Read failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// CredentialIDFromString parses a credential_id string to uint32.
func CredentialIDFromString(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid credential_id: %w", err)
	}
	return uint32(v), nil
}

// WebAuthnCredentialData is serialized as JSON in the credential column for HARDWARE_TOKEN credentials.
type WebAuthnCredentialData struct {
	ID              []byte                            `json:"id"`
	PublicKey       []byte                            `json:"public_key"`
	AttestationType string                            `json:"attestation_type"`
	Transport       []string                          `json:"transport,omitempty"`
	SignCount       uint32                            `json:"sign_count"`
	AAGUID          []byte                            `json:"aaguid,omitempty"`
	CloneWarning    bool                              `json:"clone_warning,omitempty"`
}

// ListWebAuthnCredentials returns all enabled HARDWARE_TOKEN credentials for a user.
func (r *MFARepo) ListWebAuthnCredentials(ctx context.Context, userID uint32) ([]*ent.UserCredential, error) {
	return r.entClient.Client().UserCredential.Query().
		Where(
			usercredential.UserIDEQ(userID),
			usercredential.CredentialTypeEQ(usercredential.CredentialTypeHardwareToken),
			usercredential.StatusEQ(usercredential.StatusEnabled),
		).
		All(ctx)
}

// CreateWebAuthnCredential stores a new WebAuthn credential.
func (r *MFARepo) CreateWebAuthnCredential(ctx context.Context, userID, tenantID uint32, credData *WebAuthnCredentialData, displayName string) (uint32, error) {
	credJSON, err := json.Marshal(credData)
	if err != nil {
		return 0, fmt.Errorf("marshal webauthn credential: %w", err)
	}

	identifier := fmt.Sprintf("mfa:webauthn:%d:%s", userID, hex.EncodeToString(credData.ID))
	credStr := string(credJSON)

	extraJSON, _ := json.Marshal(map[string]string{"display_name": displayName})

	cred, err := r.entClient.Client().UserCredential.Create().
		SetUserID(userID).
		SetTenantID(tenantID).
		SetIdentityType(usercredential.IdentityTypeUsername).
		SetIdentifier(identifier).
		SetCredentialType(usercredential.CredentialTypeHardwareToken).
		SetCredential(credStr).
		SetIsPrimary(false).
		SetStatus(usercredential.StatusEnabled).
		SetExtraInfo(string(extraJSON)).
		SetCreatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return 0, fmt.Errorf("create webauthn credential: %w", err)
	}

	return cred.ID, nil
}

// UpdateWebAuthnSignCount updates the sign count in the credential JSON after successful login.
func (r *MFARepo) UpdateWebAuthnSignCount(ctx context.Context, credentialID uint32, newCount uint32) error {
	cred, err := r.entClient.Client().UserCredential.Get(ctx, credentialID)
	if err != nil {
		return fmt.Errorf("get credential %d: %w", credentialID, err)
	}

	if cred.Credential == nil {
		return fmt.Errorf("credential %d has no data", credentialID)
	}

	var data WebAuthnCredentialData
	if err = json.Unmarshal([]byte(*cred.Credential), &data); err != nil {
		return fmt.Errorf("unmarshal credential %d: %w", credentialID, err)
	}

	data.SignCount = newCount
	updated, err := json.Marshal(&data)
	if err != nil {
		return fmt.Errorf("marshal updated credential: %w", err)
	}

	updatedStr := string(updated)
	return r.entClient.Client().UserCredential.UpdateOneID(credentialID).
		SetCredential(updatedStr).
		SetUpdatedAt(time.Now()).
		Exec(ctx)
}

// ParseWebAuthnCredentials converts ent credentials to go-webauthn Credential slice,
// returning both the credentials and a map from credential ID (hex) to ent ID for sign count updates.
func (r *MFARepo) ParseWebAuthnCredentials(creds []*ent.UserCredential) ([]webauthn.Credential, map[string]uint32) {
	result := make([]webauthn.Credential, 0, len(creds))
	idMap := make(map[string]uint32, len(creds))

	for _, c := range creds {
		if c.Credential == nil {
			continue
		}

		var data WebAuthnCredentialData
		if err := json.Unmarshal([]byte(*c.Credential), &data); err != nil {
			r.log.Errorf("parse webauthn credential %d: %v", c.ID, err)
			continue
		}

		wc := webauthn.Credential{
			ID:              data.ID,
			PublicKey:       data.PublicKey,
			AttestationType: data.AttestationType,
			Authenticator: webauthn.Authenticator{
				SignCount:    data.SignCount,
				CloneWarning: data.CloneWarning,
			},
		}
		if len(data.AAGUID) > 0 {
			copy(wc.Authenticator.AAGUID[:], data.AAGUID)
		}

		result = append(result, wc)
		idMap[hex.EncodeToString(data.ID)] = c.ID
	}

	return result, idMap
}

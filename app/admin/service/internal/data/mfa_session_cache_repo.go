package data

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	authenticationV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/authentication/service/v1"
)

const (
	mfaLoginSessionPrefix     = "mfa:login:"
	mfaEnrollmentPrefix       = "mfa:enroll:"
	mfaWebAuthnChallengePrefix = "mfa:webauthn:"
	mfaLoginSessionTTL        = 5 * time.Minute
	mfaEnrollmentTTL          = 10 * time.Minute
	mfaWebAuthnChallengeTTL   = 5 * time.Minute
)

// MFALoginSession stores user context during the MFA verification step of login.
type MFALoginSession struct {
	UserID   uint32   `json:"user_id"`
	TenantID uint32   `json:"tenant_id"`
	Username string   `json:"username"`
	ClientID string   `json:"client_id"`
	DeviceID string   `json:"device_id"`
	Roles    []string `json:"roles"`
	Methods  []string `json:"methods"`
}

// MFAEnrollmentSession stores temp secret during enrollment confirmation.
type MFAEnrollmentSession struct {
	UserID              uint32 `json:"user_id"`
	Method              string `json:"method"`
	Secret              string `json:"secret"`               // plaintext TOTP secret (base32)
	WebAuthnSessionJSON string `json:"webauthn_session_json"` // serialized webauthn.SessionData for registration
}

// WebAuthnChallengeSession stores webauthn login challenge state.
type WebAuthnChallengeSession struct {
	UserID      uint32 `json:"user_id"`
	MFAToken    string `json:"mfa_token"`    // reference back to MFA login session
	SessionJSON string `json:"session_json"` // serialized webauthn.SessionData for login
}

type MFASessionCacheRepo struct {
	rdb *redis.Client
	log *log.Helper
}

func NewMFASessionCacheRepo(ctx *bootstrap.Context, rdb *redis.Client) *MFASessionCacheRepo {
	return &MFASessionCacheRepo{
		rdb: rdb,
		log: ctx.NewLoggerHelper("mfa-session/cache/admin-service"),
	}
}

// CreateLoginSession stores an MFA login session and returns its token (UUID).
func (r *MFASessionCacheRepo) CreateLoginSession(ctx context.Context, session *MFALoginSession) (string, error) {
	token := uuid.New().String()
	key := mfaLoginSessionPrefix + token

	data, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("marshal mfa session: %w", err)
	}

	if err = r.rdb.Set(ctx, key, data, mfaLoginSessionTTL).Err(); err != nil {
		return "", fmt.Errorf("set mfa session: %w", err)
	}

	return token, nil
}

// ConsumeLoginSession retrieves and deletes an MFA login session (single-use).
func (r *MFASessionCacheRepo) ConsumeLoginSession(ctx context.Context, token string) (*MFALoginSession, error) {
	key := mfaLoginSessionPrefix + token

	data, err := r.rdb.GetDel(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, authenticationV1.ErrorMfaTokenExpired("mfa session expired or not found")
		}
		return nil, fmt.Errorf("getdel mfa session: %w", err)
	}

	var session MFALoginSession
	if err = json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("unmarshal mfa session: %w", err)
	}

	return &session, nil
}

// CreateEnrollmentSession stores a temporary enrollment session and returns its operation_id.
func (r *MFASessionCacheRepo) CreateEnrollmentSession(ctx context.Context, session *MFAEnrollmentSession) (string, error) {
	operationID := uuid.New().String()
	key := mfaEnrollmentPrefix + operationID

	data, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("marshal enrollment session: %w", err)
	}

	if err = r.rdb.Set(ctx, key, data, mfaEnrollmentTTL).Err(); err != nil {
		return "", fmt.Errorf("set enrollment session: %w", err)
	}

	return operationID, nil
}

// ConsumeEnrollmentSession retrieves and deletes an enrollment session (single-use).
func (r *MFASessionCacheRepo) ConsumeEnrollmentSession(ctx context.Context, operationID string) (*MFAEnrollmentSession, error) {
	key := mfaEnrollmentPrefix + operationID

	data, err := r.rdb.GetDel(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, authenticationV1.ErrorMfaTokenExpired("enrollment session expired or not found")
		}
		return nil, fmt.Errorf("getdel enrollment session: %w", err)
	}

	var session MFAEnrollmentSession
	if err = json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("unmarshal enrollment session: %w", err)
	}

	return &session, nil
}

// GetEnrollmentSession retrieves an enrollment session without consuming it.
func (r *MFASessionCacheRepo) GetEnrollmentSession(ctx context.Context, operationID string) (*MFAEnrollmentSession, error) {
	key := mfaEnrollmentPrefix + operationID

	data, err := r.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, authenticationV1.ErrorMfaTokenExpired("enrollment session expired or not found")
		}
		return nil, fmt.Errorf("get enrollment session: %w", err)
	}

	var session MFAEnrollmentSession
	if err = json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("unmarshal enrollment session: %w", err)
	}

	return &session, nil
}

// GetLoginSession retrieves a login session without consuming it (non-destructive read).
func (r *MFASessionCacheRepo) GetLoginSession(ctx context.Context, token string) (*MFALoginSession, error) {
	key := mfaLoginSessionPrefix + token

	data, err := r.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, authenticationV1.ErrorMfaTokenExpired("mfa session expired or not found")
		}
		return nil, fmt.Errorf("get mfa session: %w", err)
	}

	var session MFALoginSession
	if err = json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("unmarshal mfa session: %w", err)
	}

	return &session, nil
}

// CreateWebAuthnChallengeSession stores a WebAuthn login challenge session and returns its ID.
func (r *MFASessionCacheRepo) CreateWebAuthnChallengeSession(ctx context.Context, session *WebAuthnChallengeSession) (string, error) {
	challengeID := uuid.New().String()
	key := mfaWebAuthnChallengePrefix + challengeID

	data, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("marshal webauthn challenge session: %w", err)
	}

	if err = r.rdb.Set(ctx, key, data, mfaWebAuthnChallengeTTL).Err(); err != nil {
		return "", fmt.Errorf("set webauthn challenge session: %w", err)
	}

	return challengeID, nil
}

// ConsumeWebAuthnChallengeSession retrieves and deletes a WebAuthn challenge session.
func (r *MFASessionCacheRepo) ConsumeWebAuthnChallengeSession(ctx context.Context, challengeID string) (*WebAuthnChallengeSession, error) {
	key := mfaWebAuthnChallengePrefix + challengeID

	data, err := r.rdb.GetDel(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, authenticationV1.ErrorMfaTokenExpired("webauthn challenge expired or not found")
		}
		return nil, fmt.Errorf("getdel webauthn challenge session: %w", err)
	}

	var session WebAuthnChallengeSession
	if err = json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("unmarshal webauthn challenge session: %w", err)
	}

	return &session, nil
}

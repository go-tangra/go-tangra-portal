package service

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/tx7do/go-utils/trans"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
	authenticationV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/authentication/service/v1"

	"github.com/go-tangra/go-tangra-portal/pkg/middleware/auth"
)

const (
	totpIssuer       = "GoTangra"
	backupCodeCount  = 10
)

type MFAService struct {
	adminV1.MFAServiceHTTPServer

	mfaRepo         *data.MFARepo
	mfaSessionCache *data.MFASessionCacheRepo
	userToken       *data.UserTokenCacheRepo
	webAuthn        *webauthn.WebAuthn

	log *log.Helper
}

func NewMFAService(
	ctx *bootstrap.Context,
	mfaRepo *data.MFARepo,
	mfaSessionCache *data.MFASessionCacheRepo,
	userToken *data.UserTokenCacheRepo,
	webAuthn *webauthn.WebAuthn,
) *MFAService {
	return &MFAService{
		log:             ctx.NewLoggerHelper("mfa/service/admin-service"),
		mfaRepo:         mfaRepo,
		mfaSessionCache: mfaSessionCache,
		userToken:       userToken,
		webAuthn:        webAuthn,
	}
}

// GetMFAStatus returns MFA overview for the current user.
func (s *MFAService) GetMFAStatus(ctx context.Context, _ *authenticationV1.GetMFAStatusRequest) (*authenticationV1.GetMFAStatusResponse, error) {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	creds, err := s.mfaRepo.ListEnabledMFACredentials(ctx, operator.UserId)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("query mfa status failed")
	}

	enrolled := credentialsToEnrolledMethods(creds)

	return &authenticationV1.GetMFAStatusResponse{
		Enabled:     len(enrolled) > 0,
		Enrolled:    enrolled,
		Enforcement: authenticationV1.MFAEnforcement_MFA_OPTIONAL,
	}, nil
}

// ListEnrolledMethods returns enrolled MFA credentials.
func (s *MFAService) ListEnrolledMethods(ctx context.Context, _ *authenticationV1.ListEnrolledMethodsRequest) (*authenticationV1.ListEnrolledMethodsResponse, error) {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	creds, err := s.mfaRepo.ListEnabledMFACredentials(ctx, operator.UserId)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("query enrolled methods failed")
	}

	return &authenticationV1.ListEnrolledMethodsResponse{
		Items: credentialsToEnrolledMethods(creds),
	}, nil
}

// StartEnrollMethod begins MFA enrollment for TOTP or WebAuthn.
func (s *MFAService) StartEnrollMethod(ctx context.Context, req *authenticationV1.StartEnrollMethodRequest) (*authenticationV1.StartEnrollMethodResponse, error) {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	switch req.GetMethod() {
	case authenticationV1.MFAMethod_TOTP:
		return s.startEnrollTOTP(ctx, operator)
	case authenticationV1.MFAMethod_WEBAUTHN:
		return s.startEnrollWebAuthn(ctx, operator)
	default:
		return nil, authenticationV1.ErrorBadRequest("unsupported enrollment method")
	}
}

func (s *MFAService) startEnrollTOTP(ctx context.Context, operator *authenticationV1.UserTokenPayload) (*authenticationV1.StartEnrollMethodResponse, error) {
	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: operator.GetUsername(),
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		s.log.Errorf("generate totp key: %v", err)
		return nil, authenticationV1.ErrorInternalServerError("generate totp key failed")
	}

	// Generate QR code as data URI
	qrPNG, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		s.log.Errorf("generate qr code: %v", err)
		return nil, authenticationV1.ErrorInternalServerError("generate qr code failed")
	}
	qrDataURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrPNG)

	// Store temp enrollment session in Redis
	operationID, err := s.mfaSessionCache.CreateEnrollmentSession(ctx, &data.MFAEnrollmentSession{
		UserID: operator.UserId,
		Method: "TOTP",
		Secret: key.Secret(),
	})
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("store enrollment session failed")
	}

	return &authenticationV1.StartEnrollMethodResponse{
		Result: &authenticationV1.StartEnrollMethodResponse_Totp{
			Totp: &authenticationV1.TOTPResult{
				Secret:        key.Secret(),
				OtpAuthUrl:    key.URL(),
				QrCodeDataUri: qrDataURI,
			},
		},
		OperationId: operationID,
		ExpiresAt:   timestamppb.New(time.Now().Add(10 * time.Minute)),
	}, nil
}

func (s *MFAService) startEnrollWebAuthn(ctx context.Context, operator *authenticationV1.UserTokenPayload) (*authenticationV1.StartEnrollMethodResponse, error) {
	if s.webAuthn == nil {
		return nil, authenticationV1.ErrorBadRequest("WebAuthn is not configured")
	}

	// Load existing WebAuthn credentials to exclude them during registration
	existingCreds, err := s.mfaRepo.ListWebAuthnCredentials(ctx, operator.UserId)
	if err != nil {
		s.log.Errorf("list webauthn credentials: %v", err)
		return nil, authenticationV1.ErrorInternalServerError("list credentials failed")
	}
	waCredentials, _ := s.mfaRepo.ParseWebAuthnCredentials(existingCreds)

	user := &data.WebAuthnUser{
		ID:          operator.UserId,
		Name:        operator.GetUsername(),
		DisplayName: operator.GetUsername(),
		Credentials: waCredentials,
	}

	creation, sessionData, err := s.webAuthn.BeginRegistration(user)
	if err != nil {
		s.log.Errorf("begin webauthn registration: %v", err)
		return nil, authenticationV1.ErrorInternalServerError("begin webauthn registration failed")
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("marshal session data failed")
	}

	optionsJSON, err := json.Marshal(creation)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("marshal options failed")
	}

	operationID, err := s.mfaSessionCache.CreateEnrollmentSession(ctx, &data.MFAEnrollmentSession{
		UserID:              operator.UserId,
		Method:              "WEBAUTHN",
		WebAuthnSessionJSON: string(sessionJSON),
	})
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("store enrollment session failed")
	}

	return &authenticationV1.StartEnrollMethodResponse{
		Result: &authenticationV1.StartEnrollMethodResponse_Webauthn{
			Webauthn: &authenticationV1.WebAuthnResult{
				Challenge:   sessionData.Challenge,
				OptionsJson: string(optionsJSON),
				RpId:        s.webAuthn.Config.RPID,
			},
		},
		OperationId: operationID,
		ExpiresAt:   timestamppb.New(time.Now().Add(10 * time.Minute)),
	}, nil
}

// ConfirmEnrollMethod validates TOTP code or WebAuthn attestation, persists credential, generates backup codes.
func (s *MFAService) ConfirmEnrollMethod(ctx context.Context, req *authenticationV1.ConfirmEnrollMethodRequest) (*authenticationV1.ConfirmEnrollMethodResponse, error) {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	switch req.GetMethod() {
	case authenticationV1.MFAMethod_TOTP:
		return s.confirmEnrollTOTP(ctx, operator, req)
	case authenticationV1.MFAMethod_WEBAUTHN:
		return s.confirmEnrollWebAuthn(ctx, operator, req)
	default:
		return nil, authenticationV1.ErrorBadRequest("unsupported confirmation method")
	}
}

func (s *MFAService) confirmEnrollTOTP(ctx context.Context, operator *authenticationV1.UserTokenPayload, req *authenticationV1.ConfirmEnrollMethodRequest) (*authenticationV1.ConfirmEnrollMethodResponse, error) {
	totpCode := req.GetTotpCode()
	if totpCode == "" {
		return nil, authenticationV1.ErrorBadRequest("totp_code is required")
	}

	session, err := s.mfaSessionCache.ConsumeEnrollmentSession(ctx, req.GetOperationId())
	if err != nil {
		return nil, err
	}

	if session.UserID != operator.UserId {
		return nil, authenticationV1.ErrorMfaTokenInvalid("session user mismatch")
	}

	valid := totp.Validate(totpCode, session.Secret)
	if !valid {
		return nil, authenticationV1.ErrorMfaVerificationFailed("invalid TOTP code")
	}

	credID, err := s.mfaRepo.CreateTOTPCredential(ctx, operator.UserId, operator.GetTenantId(), session.Secret)
	if err != nil {
		return nil, err
	}

	// Auto-generate backup codes
	_, err = s.mfaRepo.CreateBackupCodes(ctx, operator.UserId, operator.GetTenantId(), backupCodeCount)
	if err != nil {
		s.log.Errorf("auto-generate backup codes failed: %v", err)
	}

	return &authenticationV1.ConfirmEnrollMethodResponse{
		Success:      true,
		CredentialId: strconv.FormatUint(uint64(credID), 10),
	}, nil
}

func (s *MFAService) confirmEnrollWebAuthn(ctx context.Context, operator *authenticationV1.UserTokenPayload, req *authenticationV1.ConfirmEnrollMethodRequest) (*authenticationV1.ConfirmEnrollMethodResponse, error) {
	if s.webAuthn == nil {
		return nil, authenticationV1.ErrorBadRequest("WebAuthn is not configured")
	}

	assertion := req.GetWebauthn()
	if assertion == nil {
		return nil, authenticationV1.ErrorBadRequest("webauthn assertion is required")
	}

	session, err := s.mfaSessionCache.ConsumeEnrollmentSession(ctx, req.GetOperationId())
	if err != nil {
		return nil, err
	}

	if session.UserID != operator.UserId {
		return nil, authenticationV1.ErrorMfaTokenInvalid("session user mismatch")
	}

	// Restore webauthn session data
	var sessionData webauthn.SessionData
	if err = json.Unmarshal([]byte(session.WebAuthnSessionJSON), &sessionData); err != nil {
		s.log.Errorf("unmarshal webauthn session: %v", err)
		return nil, authenticationV1.ErrorInternalServerError("invalid enrollment session")
	}

	// Parse the registration response from the client
	parsedResponse, err := parseRegistrationResponse(assertion)
	if err != nil {
		s.log.Errorf("parse registration response: %v", err)
		return nil, authenticationV1.ErrorMfaVerificationFailed("invalid webauthn registration response")
	}

	// Load existing credentials for the user
	existingCreds, err := s.mfaRepo.ListWebAuthnCredentials(ctx, operator.UserId)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("list credentials failed")
	}
	waCredentials, _ := s.mfaRepo.ParseWebAuthnCredentials(existingCreds)

	user := &data.WebAuthnUser{
		ID:          operator.UserId,
		Name:        operator.GetUsername(),
		DisplayName: operator.GetUsername(),
		Credentials: waCredentials,
	}

	credential, err := s.webAuthn.CreateCredential(user, sessionData, parsedResponse)
	if err != nil {
		s.log.Errorf("create webauthn credential: %v", err)
		return nil, authenticationV1.ErrorMfaVerificationFailed("webauthn registration verification failed")
	}

	// Persist the credential
	displayName := req.GetDisplay()
	if displayName == "" {
		displayName = "Security Key"
	}

	credData := &data.WebAuthnCredentialData{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		SignCount:       credential.Authenticator.SignCount,
		CloneWarning:    credential.Authenticator.CloneWarning,
		AAGUID:          credential.Authenticator.AAGUID[:],
	}

	credID, err := s.mfaRepo.CreateWebAuthnCredential(ctx, operator.UserId, operator.GetTenantId(), credData, displayName)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("store webauthn credential failed")
	}

	// Auto-generate backup codes if this is the first MFA credential
	hasMFA, _ := s.mfaRepo.HasEnabledMFA(ctx, operator.UserId)
	if !hasMFA {
		_, err = s.mfaRepo.CreateBackupCodes(ctx, operator.UserId, operator.GetTenantId(), backupCodeCount)
		if err != nil {
			s.log.Errorf("auto-generate backup codes failed: %v", err)
		}
	}

	return &authenticationV1.ConfirmEnrollMethodResponse{
		Success:      true,
		CredentialId: strconv.FormatUint(uint64(credID), 10),
	}, nil
}

// DisableMFA disables MFA for the current user.
func (s *MFAService) DisableMFA(ctx context.Context, _ *authenticationV1.DisableMFARequest) (*emptypb.Empty, error) {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	if err = s.mfaRepo.DisableAllMFA(ctx, operator.UserId); err != nil {
		s.log.Errorf("disable mfa: %v", err)
		return nil, authenticationV1.ErrorInternalServerError("disable mfa failed")
	}

	return &emptypb.Empty{}, nil
}

// StartMFAChallenge initiates MFA verification during login.
func (s *MFAService) StartMFAChallenge(ctx context.Context, req *authenticationV1.StartMFAChallengeRequest) (*authenticationV1.StartMFAChallengeResponse, error) {
	switch req.GetMethod() {
	case authenticationV1.MFAMethod_TOTP, authenticationV1.MFAMethod_BACKUP_CODE:
		// For TOTP/backup, no server-side challenge needed; frontend prompts for code directly.
		return &authenticationV1.StartMFAChallengeResponse{
			OperationId: req.GetUserId(), // mfa_token passed as user_id field
			ExpiresAt:   timestamppb.New(time.Now().Add(5 * time.Minute)),
		}, nil
	case authenticationV1.MFAMethod_WEBAUTHN:
		return s.startMFAChallengeWebAuthn(ctx, req)
	default:
		return nil, authenticationV1.ErrorBadRequest("unsupported MFA method")
	}
}

func (s *MFAService) startMFAChallengeWebAuthn(ctx context.Context, req *authenticationV1.StartMFAChallengeRequest) (*authenticationV1.StartMFAChallengeResponse, error) {
	if s.webAuthn == nil {
		return nil, authenticationV1.ErrorBadRequest("WebAuthn is not configured")
	}

	mfaToken := req.GetUserId()
	if mfaToken == "" {
		return nil, authenticationV1.ErrorBadRequest("user_id (mfa_token) is required")
	}

	// Peek at login session (non-consuming) to get user ID
	loginSession, err := s.mfaSessionCache.GetLoginSession(ctx, mfaToken)
	if err != nil {
		return nil, err
	}

	// Load user's WebAuthn credentials
	creds, err := s.mfaRepo.ListWebAuthnCredentials(ctx, loginSession.UserID)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("list credentials failed")
	}
	if len(creds) == 0 {
		return nil, authenticationV1.ErrorMfaNotEnrolled("no WebAuthn credentials enrolled")
	}
	waCredentials, _ := s.mfaRepo.ParseWebAuthnCredentials(creds)

	user := &data.WebAuthnUser{
		ID:          loginSession.UserID,
		Name:        loginSession.Username,
		DisplayName: loginSession.Username,
		Credentials: waCredentials,
	}

	assertion, sessionData, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		s.log.Errorf("begin webauthn login: %v", err)
		return nil, authenticationV1.ErrorInternalServerError("begin webauthn login failed")
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("marshal session data failed")
	}

	optionsJSON, err := json.Marshal(assertion)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("marshal options failed")
	}

	challengeID, err := s.mfaSessionCache.CreateWebAuthnChallengeSession(ctx, &data.WebAuthnChallengeSession{
		UserID:      loginSession.UserID,
		MFAToken:    mfaToken,
		SessionJSON: string(sessionJSON),
	})
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("store challenge session failed")
	}

	return &authenticationV1.StartMFAChallengeResponse{
		Challenge: &authenticationV1.StartMFAChallengeResponse_Webauthn{
			Webauthn: &authenticationV1.WebAuthnResult{
				Challenge:   sessionData.Challenge,
				OptionsJson: string(optionsJSON),
				RpId:        s.webAuthn.Config.RPID,
			},
		},
		OperationId: challengeID,
		ExpiresAt:   timestamppb.New(time.Now().Add(5 * time.Minute)),
	}, nil
}

// VerifyMFAChallenge verifies MFA code or WebAuthn assertion, consumes Redis session, returns JWT tokens.
func (s *MFAService) VerifyMFAChallenge(ctx context.Context, req *authenticationV1.VerifyMFAChallengeRequest) (*authenticationV1.VerifyMFAChallengeResponse, error) {
	// Check for WebAuthn assertion first
	if wa := req.GetWebauthn(); wa != nil {
		return s.verifyWebAuthnChallenge(ctx, req.GetOperationId(), wa)
	}

	// TOTP / backup code path: operation_id is the mfa_token (login session token)
	// Peek first (non-destructive) so the user can retry on wrong code.
	session, err := s.mfaSessionCache.GetLoginSession(ctx, req.GetOperationId())
	if err != nil {
		return nil, err
	}

	var verified bool

	// Try TOTP code
	if code := req.GetTotpCode(); code != "" {
		verified, err = s.verifyTOTPCode(ctx, session.UserID, code)
		if err != nil {
			s.log.Errorf("verify totp: %v", err)
			return nil, authenticationV1.ErrorMfaVerificationFailed("TOTP verification failed")
		}
	}

	// Try backup code
	if !verified {
		if code := req.GetBackupCode(); code != "" {
			verified, err = s.mfaRepo.VerifyAndConsumeBackupCode(ctx, session.UserID, code)
			if err != nil {
				s.log.Errorf("verify backup code: %v", err)
				return nil, authenticationV1.ErrorMfaVerificationFailed("backup code verification failed")
			}
		}
	}

	if !verified {
		return nil, authenticationV1.ErrorMfaVerificationFailed("invalid MFA code")
	}

	// Consume the session only after successful verification
	_, err = s.mfaSessionCache.ConsumeLoginSession(ctx, req.GetOperationId())
	if err != nil {
		s.log.Errorf("consume login session after verify: %v", err)
		// Session might have been consumed by a concurrent request — still proceed
	}

	return s.generateMFALoginResponse(ctx, session)
}

func (s *MFAService) verifyWebAuthnChallenge(ctx context.Context, operationID string, assertion *authenticationV1.WebAuthnAssertion) (*authenticationV1.VerifyMFAChallengeResponse, error) {
	if s.webAuthn == nil {
		return nil, authenticationV1.ErrorBadRequest("WebAuthn is not configured")
	}

	// Consume the WebAuthn challenge session
	challengeSession, err := s.mfaSessionCache.ConsumeWebAuthnChallengeSession(ctx, operationID)
	if err != nil {
		return nil, err
	}

	// Restore webauthn session data
	var sessionData webauthn.SessionData
	if err = json.Unmarshal([]byte(challengeSession.SessionJSON), &sessionData); err != nil {
		s.log.Errorf("unmarshal webauthn session: %v", err)
		return nil, authenticationV1.ErrorInternalServerError("invalid challenge session")
	}

	// Load user's WebAuthn credentials
	creds, err := s.mfaRepo.ListWebAuthnCredentials(ctx, challengeSession.UserID)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("list credentials failed")
	}
	waCredentials, idMap := s.mfaRepo.ParseWebAuthnCredentials(creds)

	user := &data.WebAuthnUser{
		ID:          challengeSession.UserID,
		Name:        "",
		Credentials: waCredentials,
	}

	// Parse the login response from the client
	parsedResponse, err := parseLoginResponse(assertion)
	if err != nil {
		s.log.Errorf("parse login response: %v", err)
		return nil, authenticationV1.ErrorMfaVerificationFailed("invalid webauthn assertion")
	}

	credential, err := s.webAuthn.ValidateLogin(user, sessionData, parsedResponse)
	if err != nil {
		s.log.Errorf("validate webauthn login: %v", err)
		return nil, authenticationV1.ErrorMfaVerificationFailed("webauthn verification failed")
	}

	// Update sign count for clone detection
	credHex := hex.EncodeToString(credential.ID)
	if entID, ok := idMap[credHex]; ok {
		if err = s.mfaRepo.UpdateWebAuthnSignCount(ctx, entID, credential.Authenticator.SignCount); err != nil {
			s.log.Errorf("update sign count for cred %s: %v", credHex, err)
		}
	}

	// Consume the MFA login session using the stored mfa_token
	loginSession, err := s.mfaSessionCache.ConsumeLoginSession(ctx, challengeSession.MFAToken)
	if err != nil {
		return nil, err
	}

	return s.generateMFALoginResponse(ctx, loginSession)
}

// generateMFALoginResponse creates JWT tokens and returns the MFA verify response.
func (s *MFAService) generateMFALoginResponse(ctx context.Context, session *data.MFALoginSession) (*authenticationV1.VerifyMFAChallengeResponse, error) {
	tokenPayload := &authenticationV1.UserTokenPayload{
		UserId:   session.UserID,
		TenantId: trans.Ptr(session.TenantID),
		Username: trans.Ptr(session.Username),
		ClientId: &session.ClientID,
		DeviceId: &session.DeviceID,
		Roles:    session.Roles,
	}

	accessToken, refreshToken, err := s.userToken.GenerateToken(ctx, tokenPayload)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("generate token failed")
	}

	loginResp := &authenticationV1.LoginResponse{
		TokenType:        authenticationV1.TokenType_bearer,
		AccessToken:      accessToken,
		RefreshToken:     trans.Ptr(refreshToken),
		ExpiresIn:        int64(s.userToken.GetAccessTokenExpires().Seconds()),
		RefreshExpiresIn: trans.Ptr(int64(s.userToken.GetRefreshTokenExpires().Seconds())),
	}

	return &authenticationV1.VerifyMFAChallengeResponse{
		Success:       true,
		LoginResponse: loginResp,
	}, nil
}

// GenerateBackupCodes generates fresh backup codes for the current user.
func (s *MFAService) GenerateBackupCodes(ctx context.Context, req *authenticationV1.GenerateBackupCodesRequest) (*authenticationV1.GenerateBackupCodesResponse, error) {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	count := int(req.GetCount())
	if count <= 0 {
		count = backupCodeCount
	}

	codes, err := s.mfaRepo.CreateBackupCodes(ctx, operator.UserId, operator.GetTenantId(), count)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("generate backup codes failed")
	}

	return &authenticationV1.GenerateBackupCodesResponse{
		Codes:       codes,
		GeneratedAt: timestamppb.Now(),
	}, nil
}

// ListBackupCodes returns the remaining count of unused backup codes.
func (s *MFAService) ListBackupCodes(ctx context.Context, _ *authenticationV1.ListBackupCodesRequest) (*authenticationV1.ListBackupCodesResponse, error) {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	remaining, err := s.mfaRepo.CountRemainingBackupCodes(ctx, operator.UserId)
	if err != nil {
		return nil, authenticationV1.ErrorInternalServerError("count backup codes failed")
	}

	return &authenticationV1.ListBackupCodesResponse{
		Remaining: int32(remaining),
	}, nil
}

// RevokeMFADevice disables a specific MFA credential by ID.
func (s *MFAService) RevokeMFADevice(ctx context.Context, req *authenticationV1.RevokeMFADeviceRequest) (*emptypb.Empty, error) {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	credID, err := data.CredentialIDFromString(req.GetCredentialId())
	if err != nil {
		return nil, authenticationV1.ErrorBadRequest("invalid credential_id")
	}

	// Verify the credential belongs to this user
	cred, err := s.mfaRepo.GetCredentialByID(ctx, credID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, authenticationV1.ErrorNotFound("credential not found")
		}
		return nil, authenticationV1.ErrorInternalServerError("query credential failed")
	}

	if cred.UserID == nil || *cred.UserID != operator.UserId {
		return nil, authenticationV1.ErrorForbidden("credential does not belong to current user")
	}

	if err = s.mfaRepo.DisableCredentialByID(ctx, credID); err != nil {
		return nil, authenticationV1.ErrorInternalServerError("revoke credential failed")
	}

	return &emptypb.Empty{}, nil
}

// verifyTOTPCode validates a TOTP code against the stored secret for a user.
func (s *MFAService) verifyTOTPCode(ctx context.Context, userID uint32, code string) (bool, error) {
	cred, err := s.mfaRepo.GetTOTPCredential(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			s.log.Errorf("verifyTOTPCode: no TOTP credential found for user %d", userID)
			return false, fmt.Errorf("no TOTP credential found")
		}
		s.log.Errorf("verifyTOTPCode: query error for user %d: %v", userID, err)
		return false, err
	}

	if cred.Credential == nil {
		s.log.Errorf("verifyTOTPCode: credential field is nil for user %d (cred ID=%d)", userID, cred.ID)
		return false, fmt.Errorf("TOTP credential has no secret")
	}

	secret := *cred.Credential
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:     2,
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		s.log.Errorf("verifyTOTPCode: ValidateCustom error for user %d: %v", userID, err)
		return false, err
	}
	if !valid {
		s.log.Warnf("verifyTOTPCode: code rejected for user %d (credID=%d, secretLen=%d, time=%s)", userID, cred.ID, len(secret), time.Now().UTC().Format(time.RFC3339))
	}

	return valid, nil
}

// credentialsToEnrolledMethods converts ent credentials to proto EnrolledMethod list.
func credentialsToEnrolledMethods(creds []*ent.UserCredential) []*authenticationV1.EnrolledMethod {
	methods := make([]*authenticationV1.EnrolledMethod, 0, len(creds))
	for _, c := range creds {
		method := authenticationV1.MFAMethod_MFA_METHOD_UNSPECIFIED
		display := ""
		if c.CredentialType != nil {
			switch *c.CredentialType {
			case "TOTP":
				method = authenticationV1.MFAMethod_TOTP
				display = "Authenticator App"
			case "HARDWARE_TOKEN":
				method = authenticationV1.MFAMethod_WEBAUTHN
				display = "Security Key"
			}
		}

		em := &authenticationV1.EnrolledMethod{
			Id:      strconv.FormatUint(uint64(c.ID), 10),
			Method:  method,
			Display: display,
			Enabled: c.Status != nil && *c.Status == "ENABLED",
		}
		if c.CreatedAt != nil && !c.CreatedAt.IsZero() {
			em.CreatedAt = timestamppb.New(*c.CreatedAt)
		}
		methods = append(methods, em)
	}
	return methods
}

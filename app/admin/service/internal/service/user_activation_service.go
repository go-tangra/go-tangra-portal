package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/pkg/validators"
)

// UserActivationService implements the public "set password from activation
// email" endpoint. Unauthenticated: the activation token is the capability.
type UserActivationService struct {
	adminV1.UserActivationServiceHTTPServer
	adminV1.UnimplementedUserActivationServiceServer

	log                *log.Helper
	userCredentialRepo *data.UserCredentialRepo
}

// NewUserActivationService wires the service dependencies.
func NewUserActivationService(
	ctx *bootstrap.Context,
	userCredentialRepo *data.UserCredentialRepo,
) *UserActivationService {
	return &UserActivationService{
		log:                ctx.NewLoggerHelper("user-activation/service/admin-service"),
		userCredentialRepo: userCredentialRepo,
	}
}

// ActivateUser consumes a one-time activation token and sets the new password.
func (s *UserActivationService) ActivateUser(ctx context.Context, req *adminV1.ActivateUserRequest) (*adminV1.ActivateUserResponse, error) {
	if req == nil || req.GetToken() == "" || req.GetNewPassword() == "" {
		return nil, adminV1.ErrorBadRequest("token and new_password are required")
	}

	if err := validators.ValidateStrongPassword(req.GetNewPassword()); err != nil {
		// Surface the specific policy failure so the UI can tell the user
		// which rule was violated without leaking anything sensitive.
		return nil, adminV1.ErrorBadRequest("%s", err.Error())
	}

	if _, err := s.userCredentialRepo.ConsumeActivationToken(ctx, req.GetToken(), req.GetNewPassword()); err != nil {
		return nil, err
	}

	return &adminV1.ActivateUserResponse{}, nil
}

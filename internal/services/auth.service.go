package services

import (
	"context"
	"user_service/dto/request"
)

type IAuth interface {
	SendOtp(ctx context.Context, req request.SendOtpReq) (int, error)
	VerifyOtp(ctx context.Context, req request.VerifyOtpReq) (int, error)
	CompleteRegistration(ctx context.Context, req request.CompleteRegistrationReq) (int, error)
	Login()
	ForgotPassword()
	UpdatePassword()
}
